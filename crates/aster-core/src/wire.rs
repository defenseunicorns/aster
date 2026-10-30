//! Deterministic wire vocabulary for inventory reconciliation.
//!
//! This module defines a small RFC 8949 deterministic-CBOR profile atop
//! `minicbor`'s generic byte mechanics instead of exposing a Rust serialization
//! format. The profile remains language neutral and protocol-owned:
//! * unsigned-integer map keys only;
//! * definite lengths only;
//! * shortest-form integers and lengths;
//! * strictly increasing map keys;
//! * no tags, floats, or application-defined simple values.
//!
//! Message fields numbered 0 through 63 are critical.  A decoder rejects an
//! unknown key in that range.  Keys 64 and above are optional extensions and
//! are ignored by older decoders.  This convention is part of the protocol,
//! not an implementation detail.

use std::fmt;

use minicbor::{
    Decoder as CborDecoder, Encoder as CborEncoder,
    data::{Int as CborInt, Type as CborType},
    encode::Write as CborWrite,
};
use sha2::{Digest, Sha256};

/// Transfer identity of one stable source-sealed envelope.
///
/// This type is deliberately distinct from [`crate::model::ItemId`].  An
/// envelope is first reassembled and checked against this SHA-256 identifier;
/// only authenticated engine ingestion may then produce the semantic item ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct EnvelopeId([u8; 32]);

impl EnvelopeId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Calculates the transfer ID over exactly the stable source-sealed bytes.
    pub fn from_sealed_bytes(sealed: &[u8]) -> Self {
        Self(Sha256::digest(sealed).into())
    }
}

impl From<[u8; 32]> for EnvelopeId {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<EnvelopeId> for [u8; 32] {
    fn from(value: EnvelopeId) -> Self {
        value.into_bytes()
    }
}

/// Stable kind tag in the transfer-object namespace.
///
/// The tag occupies the first byte of every [`ObjectId`], so a source envelope
/// can never be interpreted as a Blob chunk even if an implementation routes
/// an identifier to the wrong completion handler.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ObjectKind {
    /// A stable source-sealed data or control envelope.
    SourceEnvelope = 1,
    /// A canonical encrypted Blob chunk carrier.
    BlobChunk = 2,
    /// A source-authenticated proof covering one canonical source batch.
    SourceBatchProof = 3,
    /// A source-authenticated authorization for a bridge boundary.
    BridgeAuthorization = 4,
    /// A route-bound wrapper for bridge custody metadata.
    BridgeRouteWrapper = 5,
}

impl ObjectKind {
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::SourceEnvelope),
            2 => Some(Self::BlobChunk),
            3 => Some(Self::SourceBatchProof),
            4 => Some(Self::BridgeAuthorization),
            5 => Some(Self::BridgeRouteWrapper),
            _ => None,
        }
    }

    pub(crate) const fn is_allowed_in_semantic_version(self, semantic_version: u16) -> bool {
        match self {
            Self::SourceEnvelope => semantic_version >= SEMANTIC_PROTOCOL_V1,
            Self::BlobChunk => {
                semantic_version >= SEMANTIC_PROTOCOL_V1 && semantic_version <= SEMANTIC_PROTOCOL_V8
            }
            Self::SourceBatchProof | Self::BridgeAuthorization | Self::BridgeRouteWrapper => {
                semantic_version >= SEMANTIC_PROTOCOL_V2
            }
        }
    }

    pub(crate) const fn supports_forwarding_metadata(self) -> bool {
        matches!(
            self,
            Self::SourceEnvelope | Self::SourceBatchProof | Self::BridgeRouteWrapper
        )
    }
}

pub(crate) const SEMANTIC_PROTOCOL_V1: u16 = 1;
pub(crate) const SEMANTIC_PROTOCOL_V2: u16 = 2;
pub(crate) const SEMANTIC_PROTOCOL_V3: u16 = 3;
pub(crate) const SEMANTIC_PROTOCOL_V4: u16 = 4;
pub(crate) const SEMANTIC_PROTOCOL_V5: u16 = 5;
pub(crate) const SEMANTIC_PROTOCOL_V6: u16 = 6;
pub(crate) const SEMANTIC_PROTOCOL_V7: u16 = 7;
pub(crate) const SEMANTIC_PROTOCOL_V8: u16 = 8;
pub(crate) const SEMANTIC_PROTOCOL_V9: u16 = 9;

/// Typed identity in the reconciliation and ranged-transfer namespace.
///
/// Its fixed 33-byte representation is `kind:u8 || id:32`. Keeping the kind
/// outside the digest gives parsers unambiguous dispatch while retaining the
/// complete SHA-256 envelope or chunk commitment without truncation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId {
    kind: ObjectKind,
    id: [u8; 32],
}

/// Number of radix nibbles in the complete typed transfer identifier.
pub const OBJECT_ID_NIBBLES: u8 = 66;

impl ObjectId {
    pub const WIRE_LEN: usize = 33;

    pub const fn new(kind: ObjectKind, id: [u8; 32]) -> Self {
        Self { kind, id }
    }

    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn to_wire_bytes(self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0_u8; Self::WIRE_LEN];
        bytes[0] = self.kind as u8;
        bytes[1..].copy_from_slice(&self.id);
        bytes
    }

    pub fn from_wire_bytes(bytes: [u8; Self::WIRE_LEN]) -> Option<Self> {
        let kind = ObjectKind::from_tag(bytes[0])?;
        let mut id = [0_u8; 32];
        id.copy_from_slice(&bytes[1..]);
        Some(Self { kind, id })
    }

    /// Uses the complete SHA-256 identity of the stable source envelope.
    pub const fn for_envelope(envelope_id: EnvelopeId) -> Self {
        Self::new(ObjectKind::SourceEnvelope, envelope_id.into_bytes())
    }

    /// Uses the complete domain-separated Blob carrier commitment.
    pub(crate) const fn for_blob_chunk_digest(digest: [u8; 32]) -> Self {
        Self::new(ObjectKind::BlobChunk, digest)
    }

    /// Full stable source-envelope digest, only for the matching kind.
    pub const fn envelope_id(&self) -> Option<EnvelopeId> {
        match self.kind {
            ObjectKind::SourceEnvelope => Some(EnvelopeId::from_bytes(self.id)),
            ObjectKind::BlobChunk
            | ObjectKind::SourceBatchProof
            | ObjectKind::BridgeAuthorization
            | ObjectKind::BridgeRouteWrapper => None,
        }
    }
}

/// A commitment/hash value which is not itself an envelope identity.
pub type Digest32 = [u8; 32];

/// Stable language-neutral integer assignments.
pub mod registry {
    /// The only protocol version implemented by this module.
    pub const PROTOCOL_VERSION: u64 = 1;
    /// Unknown field keys at or below this value are critical.
    pub const MAX_CRITICAL_KEY: u64 = 63;

    pub mod message {
        pub const INTEREST: u64 = 1;
        pub const SUMMARY: u64 = 2;
        pub const PROBE: u64 = 3;
        pub const NODE: u64 = 4;
        pub const OFFER: u64 = 5;
        pub const WANT: u64 = 6;
        pub const DATA: u64 = 7;
        pub const RECEIPT: u64 = 8;
    }

    pub mod common {
        pub const VERSION: u64 = 0;
        pub const KIND: u64 = 1;
        pub const EXCHANGE_ID: u64 = 2;
    }

    pub mod interest {
        pub const TOPICS: u64 = 3;
        pub const SCOPES: u64 = 4;
        pub const MIN_PRIORITY: u64 = 5;
        pub const MAX_OFFERS: u64 = 6;
    }

    pub mod summary {
        pub const ROOT_HASH: u64 = 3;
        pub const ITEM_COUNT: u64 = 4;
        pub const SNAPSHOT_ID: u64 = 5;
    }

    pub mod probe {
        pub const PREFIX: u64 = 3;
        pub const PREFIX_NIBBLES: u64 = 4;
        pub const SNAPSHOT_ID: u64 = 5;
    }

    pub mod node {
        pub const PREFIX: u64 = 3;
        pub const PREFIX_NIBBLES: u64 = 4;
        pub const HASH: u64 = 5;
        pub const ITEM_COUNT: u64 = 6;
        pub const CHILDREN: u64 = 7;
        pub const SNAPSHOT_ID: u64 = 8;

        pub const CHILD_NIBBLE: u64 = 0;
        pub const CHILD_HASH: u64 = 1;
        pub const CHILD_COUNT: u64 = 2;
    }

    pub mod offer {
        pub const OBJECT_IDS: u64 = 3;
        pub const SNAPSHOT_ID: u64 = 4;
    }

    pub mod want {
        pub const ITEMS: u64 = 3;

        pub const ITEM_ID: u64 = 0;
        pub const TOTAL_LEN: u64 = 1;
        pub const MISSING_RANGES: u64 = 2;
        pub const NEED_FORWARDING: u64 = 3;
    }

    pub mod data {
        pub const OBJECT_ID: u64 = 3;
        pub const TOTAL_LEN: u64 = 4;
        pub const OFFSET: u64 = 5;
        pub const PAYLOAD: u64 = 6;
        pub const FORWARDING: u64 = 7;
    }

    pub mod receipt {
        pub const OBJECT_ID: u64 = 3;
        pub const TOTAL_LEN: u64 = 4;
        pub const RECEIVED_RANGES: u64 = 5;
        pub const COMPLETE: u64 = 6;
    }
}

/// Resource limits applied before allocating decoder-owned collections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub max_depth: usize,
    pub max_collection_items: usize,
    pub max_byte_string: usize,
    pub max_text_string: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 1_048_576,
            max_depth: 16,
            max_collection_items: 4_096,
            max_byte_string: 1_048_576,
            max_text_string: 4_096,
        }
    }
}

/// Maximum topic selectors admitted by one INTEREST message.
pub const MAX_INTEREST_TOPICS: usize = 256;
/// Maximum scope selectors admitted by one INTEREST message.
pub const MAX_INTEREST_SCOPES: usize = 256;
/// Maximum topic/scope combinations one INTEREST may ask a peer to evaluate.
pub const MAX_INTEREST_WORK: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterestDimension {
    Topics,
    Scopes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    MessageTooLarge,
    UnexpectedEof,
    TrailingBytes,
    UnsupportedType(u8),
    IndefiniteLength,
    NonMinimalInteger,
    DepthLimit,
    CollectionLimit,
    ByteStringLimit,
    TextStringLimit,
    InvalidUtf8,
    MapKeyMustBeUnsigned,
    DuplicateMapKey(u64),
    NonCanonicalMapOrder,
    UnknownCriticalKey(u64),
    MissingField(u64),
    WrongFieldType(u64),
    UnsupportedVersion(u64),
    UnsupportedSemanticVersion(u16),
    ObjectKindRequiresSemanticV2(ObjectKind),
    UnknownMessageType(u64),
    InvalidField(&'static str),
    NonCanonicalSet(&'static str),
    InterestDimensionLimit {
        dimension: InterestDimension,
        actual: usize,
        maximum: usize,
    },
    InterestWorkLimit {
        actual: usize,
        maximum: usize,
    },
    IntegerOverflow,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WireError {}

/// Values admitted by the deterministic-CBOR subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Unsigned(u64),
    /// RFC 8949 major type 1 argument `n`, representing the integer `-1-n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(u64, Value)>),
    Bool(bool),
    Null,
}

/// Encode a subset value in RFC 8949 deterministic form.
pub fn encode_value(value: &Value, limits: Limits) -> Result<Vec<u8>, WireError> {
    let writer = BoundedWriter::new(limits.max_message_bytes);
    let mut encoder = CborEncoder::new(writer);
    encode_into(value, 0, limits, &mut encoder)?;
    Ok(encoder.into_writer().into_bytes())
}

fn encode_into(
    value: &Value,
    depth: usize,
    limits: Limits,
    encoder: &mut CborEncoder<BoundedWriter>,
) -> Result<(), WireError> {
    if depth > limits.max_depth {
        return Err(WireError::DepthLimit);
    }
    match value {
        Value::Unsigned(value) => {
            encoder
                .u64(*value)
                .map_err(|_| WireError::MessageTooLarge)?;
        }
        Value::Negative(argument) => {
            let signed = -1_i128 - i128::from(*argument);
            let value = CborInt::try_from(signed).map_err(|_| WireError::IntegerOverflow)?;
            encoder.int(value).map_err(|_| WireError::MessageTooLarge)?;
        }
        Value::Bytes(bytes) => {
            if bytes.len() > limits.max_byte_string {
                return Err(WireError::ByteStringLimit);
            }
            encoder
                .bytes(bytes)
                .map_err(|_| WireError::MessageTooLarge)?;
        }
        Value::Text(text) => {
            if text.len() > limits.max_text_string {
                return Err(WireError::TextStringLimit);
            }
            encoder.str(text).map_err(|_| WireError::MessageTooLarge)?;
        }
        Value::Array(values) => {
            if values.len() > limits.max_collection_items {
                return Err(WireError::CollectionLimit);
            }
            encoder
                .array(usize_u64(values.len())?)
                .map_err(|_| WireError::MessageTooLarge)?;
            for value in values {
                encode_into(value, depth + 1, limits, encoder)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > limits.max_collection_items {
                return Err(WireError::CollectionLimit);
            }
            let mut ordered: Vec<_> = entries.iter().collect();
            ordered.sort_by_key(|entry| entry.0);
            for pair in ordered.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(WireError::DuplicateMapKey(pair[0].0));
                }
            }
            encoder
                .map(usize_u64(ordered.len())?)
                .map_err(|_| WireError::MessageTooLarge)?;
            for entry in ordered {
                encoder
                    .u64(entry.0)
                    .map_err(|_| WireError::MessageTooLarge)?;
                encode_into(&entry.1, depth + 1, limits, encoder)?;
            }
        }
        Value::Bool(value) => {
            encoder
                .bool(*value)
                .map_err(|_| WireError::MessageTooLarge)?;
        }
        Value::Null => {
            encoder.null().map_err(|_| WireError::MessageTooLarge)?;
        }
    }
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    max_len: usize,
}

impl BoundedWriter {
    fn new(max_len: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_len,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl CborWrite for BoundedWriter {
    type Error = WireError;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(WireError::MessageTooLarge)?;
        if new_len > self.max_len {
            return Err(WireError::MessageTooLarge);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

fn usize_u64(value: usize) -> Result<u64, WireError> {
    u64::try_from(value).map_err(|_| WireError::IntegerOverflow)
}

/// Decode one complete subset value and reject trailing bytes.
pub fn decode_value(input: &[u8], limits: Limits) -> Result<Value, WireError> {
    if input.len() > limits.max_message_bytes {
        return Err(WireError::MessageTooLarge);
    }
    let mut decoder = ValueDecoder {
        decoder: CborDecoder::new(input),
        input,
        limits,
    };
    let value = decoder.value(0)?;
    if decoder.decoder.position() != input.len() {
        return Err(WireError::TrailingBytes);
    }
    // `minicbor` is the generic mechanism, while this exact acceptance rule is
    // Aster's deterministic RFC 8949 profile.  A permissive upstream parse can
    // therefore never normalize and admit a non-canonical representation.
    if encode_value(&value, limits)?.as_slice() != input {
        return Err(WireError::NonMinimalInteger);
    }
    Ok(value)
}

struct ValueDecoder<'a> {
    decoder: CborDecoder<'a>,
    input: &'a [u8],
    limits: Limits,
}

impl ValueDecoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, WireError> {
        if depth > self.limits.max_depth {
            return Err(WireError::DepthLimit);
        }
        let initial = *self
            .input
            .get(self.decoder.position())
            .ok_or(WireError::UnexpectedEof)?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if additional == 31 {
            return Err(WireError::IndefiniteLength);
        }
        if major <= 5 && (28..=30).contains(&additional) {
            return Err(WireError::UnsupportedType(additional));
        }
        let data_type = self
            .decoder
            .datatype()
            .map_err(|_| WireError::UnsupportedType(initial))?;
        match data_type {
            CborType::U8 | CborType::U16 | CborType::U32 | CborType::U64 => self
                .decoder
                .u64()
                .map(Value::Unsigned)
                .map_err(|error| decode_error(error, WireError::UnsupportedType(initial))),
            CborType::I8 | CborType::I16 | CborType::I32 | CborType::I64 | CborType::Int => {
                let value = self
                    .decoder
                    .int()
                    .map_err(|error| decode_error(error, WireError::UnsupportedType(initial)))?;
                let signed = i128::from(value);
                let argument =
                    u64::try_from(-1_i128 - signed).map_err(|_| WireError::IntegerOverflow)?;
                Ok(Value::Negative(argument))
            }
            CborType::Bytes => {
                let bytes = self
                    .decoder
                    .bytes()
                    .map_err(|error| decode_error(error, WireError::UnsupportedType(initial)))?;
                if bytes.len() > self.limits.max_byte_string {
                    return Err(WireError::ByteStringLimit);
                }
                Ok(Value::Bytes(bytes.to_vec()))
            }
            CborType::String => {
                let text = self
                    .decoder
                    .str()
                    .map_err(|error| decode_error(error, WireError::InvalidUtf8))?;
                if text.len() > self.limits.max_text_string {
                    return Err(WireError::TextStringLimit);
                }
                Ok(Value::Text(text.to_owned()))
            }
            CborType::Array => {
                let len = self
                    .decoder
                    .array()
                    .map_err(|error| decode_error(error, WireError::UnsupportedType(initial)))?
                    .ok_or(WireError::IndefiniteLength)?;
                let len = self.collection_len(len)?;
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            CborType::Map => {
                let len = self
                    .decoder
                    .map()
                    .map_err(|error| decode_error(error, WireError::UnsupportedType(initial)))?
                    .ok_or(WireError::IndefiniteLength)?;
                let len = self.collection_len(len)?;
                let mut entries = Vec::with_capacity(len);
                let mut previous = None;
                for _ in 0..len {
                    let key = match self.value(depth + 1)? {
                        Value::Unsigned(key) => key,
                        _ => return Err(WireError::MapKeyMustBeUnsigned),
                    };
                    if let Some(previous) = previous {
                        if key == previous {
                            return Err(WireError::DuplicateMapKey(key));
                        }
                        if key < previous {
                            return Err(WireError::NonCanonicalMapOrder);
                        }
                    }
                    previous = Some(key);
                    entries.push((key, self.value(depth + 1)?));
                }
                Ok(Value::Map(entries))
            }
            CborType::Bool => self
                .decoder
                .bool()
                .map(Value::Bool)
                .map_err(|_| WireError::UnsupportedType(initial)),
            CborType::Null => {
                self.decoder
                    .null()
                    .map_err(|_| WireError::UnsupportedType(initial))?;
                Ok(Value::Null)
            }
            CborType::BytesIndef
            | CborType::StringIndef
            | CborType::ArrayIndef
            | CborType::MapIndef
            | CborType::Break => Err(WireError::IndefiniteLength),
            _ => Err(WireError::UnsupportedType(initial)),
        }
    }

    fn collection_len(&self, len: u64) -> Result<usize, WireError> {
        let len = usize::try_from(len).map_err(|_| WireError::CollectionLimit)?;
        if len > self.limits.max_collection_items {
            return Err(WireError::CollectionLimit);
        }
        Ok(len)
    }
}

fn decode_error(error: minicbor::decode::Error, fallback: WireError) -> WireError {
    if error.is_end_of_input() {
        WireError::UnexpectedEof
    } else {
        fallback
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteRange {
    pub start: u64,
    /// Exclusive upper bound.
    pub end: u64,
}

impl ByteRange {
    pub fn new(start: u64, end: u64) -> Result<Self, WireError> {
        if start >= end {
            return Err(WireError::InvalidField("byte range"));
        }
        Ok(Self { start, end })
    }

    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interest {
    pub exchange_id: u64,
    /// Canonically sorted unique UTF-8 topic names.
    pub topics: Vec<String>,
    /// Canonically sorted unique UTF-8 scope names.
    pub scopes: Vec<String>,
    pub min_priority: u8,
    pub max_offers: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub exchange_id: u64,
    pub root_hash: Digest32,
    pub item_count: u64,
    pub snapshot_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Probe {
    pub exchange_id: u64,
    /// Big-endian packed nibbles.  For an odd nibble count the low nibble of
    /// the final byte is zero.
    pub prefix: Vec<u8>,
    pub prefix_nibbles: u8,
    pub snapshot_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildSummary {
    pub nibble: u8,
    pub hash: Digest32,
    pub item_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub exchange_id: u64,
    pub prefix: Vec<u8>,
    pub prefix_nibbles: u8,
    pub hash: Digest32,
    pub item_count: u64,
    /// Sorted by nibble, with empty children omitted.
    pub children: Vec<ChildSummary>,
    pub snapshot_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offer {
    pub exchange_id: u64,
    /// Sorted unique identifiers.
    pub object_ids: Vec<ObjectId>,
    pub snapshot_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WantItem {
    pub object_id: ObjectId,
    /// Unknown for a first request.  Once known it prevents cross-object
    /// range confusion after reconnecting to another peer.
    pub total_len: Option<u64>,
    /// Sorted, disjoint missing ranges.  Empty with an unknown total means
    /// "send an initial chunk and its total length".
    pub missing: Vec<ByteRange>,
    /// Requests fresh authenticated forwarding metadata from this peer.  This
    /// can be true with no missing byte ranges after a cross-peer resume.
    pub need_forwarding: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Want {
    pub exchange_id: u64,
    /// Sorted unique by object identifier.
    pub items: Vec<WantItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Data {
    pub exchange_id: u64,
    pub object_id: ObjectId,
    pub total_len: u64,
    pub offset: u64,
    pub payload: Vec<u8>,
    /// Peer-specific protected forwarding metadata.  It is not part of the
    /// stable envelope bytes or their range offsets.
    pub forwarding: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub exchange_id: u64,
    pub object_id: ObjectId,
    pub total_len: u64,
    /// Sorted, disjoint ranges durably received by the receiver.
    pub received: Vec<ByteRange>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Interest(Interest),
    Summary(Summary),
    Probe(Probe),
    Node(Node),
    Offer(Offer),
    Want(Want),
    Data(Data),
    Receipt(Receipt),
}

impl Message {
    pub fn exchange_id(&self) -> u64 {
        match self {
            Message::Interest(value) => value.exchange_id,
            Message::Summary(value) => value.exchange_id,
            Message::Probe(value) => value.exchange_id,
            Message::Node(value) => value.exchange_id,
            Message::Offer(value) => value.exchange_id,
            Message::Want(value) => value.exchange_id,
            Message::Data(value) => value.exchange_id,
            Message::Receipt(value) => value.exchange_id,
        }
    }
}

pub fn encode_message(message: &Message, limits: Limits) -> Result<Vec<u8>, WireError> {
    encode_message_for_semantic_version(message, SEMANTIC_PROTOCOL_V1, limits)
}

pub(crate) fn encode_message_for_semantic_version(
    message: &Message,
    semantic_version: u16,
    limits: Limits,
) -> Result<Vec<u8>, WireError> {
    validate_message_for_semantic_version(message, semantic_version)?;
    encode_value(&message_value(message), limits)
}

pub fn decode_message(input: &[u8], limits: Limits) -> Result<Message, WireError> {
    decode_message_for_semantic_version(input, SEMANTIC_PROTOCOL_V1, limits)
}

pub(crate) fn decode_message_for_semantic_version(
    input: &[u8],
    semantic_version: u16,
    limits: Limits,
) -> Result<Message, WireError> {
    validate_semantic_version(semantic_version)?;
    let value = decode_value(input, limits)?;
    let map = as_map(&value, u64::MAX)?;
    let version = as_unsigned(
        required(map, registry::common::VERSION)?,
        registry::common::VERSION,
    )?;
    if version != registry::PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = as_unsigned(
        required(map, registry::common::KIND)?,
        registry::common::KIND,
    )?;
    let exchange_id = as_unsigned(
        required(map, registry::common::EXCHANGE_ID)?,
        registry::common::EXCHANGE_ID,
    )?;

    let message = match kind {
        registry::message::INTEREST => {
            check_keys(map, &[0, 1, 2, 3, 4, 5, 6])?;
            Message::Interest(Interest {
                exchange_id,
                topics: text_array(
                    required(map, registry::interest::TOPICS)?,
                    registry::interest::TOPICS,
                )?,
                scopes: text_array(
                    required(map, registry::interest::SCOPES)?,
                    registry::interest::SCOPES,
                )?,
                min_priority: u8::try_from(as_unsigned(
                    required(map, registry::interest::MIN_PRIORITY)?,
                    registry::interest::MIN_PRIORITY,
                )?)
                .map_err(|_| WireError::InvalidField("minimum priority"))?,
                max_offers: u32::try_from(as_unsigned(
                    required(map, registry::interest::MAX_OFFERS)?,
                    registry::interest::MAX_OFFERS,
                )?)
                .map_err(|_| WireError::InvalidField("maximum offers"))?,
            })
        }
        registry::message::SUMMARY => {
            check_keys(map, &[0, 1, 2, 3, 4, 5])?;
            Message::Summary(Summary {
                exchange_id,
                root_hash: digest32(
                    required(map, registry::summary::ROOT_HASH)?,
                    registry::summary::ROOT_HASH,
                )?,
                item_count: as_unsigned(
                    required(map, registry::summary::ITEM_COUNT)?,
                    registry::summary::ITEM_COUNT,
                )?,
                snapshot_id: as_unsigned(
                    required(map, registry::summary::SNAPSHOT_ID)?,
                    registry::summary::SNAPSHOT_ID,
                )?,
            })
        }
        registry::message::PROBE => {
            check_keys(map, &[0, 1, 2, 3, 4, 5])?;
            Message::Probe(Probe {
                exchange_id,
                prefix: bytes(
                    required(map, registry::probe::PREFIX)?,
                    registry::probe::PREFIX,
                )?,
                prefix_nibbles: u8::try_from(as_unsigned(
                    required(map, registry::probe::PREFIX_NIBBLES)?,
                    registry::probe::PREFIX_NIBBLES,
                )?)
                .map_err(|_| WireError::InvalidField("prefix nibble count"))?,
                snapshot_id: as_unsigned(
                    required(map, registry::probe::SNAPSHOT_ID)?,
                    registry::probe::SNAPSHOT_ID,
                )?,
            })
        }
        registry::message::NODE => {
            check_keys(map, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
            let child_values = as_array(
                required(map, registry::node::CHILDREN)?,
                registry::node::CHILDREN,
            )?;
            let mut children = Vec::with_capacity(child_values.len());
            for child in child_values {
                let child_map = as_map(child, registry::node::CHILDREN)?;
                check_keys(child_map, &[0, 1, 2])?;
                children.push(ChildSummary {
                    nibble: u8::try_from(as_unsigned(
                        required(child_map, registry::node::CHILD_NIBBLE)?,
                        registry::node::CHILD_NIBBLE,
                    )?)
                    .map_err(|_| WireError::InvalidField("child nibble"))?,
                    hash: digest32(
                        required(child_map, registry::node::CHILD_HASH)?,
                        registry::node::CHILD_HASH,
                    )?,
                    item_count: as_unsigned(
                        required(child_map, registry::node::CHILD_COUNT)?,
                        registry::node::CHILD_COUNT,
                    )?,
                });
            }
            Message::Node(Node {
                exchange_id,
                prefix: bytes(
                    required(map, registry::node::PREFIX)?,
                    registry::node::PREFIX,
                )?,
                prefix_nibbles: u8::try_from(as_unsigned(
                    required(map, registry::node::PREFIX_NIBBLES)?,
                    registry::node::PREFIX_NIBBLES,
                )?)
                .map_err(|_| WireError::InvalidField("prefix nibble count"))?,
                hash: digest32(required(map, registry::node::HASH)?, registry::node::HASH)?,
                item_count: as_unsigned(
                    required(map, registry::node::ITEM_COUNT)?,
                    registry::node::ITEM_COUNT,
                )?,
                children,
                snapshot_id: as_unsigned(
                    required(map, registry::node::SNAPSHOT_ID)?,
                    registry::node::SNAPSHOT_ID,
                )?,
            })
        }
        registry::message::OFFER => {
            check_keys(map, &[0, 1, 2, 3, 4])?;
            Message::Offer(Offer {
                exchange_id,
                object_ids: id_array(
                    required(map, registry::offer::OBJECT_IDS)?,
                    registry::offer::OBJECT_IDS,
                )?,
                snapshot_id: as_unsigned(
                    required(map, registry::offer::SNAPSHOT_ID)?,
                    registry::offer::SNAPSHOT_ID,
                )?,
            })
        }
        registry::message::WANT => {
            check_keys(map, &[0, 1, 2, 3])?;
            let values = as_array(required(map, registry::want::ITEMS)?, registry::want::ITEMS)?;
            let mut items = Vec::with_capacity(values.len());
            for value in values {
                let item = as_map(value, registry::want::ITEMS)?;
                check_keys(item, &[0, 1, 2, 3])?;
                let total_value = required(item, registry::want::TOTAL_LEN)?;
                let total_len = match total_value {
                    Value::Null => None,
                    _ => Some(as_unsigned(total_value, registry::want::TOTAL_LEN)?),
                };
                items.push(WantItem {
                    object_id: object_id(
                        required(item, registry::want::ITEM_ID)?,
                        registry::want::ITEM_ID,
                    )?,
                    total_len,
                    missing: range_array(
                        required(item, registry::want::MISSING_RANGES)?,
                        registry::want::MISSING_RANGES,
                    )?,
                    need_forwarding: as_bool(
                        required(item, registry::want::NEED_FORWARDING)?,
                        registry::want::NEED_FORWARDING,
                    )?,
                });
            }
            Message::Want(Want { exchange_id, items })
        }
        registry::message::DATA => {
            check_keys(map, &[0, 1, 2, 3, 4, 5, 6, 7])?;
            Message::Data(Data {
                exchange_id,
                object_id: object_id(
                    required(map, registry::data::OBJECT_ID)?,
                    registry::data::OBJECT_ID,
                )?,
                total_len: as_unsigned(
                    required(map, registry::data::TOTAL_LEN)?,
                    registry::data::TOTAL_LEN,
                )?,
                offset: as_unsigned(
                    required(map, registry::data::OFFSET)?,
                    registry::data::OFFSET,
                )?,
                payload: bytes(
                    required(map, registry::data::PAYLOAD)?,
                    registry::data::PAYLOAD,
                )?,
                forwarding: bytes(
                    required(map, registry::data::FORWARDING)?,
                    registry::data::FORWARDING,
                )?,
            })
        }
        registry::message::RECEIPT => {
            check_keys(map, &[0, 1, 2, 3, 4, 5, 6])?;
            Message::Receipt(Receipt {
                exchange_id,
                object_id: object_id(
                    required(map, registry::receipt::OBJECT_ID)?,
                    registry::receipt::OBJECT_ID,
                )?,
                total_len: as_unsigned(
                    required(map, registry::receipt::TOTAL_LEN)?,
                    registry::receipt::TOTAL_LEN,
                )?,
                received: range_array(
                    required(map, registry::receipt::RECEIVED_RANGES)?,
                    registry::receipt::RECEIVED_RANGES,
                )?,
                complete: as_bool(
                    required(map, registry::receipt::COMPLETE)?,
                    registry::receipt::COMPLETE,
                )?,
            })
        }
        _ => return Err(WireError::UnknownMessageType(kind)),
    };
    validate_message_for_semantic_version(&message, semantic_version)?;
    Ok(message)
}

fn message_value(message: &Message) -> Value {
    let mut map = vec![
        (
            registry::common::VERSION,
            Value::Unsigned(registry::PROTOCOL_VERSION),
        ),
        (
            registry::common::KIND,
            Value::Unsigned(match message {
                Message::Interest(_) => registry::message::INTEREST,
                Message::Summary(_) => registry::message::SUMMARY,
                Message::Probe(_) => registry::message::PROBE,
                Message::Node(_) => registry::message::NODE,
                Message::Offer(_) => registry::message::OFFER,
                Message::Want(_) => registry::message::WANT,
                Message::Data(_) => registry::message::DATA,
                Message::Receipt(_) => registry::message::RECEIPT,
            }),
        ),
        (
            registry::common::EXCHANGE_ID,
            Value::Unsigned(message.exchange_id()),
        ),
    ];
    match message {
        Message::Interest(value) => {
            map.push((
                registry::interest::TOPICS,
                Value::Array(value.topics.iter().cloned().map(Value::Text).collect()),
            ));
            map.push((
                registry::interest::SCOPES,
                Value::Array(value.scopes.iter().cloned().map(Value::Text).collect()),
            ));
            map.push((
                registry::interest::MIN_PRIORITY,
                Value::Unsigned(u64::from(value.min_priority)),
            ));
            map.push((
                registry::interest::MAX_OFFERS,
                Value::Unsigned(u64::from(value.max_offers)),
            ));
        }
        Message::Summary(value) => {
            map.push((
                registry::summary::ROOT_HASH,
                Value::Bytes(value.root_hash.to_vec()),
            ));
            map.push((
                registry::summary::ITEM_COUNT,
                Value::Unsigned(value.item_count),
            ));
            map.push((
                registry::summary::SNAPSHOT_ID,
                Value::Unsigned(value.snapshot_id),
            ));
        }
        Message::Probe(value) => {
            map.push((registry::probe::PREFIX, Value::Bytes(value.prefix.clone())));
            map.push((
                registry::probe::PREFIX_NIBBLES,
                Value::Unsigned(u64::from(value.prefix_nibbles)),
            ));
            map.push((
                registry::probe::SNAPSHOT_ID,
                Value::Unsigned(value.snapshot_id),
            ));
        }
        Message::Node(value) => {
            map.push((registry::node::PREFIX, Value::Bytes(value.prefix.clone())));
            map.push((
                registry::node::PREFIX_NIBBLES,
                Value::Unsigned(u64::from(value.prefix_nibbles)),
            ));
            map.push((registry::node::HASH, Value::Bytes(value.hash.to_vec())));
            map.push((
                registry::node::ITEM_COUNT,
                Value::Unsigned(value.item_count),
            ));
            map.push((
                registry::node::CHILDREN,
                Value::Array(
                    value
                        .children
                        .iter()
                        .map(|child| {
                            Value::Map(vec![
                                (
                                    registry::node::CHILD_NIBBLE,
                                    Value::Unsigned(u64::from(child.nibble)),
                                ),
                                (
                                    registry::node::CHILD_HASH,
                                    Value::Bytes(child.hash.to_vec()),
                                ),
                                (
                                    registry::node::CHILD_COUNT,
                                    Value::Unsigned(child.item_count),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ));
            map.push((
                registry::node::SNAPSHOT_ID,
                Value::Unsigned(value.snapshot_id),
            ));
        }
        Message::Offer(value) => {
            map.push((
                registry::offer::OBJECT_IDS,
                Value::Array(
                    value
                        .object_ids
                        .iter()
                        .map(|id| Value::Bytes(id.to_wire_bytes().to_vec()))
                        .collect(),
                ),
            ));
            map.push((
                registry::offer::SNAPSHOT_ID,
                Value::Unsigned(value.snapshot_id),
            ));
        }
        Message::Want(value) => {
            map.push((
                registry::want::ITEMS,
                Value::Array(
                    value
                        .items
                        .iter()
                        .map(|item| {
                            Value::Map(vec![
                                (
                                    registry::want::ITEM_ID,
                                    Value::Bytes(item.object_id.to_wire_bytes().to_vec()),
                                ),
                                (
                                    registry::want::TOTAL_LEN,
                                    item.total_len.map(Value::Unsigned).unwrap_or(Value::Null),
                                ),
                                (registry::want::MISSING_RANGES, ranges_value(&item.missing)),
                                (
                                    registry::want::NEED_FORWARDING,
                                    Value::Bool(item.need_forwarding),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        Message::Data(value) => {
            map.push((
                registry::data::OBJECT_ID,
                Value::Bytes(value.object_id.to_wire_bytes().to_vec()),
            ));
            map.push((registry::data::TOTAL_LEN, Value::Unsigned(value.total_len)));
            map.push((registry::data::OFFSET, Value::Unsigned(value.offset)));
            map.push((registry::data::PAYLOAD, Value::Bytes(value.payload.clone())));
            map.push((
                registry::data::FORWARDING,
                Value::Bytes(value.forwarding.clone()),
            ));
        }
        Message::Receipt(value) => {
            map.push((
                registry::receipt::OBJECT_ID,
                Value::Bytes(value.object_id.to_wire_bytes().to_vec()),
            ));
            map.push((
                registry::receipt::TOTAL_LEN,
                Value::Unsigned(value.total_len),
            ));
            map.push((
                registry::receipt::RECEIVED_RANGES,
                ranges_value(&value.received),
            ));
            map.push((registry::receipt::COMPLETE, Value::Bool(value.complete)));
        }
    }
    Value::Map(map)
}

fn ranges_value(ranges: &[ByteRange]) -> Value {
    Value::Array(
        ranges
            .iter()
            .map(|range| {
                Value::Array(vec![
                    Value::Unsigned(range.start),
                    Value::Unsigned(range.end),
                ])
            })
            .collect(),
    )
}

fn validate_message(message: &Message) -> Result<(), WireError> {
    match message {
        Message::Interest(value) => {
            validate_interest_work(value.topics.len(), value.scopes.len())?;
            validate_text_set(&value.topics, "topics")?;
            validate_text_set(&value.scopes, "scopes")?;
            if value.min_priority > 3 {
                return Err(WireError::InvalidField("minimum priority"));
            }
            if value.max_offers == 0 {
                return Err(WireError::InvalidField("maximum offers"));
            }
        }
        Message::Summary(_) => {}
        Message::Probe(value) => validate_prefix(&value.prefix, value.prefix_nibbles)?,
        Message::Node(value) => {
            validate_prefix(&value.prefix, value.prefix_nibbles)?;
            if value.children.len() > 16 {
                return Err(WireError::InvalidField("node children"));
            }
            let mut prior = None;
            let mut summed = 0_u64;
            for child in &value.children {
                if child.nibble > 15 || child.item_count == 0 {
                    return Err(WireError::InvalidField("node child"));
                }
                if prior.is_some_and(|prior| prior >= child.nibble) {
                    return Err(WireError::NonCanonicalSet("node children"));
                }
                prior = Some(child.nibble);
                summed = summed
                    .checked_add(child.item_count)
                    .ok_or(WireError::IntegerOverflow)?;
            }
            if value.prefix_nibbles < OBJECT_ID_NIBBLES && summed != value.item_count {
                return Err(WireError::InvalidField("node item count"));
            }
            if value.prefix_nibbles == OBJECT_ID_NIBBLES && !value.children.is_empty() {
                return Err(WireError::InvalidField("leaf children"));
            }
            if value.prefix_nibbles == OBJECT_ID_NIBBLES && value.item_count > 1 {
                return Err(WireError::InvalidField("leaf item count"));
            }
        }
        Message::Offer(value) => validate_id_set(&value.object_ids, "offered identifiers")?,
        Message::Want(value) => {
            let mut previous = None;
            for item in &value.items {
                if previous.is_some_and(|previous| previous >= item.object_id) {
                    return Err(WireError::NonCanonicalSet("wanted identifiers"));
                }
                previous = Some(item.object_id);
                validate_ranges(&item.missing, item.total_len)?;
                if item.total_len.is_none() && !item.missing.is_empty() {
                    return Err(WireError::InvalidField("ranges without total length"));
                }
                if item.total_len.is_some() && item.missing.is_empty() && !item.need_forwarding {
                    return Err(WireError::InvalidField("want has no requested work"));
                }
                if !item.object_id.kind().supports_forwarding_metadata() && item.need_forwarding {
                    return Err(WireError::InvalidField(
                        "object kind cannot request forwarding metadata",
                    ));
                }
            }
        }
        Message::Data(value) => {
            let payload_len = usize_u64(value.payload.len())?;
            let end = value
                .offset
                .checked_add(payload_len)
                .ok_or(WireError::IntegerOverflow)?;
            if end > value.total_len {
                return Err(WireError::InvalidField("data extent"));
            }
            if value.payload.is_empty() && value.forwarding.is_empty() {
                return Err(WireError::InvalidField("empty data and forwarding"));
            }
            if !value.object_id.kind().supports_forwarding_metadata()
                && !value.forwarding.is_empty()
            {
                return Err(WireError::InvalidField(
                    "object kind carries no forwarding metadata",
                ));
            }
        }
        Message::Receipt(value) => {
            validate_ranges(&value.received, Some(value.total_len))?;
            let covered = value.total_len == 0
                || (value.received.len() == 1
                    && value.received[0].start == 0
                    && value.received[0].end == value.total_len);
            if value.complete != covered {
                return Err(WireError::InvalidField("receipt completeness"));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_interest_work(
    topic_count: usize,
    scope_count: usize,
) -> Result<usize, WireError> {
    if topic_count > MAX_INTEREST_TOPICS {
        return Err(WireError::InterestDimensionLimit {
            dimension: InterestDimension::Topics,
            actual: topic_count,
            maximum: MAX_INTEREST_TOPICS,
        });
    }
    if scope_count > MAX_INTEREST_SCOPES {
        return Err(WireError::InterestDimensionLimit {
            dimension: InterestDimension::Scopes,
            actual: scope_count,
            maximum: MAX_INTEREST_SCOPES,
        });
    }
    let work = topic_count
        .checked_mul(scope_count)
        .ok_or(WireError::IntegerOverflow)?;
    if work > MAX_INTEREST_WORK {
        return Err(WireError::InterestWorkLimit {
            actual: work,
            maximum: MAX_INTEREST_WORK,
        });
    }
    Ok(work)
}

pub(crate) fn validate_semantic_version(semantic_version: u16) -> Result<(), WireError> {
    match semantic_version {
        SEMANTIC_PROTOCOL_V1 | SEMANTIC_PROTOCOL_V2 | SEMANTIC_PROTOCOL_V3
        | SEMANTIC_PROTOCOL_V4 | SEMANTIC_PROTOCOL_V5 | SEMANTIC_PROTOCOL_V6
        | SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 | SEMANTIC_PROTOCOL_V9 => Ok(()),
        _ => Err(WireError::UnsupportedSemanticVersion(semantic_version)),
    }
}

pub(crate) fn validate_message_for_semantic_version(
    message: &Message,
    semantic_version: u16,
) -> Result<(), WireError> {
    validate_semantic_version(semantic_version)?;
    validate_message(message)?;
    let mut validate_id = |id: ObjectId| {
        if id.kind().is_allowed_in_semantic_version(semantic_version) {
            Ok(())
        } else {
            Err(WireError::ObjectKindRequiresSemanticV2(id.kind()))
        }
    };
    match message {
        Message::Offer(value) => value
            .object_ids
            .iter()
            .copied()
            .try_for_each(&mut validate_id),
        Message::Want(value) => value
            .items
            .iter()
            .map(|item| item.object_id)
            .try_for_each(&mut validate_id),
        Message::Data(value) => validate_id(value.object_id),
        Message::Receipt(value) => validate_id(value.object_id),
        Message::Interest(_) | Message::Summary(_) | Message::Probe(_) | Message::Node(_) => Ok(()),
    }
}

pub fn validate_prefix(prefix: &[u8], nibbles: u8) -> Result<(), WireError> {
    if nibbles > OBJECT_ID_NIBBLES || prefix.len() != usize::from(nibbles).div_ceil(2) {
        return Err(WireError::InvalidField("prefix length"));
    }
    if nibbles & 1 == 1 && prefix.last().is_some_and(|byte| byte & 0x0f != 0) {
        return Err(WireError::InvalidField("prefix padding"));
    }
    Ok(())
}

pub fn validate_ranges(ranges: &[ByteRange], total: Option<u64>) -> Result<(), WireError> {
    let mut prior_end = None;
    for range in ranges {
        if range.start >= range.end || total.is_some_and(|total| range.end > total) {
            return Err(WireError::InvalidField("byte range"));
        }
        if prior_end.is_some_and(|end| end >= range.start) {
            return Err(WireError::NonCanonicalSet("byte ranges"));
        }
        prior_end = Some(range.end);
    }
    Ok(())
}

fn validate_text_set(values: &[String], name: &'static str) -> Result<(), WireError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::NonCanonicalSet(name));
    }
    Ok(())
}

fn validate_id_set(values: &[ObjectId], name: &'static str) -> Result<(), WireError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::NonCanonicalSet(name));
    }
    Ok(())
}

fn required(map: &[(u64, Value)], key: u64) -> Result<&Value, WireError> {
    map.binary_search_by_key(&key, |entry| entry.0)
        .map(|index| &map[index].1)
        .map_err(|_| WireError::MissingField(key))
}

fn check_keys(map: &[(u64, Value)], allowed: &[u64]) -> Result<(), WireError> {
    for (key, _) in map {
        if *key <= registry::MAX_CRITICAL_KEY && !allowed.contains(key) {
            return Err(WireError::UnknownCriticalKey(*key));
        }
    }
    Ok(())
}

fn as_map(value: &Value, field: u64) -> Result<&[(u64, Value)], WireError> {
    match value {
        Value::Map(value) => Ok(value),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn as_array(value: &Value, field: u64) -> Result<&[Value], WireError> {
    match value {
        Value::Array(value) => Ok(value),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn as_unsigned(value: &Value, field: u64) -> Result<u64, WireError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn as_bool(value: &Value, field: u64) -> Result<bool, WireError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn bytes(value: &Value, field: u64) -> Result<Vec<u8>, WireError> {
    match value {
        Value::Bytes(value) => Ok(value.clone()),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn object_id(value: &Value, field: u64) -> Result<ObjectId, WireError> {
    let value = match value {
        Value::Bytes(value) => value,
        _ => return Err(WireError::WrongFieldType(field)),
    };
    let encoded = value
        .as_slice()
        .try_into()
        .map_err(|_| WireError::InvalidField("object identifier"))?;
    ObjectId::from_wire_bytes(encoded).ok_or(WireError::InvalidField("transfer object kind"))
}

fn digest32(value: &Value, field: u64) -> Result<Digest32, WireError> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| WireError::InvalidField("digest")),
        _ => Err(WireError::WrongFieldType(field)),
    }
}

fn text_array(value: &Value, field: u64) -> Result<Vec<String>, WireError> {
    as_array(value, field)?
        .iter()
        .map(|value| match value {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(WireError::WrongFieldType(field)),
        })
        .collect()
}

fn id_array(value: &Value, field: u64) -> Result<Vec<ObjectId>, WireError> {
    as_array(value, field)?
        .iter()
        .map(|value| object_id(value, field))
        .collect()
}

fn range_array(value: &Value, field: u64) -> Result<Vec<ByteRange>, WireError> {
    as_array(value, field)?
        .iter()
        .map(|value| {
            let pair = as_array(value, field)?;
            if pair.len() != 2 {
                return Err(WireError::InvalidField("byte range arity"));
            }
            ByteRange::new(as_unsigned(&pair[0], field)?, as_unsigned(&pair[1], field)?)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn limits() -> Limits {
        Limits::default()
    }

    fn selectors(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index:04}"))
            .collect()
    }

    fn object_messages(id: ObjectId) -> Vec<Message> {
        vec![
            Message::Offer(Offer {
                exchange_id: 9,
                object_ids: vec![id],
                snapshot_id: 4,
            }),
            Message::Want(Want {
                exchange_id: 9,
                items: vec![WantItem {
                    object_id: id,
                    total_len: None,
                    missing: Vec::new(),
                    need_forwarding: false,
                }],
            }),
            Message::Data(Data {
                exchange_id: 9,
                object_id: id,
                total_len: 1,
                offset: 0,
                payload: vec![7],
                forwarding: Vec::new(),
            }),
            Message::Receipt(Receipt {
                exchange_id: 9,
                object_id: id,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }),
        ]
    }

    fn arbitrary_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Unsigned),
            any::<u64>().prop_map(Value::Negative),
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
            proptest::collection::vec(any::<char>(), 0..64)
                .prop_map(|characters| Value::Text(characters.into_iter().collect())),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
        ];

        leaf.prop_recursive(4, 128, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                proptest::collection::btree_map(any::<u16>(), inner, 0..8).prop_map(|entries| {
                    Value::Map(
                        entries
                            .into_iter()
                            .map(|(key, value)| (u64::from(key), value))
                            .collect(),
                    )
                }),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn generated_subset_values_round_trip_canonically(value in arbitrary_value()) {
            let encoded = encode_value(&value, limits()).unwrap();
            let decoded = decode_value(&encoded, limits()).unwrap();
            prop_assert_eq!(&decoded, &value);
            prop_assert_eq!(encode_value(&decoded, limits()).unwrap(), encoded);
        }

        #[test]
        fn arbitrary_bytes_never_escape_canonical_reencoding(
            input in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            if let Ok(value) = decode_value(&input, limits()) {
                let canonical = encode_value(&value, limits()).unwrap();
                prop_assert_eq!(&canonical, &input);
                prop_assert_eq!(&decode_value(&canonical, limits()).unwrap(), &value);
                prop_assert_eq!(encode_value(&value, limits()).unwrap(), canonical);
            }
        }
    }

    #[test]
    fn interest_has_stable_golden_bytes() {
        let message = Message::Interest(Interest {
            exchange_id: 7,
            topics: vec!["a".into()],
            scopes: vec!["s".into()],
            min_priority: 2,
            max_offers: 10,
        });
        let encoded = encode_message(&message, limits()).unwrap();
        assert_eq!(
            encoded,
            [
                0xa7, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0x81, 0x61, 0x61, 0x04, 0x81, 0x61,
                0x73, 0x05, 0x02, 0x06, 0x0a,
            ]
        );
        assert_eq!(decode_message(&encoded, limits()).unwrap(), message);
    }

    #[test]
    fn interest_limits_bound_each_dimension_and_cartesian_work() {
        let at_work_limit = Message::Interest(Interest {
            exchange_id: 8,
            topics: selectors("topic", 64),
            scopes: selectors("scope", 64),
            min_priority: 0,
            max_offers: 256,
        });
        assert!(encode_message(&at_work_limit, limits()).is_ok());

        let topic_limit = Message::Interest(Interest {
            exchange_id: 9,
            topics: selectors("topic", MAX_INTEREST_TOPICS),
            scopes: selectors("scope", 1),
            min_priority: 0,
            max_offers: 256,
        });
        assert!(encode_message(&topic_limit, limits()).is_ok());

        let scope_limit = Message::Interest(Interest {
            exchange_id: 10,
            topics: selectors("topic", 1),
            scopes: selectors("scope", MAX_INTEREST_SCOPES),
            min_priority: 0,
            max_offers: 256,
        });
        assert!(encode_message(&scope_limit, limits()).is_ok());

        let excess_topics = Message::Interest(Interest {
            exchange_id: 11,
            topics: selectors("topic", MAX_INTEREST_TOPICS + 1),
            scopes: selectors("scope", 1),
            min_priority: 0,
            max_offers: 256,
        });
        assert_eq!(
            encode_message(&excess_topics, limits()),
            Err(WireError::InterestDimensionLimit {
                dimension: InterestDimension::Topics,
                actual: MAX_INTEREST_TOPICS + 1,
                maximum: MAX_INTEREST_TOPICS,
            })
        );

        let excess_scopes = Message::Interest(Interest {
            exchange_id: 12,
            topics: selectors("topic", 1),
            scopes: selectors("scope", MAX_INTEREST_SCOPES + 1),
            min_priority: 0,
            max_offers: 256,
        });
        assert_eq!(
            encode_message(&excess_scopes, limits()),
            Err(WireError::InterestDimensionLimit {
                dimension: InterestDimension::Scopes,
                actual: MAX_INTEREST_SCOPES + 1,
                maximum: MAX_INTEREST_SCOPES,
            })
        );

        let excess_work = Message::Interest(Interest {
            exchange_id: 13,
            topics: selectors("topic", 65),
            scopes: selectors("scope", 64),
            min_priority: 0,
            max_offers: 256,
        });
        assert_eq!(
            encode_message(&excess_work, limits()),
            Err(WireError::InterestWorkLimit {
                actual: 65 * 64,
                maximum: MAX_INTEREST_WORK,
            })
        );
    }

    #[test]
    fn decoded_maximal_interest_is_rejected_by_protocol_limits() {
        let message = Message::Interest(Interest {
            exchange_id: 14,
            topics: selectors("topic", Limits::default().max_collection_items),
            scopes: selectors("scope", Limits::default().max_collection_items),
            min_priority: 0,
            max_offers: 256,
        });
        // Deliberately encode the CBOR value below message validation to model
        // bytes supplied by an untrusted peer rather than a local producer.
        let encoded = encode_value(&message_value(&message), limits()).unwrap();
        assert_eq!(
            decode_message(&encoded, limits()),
            Err(WireError::InterestDimensionLimit {
                dimension: InterestDimension::Topics,
                actual: Limits::default().max_collection_items,
                maximum: MAX_INTEREST_TOPICS,
            })
        );
    }

    #[test]
    fn every_message_round_trips() {
        let hash_a = [0x11; 32];
        let hash_b = [0x22; 32];
        let id_a = ObjectId::for_envelope(EnvelopeId::from_bytes(hash_a));
        let id_b = ObjectId::for_envelope(EnvelopeId::from_bytes(hash_b));
        let messages = vec![
            Message::Summary(Summary {
                exchange_id: 1,
                root_hash: hash_a,
                item_count: 2,
                snapshot_id: 9,
            }),
            Message::Probe(Probe {
                exchange_id: 1,
                prefix: vec![0xa0],
                prefix_nibbles: 1,
                snapshot_id: 9,
            }),
            Message::Node(Node {
                exchange_id: 1,
                prefix: vec![],
                prefix_nibbles: 0,
                hash: hash_b,
                item_count: 2,
                children: vec![ChildSummary {
                    nibble: 1,
                    hash: hash_a,
                    item_count: 2,
                }],
                snapshot_id: 9,
            }),
            Message::Offer(Offer {
                exchange_id: 1,
                object_ids: vec![id_a, id_b],
                snapshot_id: 9,
            }),
            Message::Want(Want {
                exchange_id: 1,
                items: vec![WantItem {
                    object_id: id_a,
                    total_len: Some(100),
                    missing: vec![ByteRange {
                        start: 10,
                        end: 100,
                    }],
                    need_forwarding: true,
                }],
            }),
            Message::Data(Data {
                exchange_id: 1,
                object_id: id_a,
                total_len: 3,
                offset: 1,
                payload: vec![2, 3],
                forwarding: vec![9],
            }),
            Message::Receipt(Receipt {
                exchange_id: 1,
                object_id: id_a,
                total_len: 3,
                received: vec![ByteRange { start: 0, end: 3 }],
                complete: true,
            }),
        ];
        for message in messages {
            let encoded = encode_message(&message, limits()).unwrap();
            assert_eq!(decode_message(&encoded, limits()).unwrap(), message);
        }
    }

    #[test]
    fn semantic_v2_reserves_exact_extended_kind_tags() {
        for (kind, tag) in [
            (ObjectKind::SourceBatchProof, 3),
            (ObjectKind::BridgeAuthorization, 4),
            (ObjectKind::BridgeRouteWrapper, 5),
        ] {
            let id = ObjectId::new(kind, [tag; 32]);
            assert_eq!(id.to_wire_bytes()[0], tag);
            assert_eq!(ObjectId::from_wire_bytes(id.to_wire_bytes()), Some(id));
        }
    }

    #[test]
    fn selected_v1_rejects_extended_offer_want_data_and_receipt() {
        for kind in [
            ObjectKind::SourceBatchProof,
            ObjectKind::BridgeAuthorization,
            ObjectKind::BridgeRouteWrapper,
        ] {
            let id = ObjectId::new(kind, [kind as u8; 32]);
            for message in object_messages(id) {
                assert_eq!(
                    encode_message(&message, limits()),
                    Err(WireError::ObjectKindRequiresSemanticV2(kind))
                );
                let encoded =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V2, limits())
                        .unwrap();
                assert_eq!(
                    decode_message(&encoded, limits()),
                    Err(WireError::ObjectKindRequiresSemanticV2(kind))
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V2, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V3, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V4, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V5, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V6, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V7, limits(),)
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V8, limits(),)
                        .unwrap(),
                    message
                );
            }
        }
    }

    #[test]
    fn source_and_blob_messages_are_byte_identical_on_v1_through_v8() {
        for id in [
            ObjectId::for_envelope(EnvelopeId::from_bytes([0x41; 32])),
            ObjectId::for_blob_chunk_digest([0x42; 32]),
        ] {
            for message in object_messages(id) {
                let v1 = encode_message(&message, limits()).unwrap();
                let v2 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V2, limits())
                        .unwrap();
                let v3 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V3, limits())
                        .unwrap();
                let v4 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V4, limits())
                        .unwrap();
                let v5 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V5, limits())
                        .unwrap();
                let v6 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V6, limits())
                        .unwrap();
                let v7 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V7, limits())
                        .unwrap();
                let v8 =
                    encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V8, limits())
                        .unwrap();
                assert_eq!(v2, v1);
                assert_eq!(v3, v1);
                assert_eq!(v4, v1);
                assert_eq!(v5, v1);
                assert_eq!(v6, v1);
                assert_eq!(v7, v1);
                assert_eq!(v8, v1);
                assert_eq!(decode_message(&v1, limits()).unwrap(), message);
                assert_eq!(
                    decode_message_for_semantic_version(&v2, SEMANTIC_PROTOCOL_V2, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v3, SEMANTIC_PROTOCOL_V3, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v4, SEMANTIC_PROTOCOL_V4, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v5, SEMANTIC_PROTOCOL_V5, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v6, SEMANTIC_PROTOCOL_V6, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v7, SEMANTIC_PROTOCOL_V7, limits())
                        .unwrap(),
                    message
                );
                assert_eq!(
                    decode_message_for_semantic_version(&v8, SEMANTIC_PROTOCOL_V8, limits())
                        .unwrap(),
                    message
                );
            }
        }
    }

    #[test]
    fn semantic_v9_keeps_fixed_lane_objects_but_rejects_legacy_blob_chunks() {
        let source = ObjectId::for_envelope(EnvelopeId::from_bytes([0x43; 32]));
        for message in object_messages(source) {
            let encoded =
                encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V9, limits())
                    .unwrap();
            assert_eq!(
                decode_message_for_semantic_version(&encoded, SEMANTIC_PROTOCOL_V9, limits(),)
                    .unwrap(),
                message
            );
        }

        let legacy_blob = ObjectId::for_blob_chunk_digest([0x44; 32]);
        for message in object_messages(legacy_blob) {
            assert!(matches!(
                encode_message_for_semantic_version(&message, SEMANTIC_PROTOCOL_V9, limits()),
                Err(WireError::ObjectKindRequiresSemanticV2(
                    ObjectKind::BlobChunk
                ))
            ));
        }
    }

    #[test]
    fn rejects_non_minimal_indefinite_duplicate_and_unsorted_maps() {
        assert_eq!(
            decode_value(&[0x18, 0x17], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0x38, 0x17], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0x58, 0x01, 0x00], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0x78, 0x01, b'a'], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0x98, 0x00], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0xb8, 0x00], limits()),
            Err(WireError::NonMinimalInteger)
        );
        assert_eq!(
            decode_value(&[0x18], limits()),
            Err(WireError::UnexpectedEof)
        );
        assert_eq!(
            decode_value(&[0x1f], limits()),
            Err(WireError::IndefiniteLength)
        );
        assert_eq!(
            decode_value(&[0x3c], limits()),
            Err(WireError::UnsupportedType(28))
        );
        assert_eq!(
            decode_value(&[0x9f, 0xff], limits()),
            Err(WireError::IndefiniteLength)
        );
        assert_eq!(
            decode_value(&[0xa2, 0x00, 0x01, 0x00, 0x02], limits()),
            Err(WireError::DuplicateMapKey(0))
        );
        assert_eq!(
            decode_value(&[0xa2, 0x01, 0x01, 0x00, 0x02], limits()),
            Err(WireError::NonCanonicalMapOrder)
        );
    }

    #[test]
    fn preserves_the_complete_cbor_integer_domain() {
        for (value, encoded) in [
            (
                Value::Unsigned(u64::MAX),
                [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
            (
                Value::Negative(u64::MAX),
                [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ] {
            assert_eq!(encode_value(&value, limits()).unwrap(), encoded);
            assert_eq!(decode_value(&encoded, limits()).unwrap(), value);
        }
    }

    #[test]
    fn rejects_unknown_critical_but_ignores_optional_extension() {
        let critical = [0xa4, 0x00, 0x01, 0x01, 0x02, 0x02, 0x01, 0x18, 0x3f, 0x00];
        assert_eq!(
            decode_message(&critical, limits()),
            Err(WireError::UnknownCriticalKey(63))
        );

        let optional = [0xa7, 0x00, 0x01, 0x01, 0x02, 0x02, 0x01, 0x03, 0x58, 0x20];
        let mut optional = optional.to_vec();
        optional.extend_from_slice(&[0_u8; 32]);
        optional.extend_from_slice(&[0x04, 0x00, 0x05, 0x00, 0x18, 0x40, 0xf6]);
        let decoded = decode_message(&optional, limits()).unwrap();
        assert!(matches!(decoded, Message::Summary(_)));
    }

    #[test]
    fn enforces_depth_and_size_before_allocation() {
        let shallow = Limits {
            max_depth: 1,
            ..limits()
        };
        assert_eq!(
            decode_value(&[0x81, 0x81, 0x00], shallow),
            Err(WireError::DepthLimit)
        );
        let tiny = Limits {
            max_byte_string: 2,
            ..limits()
        };
        assert_eq!(
            decode_value(&[0x43, 1, 2, 3], tiny),
            Err(WireError::ByteStringLimit)
        );
    }

    #[test]
    fn rejects_semantically_ambiguous_ranges_and_prefixes() {
        let overlapping = Message::Want(Want {
            exchange_id: 1,
            items: vec![WantItem {
                object_id: ObjectId::for_envelope(EnvelopeId::from_bytes([1; 32])),
                total_len: Some(10),
                missing: vec![
                    ByteRange { start: 0, end: 5 },
                    ByteRange { start: 5, end: 10 },
                ],
                need_forwarding: true,
            }],
        });
        assert_eq!(
            encode_message(&overlapping, limits()),
            Err(WireError::NonCanonicalSet("byte ranges"))
        );
        assert_eq!(
            validate_prefix(&[0xaf], 1),
            Err(WireError::InvalidField("prefix padding"))
        );
    }
}
