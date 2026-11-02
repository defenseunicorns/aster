use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"ASM\x01";
const COMPOSITE_DATA_MAGIC: &[u8; 4] = b"ASD1";
pub(crate) const PROFILE5_SOURCE_CHUNK_BYTES: usize = 1024 * 1024;
pub(crate) const PROFILE5_PACK_RECORD_PREFIX_BYTES: usize = 4;
/// Maximum exact length-prefixed ASTRBS02 record size.
pub(crate) const PROFILE5_PACK_SEGMENT_RECORD_BYTES: usize =
    aster_mesh::BLOB_STREAM_SEGMENT_BYTES + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES;
/// One length-prefixed authenticated ASTRBS02 record. Native Profile-5 pack
/// transfer keeps the record intact instead of emitting a tiny tail frame.
pub(crate) const PROFILE5_PACK_TRANSPORT_FRAME_BYTES: usize =
    PROFILE5_PACK_RECORD_PREFIX_BYTES + PROFILE5_PACK_SEGMENT_RECORD_BYTES;
pub(crate) const PROFILE5_MAX_PACK_SEGMENTS: usize =
    (aster_mesh::MAX_BLOB_STREAM_BYTES / aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64) as usize;
pub(crate) const PROFILE5_MAX_PACK_WIRE_BYTES: u64 = aster_mesh::MAX_BLOB_STREAM_BYTES
    + PROFILE5_MAX_PACK_SEGMENTS as u64
        * (PROFILE5_PACK_RECORD_PREFIX_BYTES as u64
            + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64);
/// No authenticated protocol progress for this long is a retryable stall.
pub(crate) const PROFILE5_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// Legacy pack paths retain their bounded attempt while profile-5 canonical
/// streams use the size-derived hard bound below.
pub(crate) const PROFILE5_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PROFILE5_MIN_USEFUL_BYTES_PER_SECOND: u64 = 128 * 1024;
const PROFILE5_SETTLEMENT_HEADROOM: Duration = Duration::from_secs(20 * 60);
pub(crate) const MAX_STREAM_EXTENT_BYTES: usize = PROFILE5_PACK_TRANSPORT_FRAME_BYTES;
pub(crate) const MAX_STREAM_CHECKPOINT_BATCH_BYTES: u32 = 128 * 1_048_576;
pub(crate) const STREAM_DATA_FIXED_BYTES: usize = 89;
pub(crate) const MAX_PROTECTED_STREAM_DATA_HEADER_BYTES: usize = 2 * 1024;
pub(crate) const MAX_COMPOSITE_STREAM_DATA_BYTES: usize =
    8 + MAX_PROTECTED_STREAM_DATA_HEADER_BYTES + MAX_STREAM_EXTENT_BYTES;
pub(crate) const MAX_STREAM_DATA_FRAME_BYTES: usize =
    STREAM_DATA_FIXED_BYTES + MAX_STREAM_EXTENT_BYTES;
pub(crate) const MAX_STREAM_SEMANTIC_COMMITMENT_BYTES: usize = 64 * 1024;
/// Signed canonical source envelope, including the maximum 8-GiB Blob's
/// bounded ~9-MiB manifest plus route and signature material.
pub(crate) const MAX_STREAM_AUTHENTICATED_OPEN_BYTES: usize =
    aster_mesh::MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES;
pub(crate) const STREAM_TAGS: std::ops::RangeInclusive<u8> = 0xd6..=0xdd;

pub(crate) fn profile5_receive_limit(total: u64, durable: u64, checkpoint_batch: u32) -> u64 {
    let record = PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u64;
    // Record boundaries need not align with the byte batch. Admit the one
    // whole maximum-size native pack record that can cross the threshold.
    let window = u64::from(checkpoint_batch).saturating_add(record.saturating_sub(1));
    total.min(durable.saturating_add(window))
}

pub(crate) fn profile5_attempt_bounds(bytes: u64) -> Result<(u64, u64), StreamError> {
    let extents = if bytes == 0 {
        0
    } else {
        usize::try_from(bytes.min(PROFILE5_MAX_PACK_SEGMENTS as u64))
            .map_err(|_| StreamError::invalid("extent count overflow"))?
    };
    profile5_attempt_bounds_for_extents(bytes, extents)
}

/// Bounds one attempt with its authenticated native pack-record count. Each
/// record pays the complete ASD1 prefix/protected-header ceiling plus a
/// conservative transport-accounting allowance; callers with a verified open
/// pass its exact segment count.
pub(crate) fn profile5_attempt_bounds_for_extents(
    bytes: u64,
    extents: usize,
) -> Result<(u64, u64), StreamError> {
    if extents > PROFILE5_MAX_PACK_SEGMENTS || (bytes == 0) != (extents == 0) {
        return Err(StreamError::invalid(
            "native pack record count is out of bounds",
        ));
    }
    let extents = extents as u64;
    let data = extents
        .checked_mul(8 + MAX_PROTECTED_STREAM_DATA_HEADER_BYTES as u64 + 192)
        .and_then(|overhead| bytes.checked_add(overhead))
        .and_then(|value| {
            value.checked_add(
                (MAX_STREAM_AUTHENTICATED_OPEN_BYTES + MAX_STREAM_SEMANTIC_COMMITMENT_BYTES + 4096)
                    as u64,
            )
        })
        .ok_or_else(|| StreamError::invalid("data stream bound overflow"))?;
    // A receiver may select a batch smaller than the profile maximum. One
    // cumulative checkpoint per admitted extent is the bounded worst case.
    let control = extents
        .checked_mul(192)
        .and_then(|value| value.checked_add(8192))
        .ok_or_else(|| StreamError::invalid("control stream bound overflow"))?;
    Ok((data, control))
}

/// Hard cancellation bound for one canonical attempt. The 128-KiB/s floor is
/// more than an order of magnitude below the measured 1.5-MiB/s CM4 result;
/// idle progress is governed independently by `PROFILE5_IDLE_TIMEOUT`.
pub(crate) fn profile5_attempt_hard_timeout(bytes: u64) -> Duration {
    Duration::from_secs(bytes.div_ceil(PROFILE5_MIN_USEFUL_BYTES_PER_SECOND))
        .saturating_add(PROFILE5_SETTLEMENT_HEADROOM)
}

pub(crate) fn blob_pack_wire_len(plaintext_len: u64) -> Result<u64, StreamError> {
    let segments = plaintext_len.div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64);
    plaintext_len
        .checked_add(
            segments
                .checked_mul(
                    PROFILE5_PACK_RECORD_PREFIX_BYTES as u64
                        + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64,
                )
                .ok_or_else(|| StreamError::invalid("wire length overflow"))?,
        )
        .ok_or_else(|| StreamError::invalid("wire length overflow"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamError(String);
impl StreamError {
    fn invalid(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}
impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StreamError {}

pub(crate) fn inspect_native_pack_record(
    bytes: &[u8],
) -> Result<aster_mesh::EncryptedBlobStreamSegmentHeader, StreamError> {
    let encoded_len = bytes
        .get(..PROFILE5_PACK_RECORD_PREFIX_BYTES)
        .and_then(|prefix| prefix.try_into().ok())
        .map(u32::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| StreamError::invalid("native pack record prefix is truncated"))?;
    if encoded_len == 0
        || encoded_len > PROFILE5_PACK_SEGMENT_RECORD_BYTES
        || bytes.len() != PROFILE5_PACK_RECORD_PREFIX_BYTES + encoded_len
    {
        return Err(StreamError::invalid("native pack record length is invalid"));
    }
    aster_mesh::EncryptedBlobStreamSegment::inspect_encoded(
        &bytes[PROFILE5_PACK_RECORD_PREFIX_BYTES..],
    )
    .map_err(|error| StreamError::invalid(format!("native ASTRBS02 record is invalid: {error}")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamClass {
    Blob = 1,
}
impl StreamClass {
    pub(crate) fn decode(v: u8) -> Result<Self, StreamError> {
        (v == 1)
            .then_some(Self::Blob)
            .ok_or_else(|| StreamError::invalid("unknown required stream class"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamDirection {
    ToSessionInitiator = 1,
    ToSessionResponder = 2,
}
impl StreamDirection {
    fn decode(v: u8) -> Result<Self, StreamError> {
        match v {
            1 => Ok(Self::ToSessionInitiator),
            2 => Ok(Self::ToSessionResponder),
            _ => Err(StreamError::invalid("unknown stream direction")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamResultCode {
    Promoted = 1,
    AlreadyPresent = 2,
    DeferredCapacity = 3,
    RetiredExpired = 4,
    RejectedPolicy = 5,
    IntegrityFailure = 6,
}
impl StreamResultCode {
    fn decode(v: u8) -> Result<Self, StreamError> {
        match v {
            1 => Ok(Self::Promoted),
            2 => Ok(Self::AlreadyPresent),
            3 => Ok(Self::DeferredCapacity),
            4 => Ok(Self::RetiredExpired),
            5 => Ok(Self::RejectedPolicy),
            6 => Ok(Self::IntegrityFailure),
            _ => Err(StreamError::invalid("unknown stream result")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamOpenV1 {
    pub class: StreamClass,
    pub direction: StreamDirection,
    pub session_transcript: [u8; 32],
    pub exchange_id: u64,
    pub transfer_id: [u8; 32],
    pub source_transfer_id: [u8; 32],
    pub publication_id: [u8; 32],
    pub variant_id: [u8; 32],
    pub total_len: u64,
    pub attempt_nonce: [u8; 32],
    pub checkpoint_generation: u64,
    pub custody_digest: Option<[u8; 32]>,
    pub source_len: u32,
    pub source_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamSourceV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub offset: u32,
    pub total_len: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamAcceptV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub durable_offset: u64,
    pub checkpoint_generation: u64,
    pub absolute_receive_limit: u64,
    pub max_extent_bytes: u32,
    pub checkpoint_batch_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamDataV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamDataHeaderV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub offset: u64,
    pub extent_len: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamCheckpointV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub durable_offset: u64,
    pub checkpoint_generation: u64,
    pub absolute_receive_limit: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamFinishV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub final_offset: u64,
    pub semantic_commitment: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamResultV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub final_offset: u64,
    pub code: StreamResultCode,
    pub result_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamResultAckV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub result_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StreamFrame {
    Open(StreamOpenV1),
    Source(StreamSourceV1),
    Accept(StreamAcceptV1),
    Data(StreamDataV1),
    Checkpoint(StreamCheckpointV1),
    Finish(StreamFinishV1),
    Result(StreamResultV1),
    ResultAck(StreamResultAckV1),
}

fn context(v: u16, p: u16) -> Result<(), StreamError> {
    if v == 9 && p == 5 {
        Ok(())
    } else {
        Err(StreamError::invalid(
            "stream records require semantic v9 profile 5",
        ))
    }
}
fn nonce(v: &[u8; 32]) -> Result<(), StreamError> {
    if v.iter().all(|b| *b == 0) {
        Err(StreamError::invalid("zero attempt nonce"))
    } else {
        Ok(())
    }
}
fn extent(v: u32) -> Result<(), StreamError> {
    if v == 0 || v as usize > MAX_STREAM_EXTENT_BYTES {
        Err(StreamError::invalid("extent length out of bounds"))
    } else {
        Ok(())
    }
}
fn validate_semantic_commitment(bytes: &[u8]) -> Result<(), StreamError> {
    validate_semantic_commitment_with_max(bytes, MAX_STREAM_SEMANTIC_COMMITMENT_BYTES)
}
fn validate_semantic_commitment_with_max(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), StreamError> {
    if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes {
        Err(StreamError::invalid(
            "semantic commitment length is out of bounds",
        ))
    } else {
        Ok(())
    }
}

fn validate_authenticated_open(bytes: &[u8]) -> Result<(), StreamError> {
    validate_authenticated_open_with_max(bytes, MAX_STREAM_AUTHENTICATED_OPEN_BYTES)
}
fn validate_profile5_wire_len(bytes: u64) -> Result<(), StreamError> {
    if bytes <= PROFILE5_MAX_PACK_WIRE_BYTES {
        Ok(())
    } else {
        Err(StreamError::invalid(
            "native Profile-5 pack wire length exceeds profile 5",
        ))
    }
}
fn validate_authenticated_open_with_max(bytes: &[u8], max_bytes: usize) -> Result<(), StreamError> {
    if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes {
        Err(StreamError::invalid(
            "authenticated open length is out of bounds",
        ))
    } else {
        Ok(())
    }
}
fn put_attempt(o: &mut Vec<u8>, id: &[u8; 32], n: &[u8; 32], s: u64) {
    o.extend_from_slice(id);
    o.extend_from_slice(n);
    o.extend_from_slice(&s.to_be_bytes());
}

impl StreamFrame {
    pub(crate) fn declared_direction(&self) -> Option<StreamDirection> {
        match self {
            Self::Open(value) => Some(value.direction),
            Self::Source(_)
            | Self::Accept(_)
            | Self::Data(_)
            | Self::Checkpoint(_)
            | Self::Finish(_)
            | Self::Result(_)
            | Self::ResultAck(_) => None,
        }
    }

    pub(crate) fn attempt_binding(&self) -> ([u8; 32], Option<u64>) {
        match self {
            Self::Open(value) => (value.attempt_nonce, None),
            Self::Source(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Accept(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Data(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Checkpoint(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Finish(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Result(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::ResultAck(value) => (value.attempt_nonce, Some(value.sequence)),
        }
    }

    pub(crate) fn encode_for_context(&self, v: u16, p: u16) -> Result<Vec<u8>, StreamError> {
        context(v, p)?;
        let mut o = MAGIC.to_vec();
        match self {
            Self::Open(x) => {
                nonce(&x.attempt_nonce)?;
                validate_profile5_wire_len(x.total_len)?;
                if x.source_len == 0
                    || usize::try_from(x.source_len)
                        .ok()
                        .is_none_or(|length| length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES)
                {
                    return Err(StreamError::invalid(
                        "authenticated source length is out of bounds",
                    ));
                }
                o.push(0xd6);
                o.extend([x.class as u8, x.direction as u8]);
                o.extend(9u16.to_be_bytes());
                o.extend(5u16.to_be_bytes());
                o.extend(x.session_transcript);
                o.extend(x.exchange_id.to_be_bytes());
                o.extend(x.transfer_id);
                o.extend(x.source_transfer_id);
                o.extend(x.publication_id);
                o.extend(x.variant_id);
                o.extend(x.total_len.to_be_bytes());
                o.extend(x.attempt_nonce);
                o.extend(x.checkpoint_generation.to_be_bytes());
                match x.custody_digest {
                    None => o.push(0),
                    Some(d) => {
                        o.push(1);
                        o.extend(d)
                    }
                }
                o.extend(x.source_len.to_be_bytes());
                o.extend(x.source_digest);
            }
            Self::Source(x) => {
                nonce(&x.attempt_nonce)?;
                if x.bytes.is_empty()
                    || x.bytes.len() > PROFILE5_SOURCE_CHUNK_BYTES
                    || x.total_len == 0
                    || usize::try_from(x.total_len)
                        .ok()
                        .is_none_or(|length| length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES)
                    || x.offset
                        .checked_add(u32::try_from(x.bytes.len()).map_err(|_| {
                            StreamError::invalid("authenticated source chunk overflows")
                        })?)
                        .is_none_or(|end| end > x.total_len)
                {
                    return Err(StreamError::invalid(
                        "authenticated source chunk is out of bounds",
                    ));
                }
                o.push(0xdd);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.offset.to_be_bytes());
                o.extend(x.total_len.to_be_bytes());
                o.extend(
                    u32::try_from(x.bytes.len())
                        .map_err(|_| StreamError::invalid("authenticated source chunk overflows"))?
                        .to_be_bytes(),
                );
                o.extend(&x.bytes);
            }
            Self::Accept(x) => {
                nonce(&x.attempt_nonce)?;
                extent(x.max_extent_bytes)?;
                if x.absolute_receive_limit < x.durable_offset
                    || x.checkpoint_batch_bytes == 0
                    || x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
                {
                    return Err(StreamError::invalid("invalid accept bounds"));
                }
                o.push(0xd7);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.durable_offset.to_be_bytes());
                o.extend(x.checkpoint_generation.to_be_bytes());
                o.extend(x.absolute_receive_limit.to_be_bytes());
                o.extend(x.max_extent_bytes.to_be_bytes());
                o.extend(x.checkpoint_batch_bytes.to_be_bytes());
            }
            Self::Data(x) => {
                nonce(&x.attempt_nonce)?;
                let l = u32::try_from(x.bytes.len())
                    .map_err(|_| StreamError::invalid("extent overflow"))?;
                extent(l)?;
                x.offset
                    .checked_add(l.into())
                    .ok_or_else(|| StreamError::invalid("offset overflow"))?;
                o.push(0xd8);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.offset.to_be_bytes());
                o.extend(l.to_be_bytes());
                o.extend(&x.bytes);
            }
            Self::Checkpoint(x) => {
                nonce(&x.attempt_nonce)?;
                if x.absolute_receive_limit < x.durable_offset {
                    return Err(StreamError::invalid(
                        "checkpoint credit precedes durable offset",
                    ));
                }
                o.push(0xd9);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.durable_offset.to_be_bytes());
                o.extend(x.checkpoint_generation.to_be_bytes());
                o.extend(x.absolute_receive_limit.to_be_bytes());
            }
            Self::Finish(x) => {
                nonce(&x.attempt_nonce)?;
                validate_semantic_commitment(&x.semantic_commitment)?;
                o.push(0xda);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.final_offset.to_be_bytes());
                o.extend(
                    u32::try_from(x.semantic_commitment.len())
                        .map_err(|_| StreamError::invalid("semantic commitment overflow"))?
                        .to_be_bytes(),
                );
                o.extend(&x.semantic_commitment);
            }
            Self::Result(x) => {
                nonce(&x.attempt_nonce)?;
                o.push(0xdb);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.final_offset.to_be_bytes());
                o.push(x.code as u8);
                o.extend(x.result_digest);
            }
            Self::ResultAck(x) => {
                nonce(&x.attempt_nonce)?;
                o.push(0xdc);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.result_digest);
            }
        }
        Ok(o)
    }
    pub(crate) fn decode_for_context(v: u16, p: u16, b: &[u8]) -> Result<Self, StreamError> {
        context(v, p)?;
        if b.len() < 5 || &b[..4] != MAGIC {
            return Err(StreamError::invalid("invalid stream frame"));
        }
        if b[4] == 0xd8 {
            return decode_data(b).map(Self::Data);
        }
        let mut r = Reader::new(&b[5..]);
        let f = match b[4] {
            0xd6 => {
                let class = StreamClass::decode(r.u8()?)?;
                let direction = StreamDirection::decode(r.u8()?)?;
                if r.u16() != Ok(9) || r.u16() != Ok(5) {
                    return Err(StreamError::invalid("open binding differs"));
                }
                let session_transcript = r.array()?;
                let exchange_id = r.u64()?;
                let transfer_id = r.array()?;
                let source_transfer_id = r.array()?;
                let publication_id = r.array()?;
                let variant_id = r.array()?;
                let total_len = r.u64()?;
                validate_profile5_wire_len(total_len)?;
                let attempt_nonce = r.array()?;
                nonce(&attempt_nonce)?;
                let checkpoint_generation = r.u64()?;
                let custody_digest = match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(StreamError::invalid("noncanonical custody presence")),
                };
                let source_len = r.u32()?;
                if source_len == 0
                    || usize::try_from(source_len)
                        .ok()
                        .is_none_or(|length| length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES)
                {
                    return Err(StreamError::invalid(
                        "authenticated source length is out of bounds",
                    ));
                }
                let source_digest = r.array()?;
                Self::Open(StreamOpenV1 {
                    class,
                    direction,
                    session_transcript,
                    exchange_id,
                    transfer_id,
                    source_transfer_id,
                    publication_id,
                    variant_id,
                    total_len,
                    attempt_nonce,
                    checkpoint_generation,
                    custody_digest,
                    source_len,
                    source_digest,
                })
            }
            0xdd => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let offset = r.u32()?;
                let total_len = r.u32()?;
                let chunk_len = usize::try_from(r.u32()?)
                    .map_err(|_| StreamError::invalid("authenticated source chunk overflows"))?;
                if chunk_len == 0
                    || chunk_len > PROFILE5_SOURCE_CHUNK_BYTES
                    || total_len == 0
                    || usize::try_from(total_len)
                        .ok()
                        .is_none_or(|length| length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES)
                    || offset
                        .checked_add(u32::try_from(chunk_len).map_err(|_| {
                            StreamError::invalid("authenticated source chunk overflows")
                        })?)
                        .is_none_or(|end| end > total_len)
                {
                    return Err(StreamError::invalid(
                        "authenticated source chunk is out of bounds",
                    ));
                }
                Self::Source(StreamSourceV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    offset,
                    total_len,
                    bytes: r.take(chunk_len)?.to_vec(),
                })
            }
            0xd7 => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let x = StreamAcceptV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    durable_offset: r.u64()?,
                    checkpoint_generation: r.u64()?,
                    absolute_receive_limit: r.u64()?,
                    max_extent_bytes: r.u32()?,
                    checkpoint_batch_bytes: r.u32()?,
                };
                extent(x.max_extent_bytes)?;
                if x.absolute_receive_limit < x.durable_offset
                    || x.checkpoint_batch_bytes == 0
                    || x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
                {
                    return Err(StreamError::invalid("invalid accept bounds"));
                }
                Self::Accept(x)
            }
            0xd9 => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let x = StreamCheckpointV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    durable_offset: r.u64()?,
                    checkpoint_generation: r.u64()?,
                    absolute_receive_limit: r.u64()?,
                };
                if x.absolute_receive_limit < x.durable_offset {
                    return Err(StreamError::invalid("invalid checkpoint"));
                }
                Self::Checkpoint(x)
            }
            0xda => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let final_offset = r.u64()?;
                let commitment_len = usize::try_from(r.u32()?)
                    .map_err(|_| StreamError::invalid("semantic commitment overflow"))?;
                if commitment_len == 0 || commitment_len > MAX_STREAM_SEMANTIC_COMMITMENT_BYTES {
                    return Err(StreamError::invalid(
                        "semantic commitment length is out of bounds",
                    ));
                }
                Self::Finish(StreamFinishV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    final_offset,
                    semantic_commitment: r.take(commitment_len)?.to_vec(),
                })
            }
            0xdb => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                Self::Result(StreamResultV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    final_offset: r.u64()?,
                    code: StreamResultCode::decode(r.u8()?)?,
                    result_digest: r.array()?,
                })
            }
            0xdc => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                Self::ResultAck(StreamResultAckV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    result_digest: r.array()?,
                })
            }
            _ => return Err(StreamError::invalid("unknown stream tag")),
        };
        r.finish()?;
        Ok(f)
    }
}

impl StreamDataHeaderV1 {
    fn validate_for_context(&self, v: u16, p: u16) -> Result<(), StreamError> {
        context(v, p)?;
        nonce(&self.attempt_nonce)?;
        extent(self.extent_len)?;
        self.offset
            .checked_add(self.extent_len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        Ok(())
    }

    pub(crate) fn encode_for_context(self, v: u16, p: u16) -> Result<Vec<u8>, StreamError> {
        self.validate_for_context(v, p)?;
        #[cfg(test)]
        DATA_HEADER_ENCODING_COUNT.with(|count| count.set(count.get() + 1));
        let mut output = Vec::with_capacity(STREAM_DATA_FIXED_BYTES);
        output.extend_from_slice(MAGIC);
        output.push(0xd8);
        put_attempt(
            &mut output,
            &self.transfer_id,
            &self.attempt_nonce,
            self.sequence,
        );
        output.extend_from_slice(&self.offset.to_be_bytes());
        output.extend_from_slice(&self.extent_len.to_be_bytes());
        Ok(output)
    }

    pub(crate) fn decode_for_context(v: u16, p: u16, b: &[u8]) -> Result<Self, StreamError> {
        context(v, p)?;
        if b.len() != STREAM_DATA_FIXED_BYTES || &b[..4] != MAGIC || b[4] != 0xd8 {
            return Err(StreamError::invalid("data header differs"));
        }
        let mut r = Reader::new(&b[5..]);
        let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
        let offset = r.u64()?;
        let extent_len = r.u32()?;
        r.finish()?;
        extent(extent_len)?;
        offset
            .checked_add(extent_len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        Ok(Self {
            transfer_id,
            attempt_nonce,
            sequence,
            offset,
            extent_len,
        })
    }
    pub(crate) fn decode_body(self, b: &[u8]) -> Result<StreamDataV1, StreamError> {
        if b.len() != self.extent_len as usize {
            return Err(StreamError::invalid("data body length differs"));
        }
        Ok(StreamDataV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.attempt_nonce,
            sequence: self.sequence,
            offset: self.offset,
            bytes: b.to_vec(),
        })
    }
}

#[cfg(test)]
std::thread_local! {
    static DATA_HEADER_ENCODING_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn test_data_header_encoding_count() -> usize {
    DATA_HEADER_ENCODING_COUNT.with(std::cell::Cell::get)
}

impl StreamDataV1 {
    pub(crate) fn into_header_and_body(
        mut self,
    ) -> Result<(StreamDataHeaderV1, Vec<u8>), StreamError> {
        let extent_len = match u32::try_from(self.bytes.len()) {
            Ok(length) => length,
            Err(_) => {
                self.bytes.zeroize();
                return Err(StreamError::invalid("extent overflow"));
            }
        };
        let header = StreamDataHeaderV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.attempt_nonce,
            sequence: self.sequence,
            offset: self.offset,
            extent_len,
        };
        if let Err(error) = header.validate_for_context(9, 5) {
            self.bytes.zeroize();
            return Err(error);
        }
        Ok((header, std::mem::take(&mut self.bytes)))
    }
}

pub(crate) fn encode_composite_data_record(
    protected_header: &[u8],
    body: Vec<u8>,
) -> Result<Vec<u8>, StreamError> {
    let mut output = encode_composite_data_prefix(protected_header)?;
    output
        .try_reserve(body.len())
        .map_err(|_| StreamError::invalid("composite data record length overflow"))?;
    output.extend_from_slice(&body);
    Ok(output)
}

pub(crate) fn encode_composite_data_prefix(
    protected_header: &[u8],
) -> Result<Vec<u8>, StreamError> {
    if protected_header.is_empty()
        || protected_header.len() > MAX_PROTECTED_STREAM_DATA_HEADER_BYTES
    {
        return Err(StreamError::invalid(
            "protected data header length exceeds its bound",
        ));
    }
    let protected_len = u32::try_from(protected_header.len())
        .map_err(|_| StreamError::invalid("protected data header length exceeds wire field"))?;
    let capacity = 8_usize
        .checked_add(protected_header.len())
        .ok_or_else(|| StreamError::invalid("composite data record length overflow"))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(COMPOSITE_DATA_MAGIC);
    output.extend_from_slice(&protected_len.to_be_bytes());
    output.extend_from_slice(protected_header);
    Ok(output)
}

pub(crate) fn split_composite_data_record(bytes: &[u8]) -> Result<(&[u8], &[u8]), StreamError> {
    if bytes.len() < 8 || &bytes[..4] != COMPOSITE_DATA_MAGIC {
        return Err(StreamError::invalid("composite data record marker differs"));
    }
    let protected_len = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| StreamError::invalid("truncated protected data header length"))?,
    ) as usize;
    if protected_len == 0 || protected_len > MAX_PROTECTED_STREAM_DATA_HEADER_BYTES {
        return Err(StreamError::invalid(
            "protected data header length exceeds its bound",
        ));
    }
    let body_offset = 8_usize
        .checked_add(protected_len)
        .ok_or_else(|| StreamError::invalid("composite data record length overflow"))?;
    if body_offset > bytes.len() {
        return Err(StreamError::invalid("truncated protected data header"));
    }
    Ok((&bytes[8..body_offset], &bytes[body_offset..]))
}
fn decode_data(b: &[u8]) -> Result<StreamDataV1, StreamError> {
    if b.len() < STREAM_DATA_FIXED_BYTES {
        return Err(StreamError::invalid("truncated data header"));
    }
    StreamDataHeaderV1::decode_for_context(9, 5, &b[..STREAM_DATA_FIXED_BYTES])?
        .decode_body(&b[STREAM_DATA_FIXED_BYTES..])
}

struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamRetry {
    CreditBlocked,
    DuplicateBelowCheckpoint,
    TransportLost,
    SettlementPending,
}
#[derive(Clone, Debug, Eq, PartialEq)]
// Frames remain inline deliberately: actions are transient state-machine
// results, and boxing every data/control frame would add a hot-path allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum StreamAction {
    SendData,
    SendFinish,
    Send(StreamFrame),
    Persist { through: u64 },
    Promote,
    Retry(StreamRetry),
    Terminal(StreamResultCode),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StreamExtentAction {
    Send(StreamDataV1),
    Retry { reason: StreamRetry, bytes: Vec<u8> },
}

#[derive(Debug)]
pub(crate) struct StreamSenderState {
    transfer_id: [u8; 32],
    nonce: [u8; 32],
    total: u64,
    durable: u64,
    next: u64,
    limit: u64,
    max_extent: u32,
    generation: u64,
    send_sequence: u64,
    control_sequence: u64,
    last_result: Option<(StreamResultV1, StreamResultAckV1)>,
}
impl StreamSenderState {
    pub(crate) fn new(transfer_id: [u8; 32], nonce: [u8; 32], total: u64) -> Self {
        Self {
            transfer_id,
            nonce,
            total,
            durable: 0,
            next: 0,
            limit: 0,
            max_extent: 0,
            generation: 0,
            send_sequence: 0,
            control_sequence: 0,
            last_result: None,
        }
    }
    pub(crate) const fn transport_lost(&self) -> StreamAction {
        StreamAction::Retry(StreamRetry::TransportLost)
    }
    pub(crate) fn accept(&mut self, x: StreamAcceptV1) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if x.sequence != 0
            || x.durable_offset > x.absolute_receive_limit
            || x.absolute_receive_limit > self.total
            || x.checkpoint_batch_bytes == 0
            || x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
        {
            return Err(StreamError::invalid("invalid stream acceptance"));
        }
        extent(x.max_extent_bytes)?;
        self.durable = x.durable_offset;
        self.next = x.durable_offset;
        self.limit = x.absolute_receive_limit;
        self.max_extent = x.max_extent_bytes;
        self.generation = x.checkpoint_generation;
        self.control_sequence = 1;
        Ok(if self.durable == self.total {
            StreamAction::SendFinish
        } else {
            StreamAction::SendData
        })
    }
    pub(crate) fn send_extent(
        &mut self,
        mut bytes: Vec<u8>,
    ) -> Result<StreamExtentAction, StreamError> {
        let len = match u32::try_from(bytes.len()) {
            Ok(length) => length,
            Err(_) => {
                bytes.zeroize();
                return Err(StreamError::invalid("extent overflow"));
            }
        };
        if let Err(error) = extent(len) {
            bytes.zeroize();
            return Err(error);
        }
        if len > self.max_extent {
            bytes.zeroize();
            return Err(StreamError::invalid("extent exceeds negotiated maximum"));
        }
        let Some(end) = self.next.checked_add(len.into()) else {
            bytes.zeroize();
            return Err(StreamError::invalid("offset overflow"));
        };
        if end > self.limit {
            return Ok(StreamExtentAction::Retry {
                reason: StreamRetry::CreditBlocked,
                bytes,
            });
        }
        if end > self.total {
            bytes.zeroize();
            return Err(StreamError::invalid("data exceeds declared length"));
        }
        let f = StreamDataV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            offset: self.next,
            bytes,
        };
        self.send_sequence += 1;
        self.next = end;
        Ok(StreamExtentAction::Send(f))
    }
    pub(crate) fn checkpoint(&mut self, x: StreamCheckpointV1) -> Result<(), StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if x.sequence != self.control_sequence
            || x.durable_offset < self.durable
            || x.durable_offset > self.next
            || x.checkpoint_generation < self.generation
            || ((x.durable_offset == self.durable) != (x.checkpoint_generation == self.generation))
            || x.absolute_receive_limit < self.limit
            || x.absolute_receive_limit > self.total
        {
            return Err(StreamError::invalid("invalid cumulative checkpoint"));
        }
        self.control_sequence += 1;
        self.durable = x.durable_offset;
        self.generation = x.checkpoint_generation;
        self.limit = x.absolute_receive_limit;
        Ok(())
    }
    pub(crate) fn finish(
        &mut self,
        semantic_commitment: Vec<u8>,
    ) -> Result<StreamAction, StreamError> {
        if self.next != self.total {
            return Err(StreamError::invalid(
                "stream finish precedes declared length",
            ));
        }
        validate_semantic_commitment(&semantic_commitment)?;
        let f = StreamFinishV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            final_offset: self.total,
            semantic_commitment,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Finish(f)))
    }
    pub(crate) fn result(
        &mut self,
        x: StreamResultV1,
    ) -> Result<(StreamAction, StreamAction), StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if let Some((result, ack)) = &self.last_result {
            if result == &x {
                return Ok((
                    StreamAction::Send(StreamFrame::ResultAck(ack.clone())),
                    StreamAction::Terminal(x.code),
                ));
            }
            return Err(StreamError::invalid("terminal stream result changed"));
        }
        if x.sequence != self.control_sequence || x.final_offset != self.total {
            return Err(StreamError::invalid("stream result binding differs"));
        }
        self.control_sequence += 1;
        let ack = StreamResultAckV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            result_digest: x.result_digest,
        };
        self.send_sequence += 1;
        self.last_result = Some((x.clone(), ack.clone()));
        Ok((
            StreamAction::Send(StreamFrame::ResultAck(ack)),
            StreamAction::Terminal(x.code),
        ))
    }
    fn identity(&self, id: &[u8; 32], n: &[u8; 32]) -> Result<(), StreamError> {
        if id == &self.transfer_id && n == &self.nonce {
            Ok(())
        } else {
            Err(StreamError::invalid("stream attempt identity differs"))
        }
    }
}

#[derive(Debug)]
pub(crate) struct StreamReceiverState {
    transfer_id: [u8; 32],
    nonce: [u8; 32],
    total: u64,
    durable: u64,
    received: u64,
    limit: u64,
    generation: u64,
    max_extent: u32,
    receive_sequence: u64,
    send_sequence: u64,
    result_digest: Option<[u8; 32]>,
    last_finish: Option<StreamFinishV1>,
    result_frame: Option<StreamResultV1>,
    last_ack: Option<StreamResultAckV1>,
    terminal_code: Option<StreamResultCode>,
}
impl StreamReceiverState {
    pub(crate) fn new(
        open: &StreamOpenV1,
        durable: u64,
        generation: u64,
        limit: u64,
        max_extent: u32,
    ) -> Result<Self, StreamError> {
        nonce(&open.attempt_nonce)?;
        extent(max_extent)?;
        if durable > limit || limit > open.total_len {
            return Err(StreamError::invalid("receiver bounds differ"));
        }
        Ok(Self {
            transfer_id: open.transfer_id,
            nonce: open.attempt_nonce,
            total: open.total_len,
            durable,
            received: durable,
            limit,
            generation,
            max_extent,
            receive_sequence: 0,
            send_sequence: 0,
            result_digest: None,
            last_finish: None,
            result_frame: None,
            last_ack: None,
            terminal_code: None,
        })
    }
    pub(crate) fn reopen(
        previous_nonce: &[u8; 32],
        open: &StreamOpenV1,
        durable: u64,
        generation: u64,
        limit: u64,
        max_extent: u32,
    ) -> Result<Self, StreamError> {
        if previous_nonce == &open.attempt_nonce {
            return Err(StreamError::invalid("stream attempt nonce was reused"));
        }
        Self::new(open, durable, generation, limit, max_extent)
    }
    pub(crate) fn accept(&mut self, batch: u32) -> Result<StreamAction, StreamError> {
        if batch == 0 || batch > MAX_STREAM_CHECKPOINT_BATCH_BYTES {
            return Err(StreamError::invalid("checkpoint batch out of bounds"));
        }
        let f = StreamAcceptV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            durable_offset: self.durable,
            checkpoint_generation: self.generation,
            absolute_receive_limit: self.limit,
            max_extent_bytes: self.max_extent,
            checkpoint_batch_bytes: batch,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Accept(f)))
    }
    pub(crate) fn data(&mut self, x: &StreamDataV1) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if x.sequence != self.receive_sequence {
            return Err(StreamError::invalid("stream data sequence differs"));
        }
        let len =
            u32::try_from(x.bytes.len()).map_err(|_| StreamError::invalid("extent overflow"))?;
        extent(len)?;
        if len > self.max_extent {
            return Err(StreamError::invalid("extent exceeds maximum"));
        }
        let end = x
            .offset
            .checked_add(len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        if end <= self.durable {
            self.receive_sequence += 1;
            return Ok(StreamAction::Retry(StreamRetry::DuplicateBelowCheckpoint));
        }
        if x.offset != self.received || end > self.limit || end > self.total {
            return Err(StreamError::invalid(
                "stream data gap overlap or credit violation",
            ));
        }
        self.receive_sequence += 1;
        self.received = end;
        Ok(StreamAction::Persist { through: end })
    }
    pub(crate) fn persisted(
        &mut self,
        through: u64,
        generation: u64,
        new_limit: u64,
    ) -> Result<StreamAction, StreamError> {
        if through < self.durable
            || through > self.received
            || generation < self.generation
            || ((through == self.durable) != (generation == self.generation))
            || new_limit < self.limit
            || new_limit > self.total
        {
            return Err(StreamError::invalid("invalid durable checkpoint"));
        }
        self.durable = through;
        self.generation = generation;
        self.limit = new_limit;
        let f = StreamCheckpointV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            durable_offset: through,
            checkpoint_generation: generation,
            absolute_receive_limit: new_limit,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Checkpoint(f)))
    }
    pub(crate) fn finish(&mut self, x: StreamFinishV1) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        validate_semantic_commitment(&x.semantic_commitment)?;
        if self.last_finish.as_ref() == Some(&x) {
            return Ok(self.result_frame.clone().map_or(
                StreamAction::Retry(StreamRetry::SettlementPending),
                |result| StreamAction::Send(StreamFrame::Result(result)),
            ));
        }
        if x.sequence != self.receive_sequence
            || x.final_offset != self.total
            || self.received != self.total
            || self.durable != self.total
        {
            return Err(StreamError::invalid("finish before durable completion"));
        }
        self.receive_sequence += 1;
        self.last_finish = Some(x);
        Ok(StreamAction::Promote)
    }
    pub(crate) fn promoted(
        &mut self,
        code: StreamResultCode,
        digest: [u8; 32],
    ) -> Result<StreamAction, StreamError> {
        if let Some(result) = &self.result_frame {
            if result.code == code && result.result_digest == digest {
                return Ok(StreamAction::Send(StreamFrame::Result(result.clone())));
            }
            return Err(StreamError::invalid("terminal stream result changed"));
        }
        self.result_digest = Some(digest);
        let f = StreamResultV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            final_offset: self.total,
            code,
            result_digest: digest,
        };
        self.send_sequence += 1;
        self.result_frame = Some(f.clone());
        self.terminal_code = Some(code);
        Ok(StreamAction::Send(StreamFrame::Result(f)))
    }
    pub(crate) fn result_ack(
        &mut self,
        x: StreamResultAckV1,
        code: StreamResultCode,
    ) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if self.terminal_code != Some(code) {
            return Err(StreamError::invalid("terminal result code differs"));
        }
        if self.last_ack.as_ref() == Some(&x) {
            return Ok(StreamAction::Terminal(self.terminal_code.ok_or_else(
                || StreamError::invalid("terminal result is missing"),
            )?));
        }
        if x.sequence != self.receive_sequence || Some(x.result_digest) != self.result_digest {
            return Err(StreamError::invalid("result acknowledgement differs"));
        }
        self.receive_sequence += 1;
        self.last_ack = Some(x);
        Ok(StreamAction::Terminal(code))
    }
    fn identity(&self, id: &[u8; 32], n: &[u8; 32]) -> Result<(), StreamError> {
        if id == &self.transfer_id && n == &self.nonce {
            Ok(())
        } else {
            Err(StreamError::invalid("stream attempt identity differs"))
        }
    }
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], StreamError> {
        let e = self
            .o
            .checked_add(n)
            .ok_or_else(|| StreamError::invalid("length overflow"))?;
        let v = self
            .b
            .get(self.o..e)
            .ok_or_else(|| StreamError::invalid("truncated stream frame"))?;
        self.o = e;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StreamError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StreamError::invalid("fixed field differs"))
    }
    fn u8(&mut self) -> Result<u8, StreamError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, StreamError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, StreamError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, StreamError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn attempt(&mut self) -> Result<([u8; 32], [u8; 32], u64), StreamError> {
        let id = self.array()?;
        let n = self.array()?;
        nonce(&n)?;
        Ok((id, n, self.u64()?))
    }
    fn finish(self) -> Result<(), StreamError> {
        if self.o == self.b.len() {
            Ok(())
        } else {
            Err(StreamError::invalid("trailing stream bytes"))
        }
    }
}

#[cfg(feature = "fuzzing")]
fn decode_fuzz_transcript(input: &[u8]) -> Option<(bool, Vec<StreamFrame>)> {
    if !input.starts_with(b"AST1") || input.len() < 6 || input[4] > 1 {
        return None;
    }
    let expected_accept = input[4] == 1;
    let count = usize::from(input[5]);
    if count == 0 || count > 16 {
        return None;
    }
    let mut reader = Reader::new(&input[6..]);
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::try_from(reader.u32().ok()?).ok()?;
        frames.push(StreamFrame::decode_for_context(9, 5, reader.take(len).ok()?).ok()?);
    }
    reader.finish().ok()?;
    Some((expected_accept, frames))
}

#[cfg(feature = "fuzzing")]
fn model_fuzz_transcript(frames: &[StreamFrame]) -> bool {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Phase {
        Source,
        Data,
        Finished,
        Result,
        Terminal,
    }

    let Some(StreamFrame::Open(open)) = frames.first() else {
        return false;
    };
    let mut phase = Phase::Source;
    let mut source_sequence = 0_u64;
    let mut data_sequence = 0_u64;
    let mut control_sequence = 0_u64;
    let mut received = 0_u64;
    let mut durable = 0_u64;
    let mut generation = open.checkpoint_generation;
    let mut limit = open.total_len;
    let mut max_extent = MAX_STREAM_EXTENT_BYTES as u32;
    let mut result: Option<StreamResultV1> = None;
    let mut expected_ack: Option<StreamResultAckV1> = None;

    let bound =
        |id: &[u8; 32], nonce: &[u8; 32]| id == &open.transfer_id && nonce == &open.attempt_nonce;
    for frame in &frames[1..] {
        match frame {
            StreamFrame::Open(_) => return false,
            StreamFrame::Source(value) if phase == Phase::Source => {
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != source_sequence
                {
                    return false;
                }
                source_sequence += 1;
            }
            StreamFrame::Accept(value) if phase == Phase::Source => {
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != 0
                    || value.durable_offset != 0
                    || value.checkpoint_generation != generation
                    || value.absolute_receive_limit != limit
                    || value.max_extent_bytes == 0
                    || value.max_extent_bytes > max_extent
                    || value.checkpoint_batch_bytes == 0
                    || value.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
                {
                    return false;
                }
                max_extent = value.max_extent_bytes;
                control_sequence = 1;
                phase = Phase::Data;
            }
            StreamFrame::Data(value) if phase == Phase::Data => {
                let Ok(length) = u32::try_from(value.bytes.len()) else {
                    return false;
                };
                let Some(end) = value.offset.checked_add(u64::from(length)) else {
                    return false;
                };
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != data_sequence
                    || value.offset != received
                    || length == 0
                    || length > max_extent
                    || end > limit
                    || end > open.total_len
                {
                    return false;
                }
                data_sequence += 1;
                received = end;
            }
            StreamFrame::Checkpoint(value) if phase == Phase::Data => {
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != control_sequence
                    || value.durable_offset < durable
                    || value.durable_offset > received
                    || value.checkpoint_generation < generation
                    || ((value.durable_offset == durable)
                        != (value.checkpoint_generation == generation))
                    || value.absolute_receive_limit < limit
                    || value.absolute_receive_limit > open.total_len
                {
                    return false;
                }
                control_sequence += 1;
                durable = value.durable_offset;
                generation = value.checkpoint_generation;
                limit = value.absolute_receive_limit;
            }
            StreamFrame::Finish(value) if phase == Phase::Data => {
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != data_sequence
                    || value.final_offset != open.total_len
                    || received != open.total_len
                    || durable != open.total_len
                    || validate_semantic_commitment(&value.semantic_commitment).is_err()
                {
                    return false;
                }
                data_sequence += 1;
                phase = Phase::Finished;
            }
            StreamFrame::Result(value) if phase == Phase::Finished => {
                if !bound(&value.transfer_id, &value.attempt_nonce)
                    || value.sequence != control_sequence
                    || value.final_offset != open.total_len
                {
                    return false;
                }
                control_sequence += 1;
                expected_ack = Some(StreamResultAckV1 {
                    transfer_id: open.transfer_id,
                    attempt_nonce: open.attempt_nonce,
                    sequence: data_sequence,
                    result_digest: value.result_digest,
                });
                result = Some(value.clone());
                phase = Phase::Result;
            }
            StreamFrame::Result(value) if matches!(phase, Phase::Result | Phase::Terminal) => {
                if result.as_ref() != Some(value) {
                    return false;
                }
            }
            StreamFrame::ResultAck(value) if matches!(phase, Phase::Result | Phase::Terminal) => {
                if expected_ack.as_ref() != Some(value) {
                    return false;
                }
                phase = Phase::Terminal;
            }
            _ => return false,
        }
    }
    phase == Phase::Terminal
}

#[cfg(feature = "fuzzing")]
fn drive_fuzz_transcript(frames: &[StreamFrame]) -> bool {
    let Some(StreamFrame::Open(open)) = frames.first() else {
        return false;
    };
    let max_extent = frames
        .iter()
        .find_map(|frame| match frame {
            StreamFrame::Accept(value) => Some(value.max_extent_bytes),
            _ => None,
        })
        .unwrap_or(MAX_STREAM_EXTENT_BYTES as u32);
    if max_extent == 0 || max_extent as usize > MAX_STREAM_EXTENT_BYTES {
        return false;
    }
    let receive_limit = open.total_len;
    let Ok(mut receiver) = StreamReceiverState::new(
        open,
        0,
        open.checkpoint_generation,
        receive_limit,
        max_extent,
    ) else {
        return false;
    };
    let mut sender = StreamSenderState::new(open.transfer_id, open.attempt_nonce, open.total_len);
    let mut source_sequence = 0;
    let mut pending_ack = None;
    let mut terminal_code = None;
    let mut terminal = false;
    for frame in &frames[1..] {
        match frame {
            StreamFrame::Open(_) => return false,
            StreamFrame::Source(value) => {
                if value.transfer_id != open.transfer_id
                    || value.attempt_nonce != open.attempt_nonce
                    || value.sequence != source_sequence
                {
                    return false;
                }
                source_sequence += 1;
            }
            StreamFrame::Accept(value) => {
                let Ok(StreamAction::Send(StreamFrame::Accept(generated))) =
                    receiver.accept(value.checkpoint_batch_bytes)
                else {
                    return false;
                };
                if generated != *value || sender.accept(value.clone()).is_err() {
                    return false;
                }
            }
            StreamFrame::Data(value) => {
                let Ok(StreamExtentAction::Send(generated)) =
                    sender.send_extent(value.bytes.clone())
                else {
                    return false;
                };
                if generated != *value
                    || !matches!(receiver.data(value), Ok(StreamAction::Persist { .. }))
                {
                    return false;
                }
            }
            StreamFrame::Checkpoint(value) => {
                let Ok(StreamAction::Send(StreamFrame::Checkpoint(generated))) = receiver
                    .persisted(
                        value.durable_offset,
                        value.checkpoint_generation,
                        value.absolute_receive_limit,
                    )
                else {
                    return false;
                };
                if generated != *value || sender.checkpoint(value.clone()).is_err() {
                    return false;
                }
            }
            StreamFrame::Finish(value) => {
                let Ok(StreamAction::Send(StreamFrame::Finish(generated))) =
                    sender.finish(value.semantic_commitment.clone())
                else {
                    return false;
                };
                if generated != *value
                    || receiver.finish(value.clone()) != Ok(StreamAction::Promote)
                {
                    return false;
                }
            }
            StreamFrame::Result(value) => {
                let Ok(StreamAction::Send(StreamFrame::Result(generated))) =
                    receiver.promoted(value.code, value.result_digest)
                else {
                    return false;
                };
                let Ok((StreamAction::Send(StreamFrame::ResultAck(ack)), generated_terminal)) =
                    sender.result(value.clone())
                else {
                    return false;
                };
                if generated != *value || generated_terminal != StreamAction::Terminal(value.code) {
                    return false;
                }
                terminal_code = Some(value.code);
                pending_ack = Some(ack);
            }
            StreamFrame::ResultAck(value) => {
                if pending_ack.as_ref() != Some(value)
                    || receiver.result_ack(
                        value.clone(),
                        terminal_code.unwrap_or(StreamResultCode::IntegrityFailure),
                    ) != Ok(StreamAction::Terminal(
                        terminal_code.unwrap_or(StreamResultCode::IntegrityFailure),
                    ))
                {
                    return false;
                }
                terminal = true;
            }
        }
    }
    terminal
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode(input: &[u8]) {
    if input.starts_with(b"AST1") {
        if let Some((_seed_expectation, frames)) = decode_fuzz_transcript(input) {
            assert_eq!(
                drive_fuzz_transcript(&frames),
                model_fuzz_transcript(&frames)
            );
        }
        return;
    }
    if input.starts_with(COMPOSITE_DATA_MAGIC) {
        if let Ok(data) = crate::runtime::blob_stream::fuzz_open_profile5_data_extent(input)
            && inspect_native_pack_record(&data.bytes).is_ok()
        {
            if !data.bytes.is_empty() {
                assert!(inspect_native_pack_record(&data.bytes[..data.bytes.len() - 1]).is_err());
            }
            let mut trailing = data.bytes;
            trailing.push(0);
            assert!(inspect_native_pack_record(&trailing).is_err());
        }
        return;
    }
    let Ok(decoded) = StreamFrame::decode_for_context(9, 5, input) else {
        return;
    };
    let canonical = decoded
        .encode_for_context(9, 5)
        .expect("accepted stream frame must re-encode");
    assert_eq!(canonical, input);
    if !canonical.is_empty() {
        assert!(StreamFrame::decode_for_context(9, 5, &canonical[..canonical.len() - 1]).is_err());
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert!(StreamFrame::decode_for_context(9, 5, &trailing).is_err());

    if let StreamFrame::Data(data) = &decoded {
        let _ = inspect_native_pack_record(&data.bytes);
        if !data.bytes.is_empty() {
            let overflow = StreamFrame::Data(StreamDataV1 {
                offset: u64::MAX,
                ..data.clone()
            });
            assert!(overflow.encode_for_context(9, 5).is_err());
        }
    }

    // Stateful mutation is intentionally exclusive to assertion-bearing AST1
    // transcripts above. A standalone ASM record proves only codec
    // canonicality and record-local bounds; it lacks the preceding attempt
    // state required for a meaningful transition oracle.
}

#[cfg(test)]
mod stream_frame_codec {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn profile5_checkpoint_policy_and_native_record_bounds_are_independent() {
        assert_eq!(aster_mesh::BLOB_STREAM_SEGMENT_BYTES, 1_048_576);
        assert_eq!(PROFILE5_PACK_SEGMENT_RECORD_BYTES, 1_048_706);
        assert_eq!(PROFILE5_PACK_TRANSPORT_FRAME_BYTES, 1_048_710);
        assert_eq!(MAX_STREAM_EXTENT_BYTES, PROFILE5_PACK_TRANSPORT_FRAME_BYTES);
        assert!(extent(PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32).is_ok());
        assert!(extent((PROFILE5_PACK_TRANSPORT_FRAME_BYTES + 1) as u32).is_err());
        assert_eq!(MAX_STREAM_CHECKPOINT_BATCH_BYTES, 128 * 1_048_576);
        assert_eq!(
            PROFILE5_PACK_SEGMENT_RECORD_BYTES,
            aster_mesh::BLOB_STREAM_SEGMENT_BYTES
                + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES
        );
        let total = 8 * 1024 * 1024 * 1024_u64;
        let extents = total.div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64);
        let (_, control_bytes) = profile5_attempt_bounds(total).expect("attempt bounds");
        assert!(control_bytes >= extents * 192 + 8192);
    }

    #[test]
    fn maximum_native_pack_attempt_budget_cannot_undercount_frames() {
        let segments = PROFILE5_MAX_PACK_SEGMENTS;
        let wire = PROFILE5_MAX_PACK_WIRE_BYTES;
        let (data, control) =
            profile5_attempt_bounds_for_extents(wire, segments).expect("maximum attempt bound");
        assert_eq!(segments, 8192);
        assert_eq!(wire, 8_591_032_320);
        let composite =
            wire + segments as u64 * (8 + MAX_PROTECTED_STREAM_DATA_HEADER_BYTES as u64 + 192);
        assert!(data >= composite + MAX_STREAM_AUTHENTICATED_OPEN_BYTES as u64);
        assert!(control >= segments as u64 * 192);
        assert!(profile5_attempt_bounds_for_extents(u64::MAX, segments).is_err());
        assert!(profile5_attempt_bounds_for_extents(wire, segments + 1).is_err());
    }

    #[test]
    fn profile5_data_body_is_one_complete_native_pack_record() {
        let bytes = include_bytes!(
            "../../../fuzz/corpus/stream_transfer_decode/profile5-composite-valid.bin"
        );
        let (_, record) = split_composite_data_record(bytes).expect("ASD1 seed");
        let header = inspect_native_pack_record(record).expect("native pack record");
        assert_eq!(header.index(), 0);
        assert_eq!(header.offset(), 0);
        assert_eq!(header.total_len(), 17);
        assert_eq!(header.plaintext_len(), 17);
        assert_eq!(header.ciphertext_len(), 33);

        for split in 0..record.len() {
            assert!(inspect_native_pack_record(&record[..split]).is_err());
        }
        let mut trailing = record.to_vec();
        trailing.push(0);
        assert!(inspect_native_pack_record(&trailing).is_err());
    }

    #[test]
    fn authenticated_source_chunks_are_ordered_and_bounded() {
        let source = StreamSourceV1 {
            transfer_id: [0x31; 32],
            attempt_nonce: [0x32; 32],
            sequence: 1,
            offset: 7,
            total_len: 14,
            bytes: vec![0x33; 7],
        };
        let frame = StreamFrame::Source(source.clone());
        let encoded = frame.encode_for_context(9, 5).unwrap();
        assert_eq!(
            StreamFrame::decode_for_context(9, 5, &encoded).unwrap(),
            frame
        );
        assert!(encoded.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);

        let oversized = StreamFrame::Source(StreamSourceV1 {
            bytes: vec![0; PROFILE5_SOURCE_CHUNK_BYTES + 1],
            ..source
        });
        assert!(oversized.encode_for_context(9, 5).is_err());
    }

    #[test]
    fn empty_profile5_sender_settles_without_data_extents() {
        let transfer_id = [0x81; 32];
        let attempt_nonce = [0x82; 32];
        let mut sender = StreamSenderState::new(transfer_id, attempt_nonce, 0);
        assert_eq!(
            sender
                .accept(StreamAcceptV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence: 0,
                    durable_offset: 0,
                    checkpoint_generation: 0,
                    absolute_receive_limit: 0,
                    max_extent_bytes: PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
                    checkpoint_batch_bytes: MAX_STREAM_CHECKPOINT_BATCH_BYTES,
                })
                .expect("accept empty stream"),
            StreamAction::SendFinish
        );
        let StreamAction::Send(StreamFrame::Finish(finish)) =
            sender.finish(vec![0x83; 32]).expect("finish empty stream")
        else {
            panic!("empty sender did not emit FINISH");
        };
        assert_eq!(finish.final_offset, 0);
        assert_eq!(finish.sequence, 0);

        let result = StreamResultV1 {
            transfer_id,
            attempt_nonce,
            sequence: 1,
            final_offset: 0,
            code: StreamResultCode::Promoted,
            result_digest: [0x84; 32],
        };
        let (StreamAction::Send(StreamFrame::ResultAck(ack)), StreamAction::Terminal(code)) =
            sender.result(result.clone()).expect("settle empty stream")
        else {
            panic!("empty sender settlement differed");
        };
        assert_eq!(ack.result_digest, result.result_digest);
        assert_eq!(code, StreamResultCode::Promoted);
        assert_eq!(
            sender.result(result).expect("replay exact result"),
            (
                StreamAction::Send(StreamFrame::ResultAck(ack)),
                StreamAction::Terminal(StreamResultCode::Promoted),
            )
        );
    }

    fn frames() -> Vec<StreamFrame> {
        let id = [1; 32];
        let n = [2; 32];
        vec![
            StreamFrame::Open(StreamOpenV1 {
                class: StreamClass::Blob,
                direction: StreamDirection::ToSessionResponder,
                session_transcript: [3; 32],
                exchange_id: 4,
                transfer_id: id,
                source_transfer_id: [5; 32],
                publication_id: [6; 32],
                variant_id: [7; 32],
                total_len: 64,
                attempt_nonce: n,
                checkpoint_generation: 8,
                custody_digest: Some([9; 32]),
                source_len: 257,
                source_digest: [0xa5; 32],
            }),
            StreamFrame::Accept(StreamAcceptV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 0,
                durable_offset: 0,
                checkpoint_generation: 8,
                absolute_receive_limit: 64,
                max_extent_bytes: 32,
                checkpoint_batch_bytes: 64,
            }),
            StreamFrame::Data(StreamDataV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 1,
                offset: 0,
                bytes: vec![10; 32],
            }),
            StreamFrame::Checkpoint(StreamCheckpointV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 1,
                durable_offset: 32,
                checkpoint_generation: 9,
                absolute_receive_limit: 64,
            }),
            StreamFrame::Finish(StreamFinishV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 2,
                final_offset: 64,
                semantic_commitment: vec![12; 3],
            }),
            StreamFrame::Result(StreamResultV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 2,
                final_offset: 64,
                code: StreamResultCode::Promoted,
                result_digest: [11; 32],
            }),
            StreamFrame::ResultAck(StreamResultAckV1 {
                transfer_id: id,
                attempt_nonce: n,
                sequence: 3,
                result_digest: [11; 32],
            }),
        ]
    }
    #[test]
    fn all_seven_records_round_trip_and_are_context_gated() {
        let vectors = [
            (
                0xd6,
                296,
                [
                    0x65, 0x2e, 0xed, 0x21, 0x1e, 0xc7, 0x0b, 0x78, 0x24, 0xcf, 0x42, 0xfa, 0xd3,
                    0xda, 0x6c, 0x95, 0xea, 0x8c, 0x48, 0xdc, 0xd5, 0x9d, 0xaf, 0xdd, 0x3a, 0xc4,
                    0x75, 0x2a, 0x48, 0xe2, 0x08, 0x86,
                ],
            ),
            (
                0xd7,
                109,
                [
                    0x1c, 0xea, 0xe0, 0xcf, 0x45, 0xdf, 0x03, 0x15, 0x8d, 0x80, 0x3e, 0xb5, 0xd0,
                    0x63, 0xe3, 0xea, 0x50, 0x0e, 0x72, 0xbc, 0x7b, 0x82, 0xa9, 0x57, 0x4a, 0xbe,
                    0x1f, 0x6b, 0xf3, 0xd3, 0x67, 0x05,
                ],
            ),
            (
                0xd8,
                121,
                [
                    0xab, 0x42, 0xda, 0xe5, 0x60, 0xdf, 0xf7, 0xd7, 0x05, 0xa5, 0x82, 0xfc, 0x7b,
                    0xf3, 0x49, 0xc5, 0x34, 0x43, 0xa7, 0xf4, 0x49, 0x87, 0x44, 0xf3, 0xab, 0x4f,
                    0xb2, 0x4f, 0xb0, 0x73, 0x24, 0x26,
                ],
            ),
            (
                0xd9,
                101,
                [
                    0xd6, 0x7e, 0xa6, 0x8e, 0x8e, 0x64, 0x02, 0x07, 0x9e, 0x17, 0xa2, 0x2b, 0xab,
                    0x4c, 0x12, 0xe1, 0xf3, 0x1c, 0x5a, 0xaf, 0x47, 0xb7, 0xaf, 0x67, 0xe9, 0x14,
                    0x70, 0xf3, 0x0e, 0x4a, 0x67, 0x67,
                ],
            ),
            (
                0xda,
                92,
                [
                    0xd3, 0x55, 0x3c, 0x10, 0x59, 0xdf, 0xe7, 0xe0, 0x00, 0x06, 0x93, 0x96, 0x3a,
                    0x66, 0x62, 0xd1, 0x04, 0x01, 0xa8, 0x20, 0x9f, 0xde, 0xf4, 0x0c, 0x8f, 0xf3,
                    0x6b, 0xff, 0x36, 0x05, 0xf9, 0xeb,
                ],
            ),
            (
                0xdb,
                118,
                [
                    0x00, 0x3b, 0x47, 0x68, 0x2d, 0xcf, 0xdf, 0xde, 0xac, 0x05, 0x96, 0x84, 0x5d,
                    0xbe, 0x5e, 0xbd, 0x39, 0xd9, 0x5c, 0xde, 0x29, 0x07, 0xdf, 0x99, 0x7e, 0x56,
                    0x18, 0x44, 0x82, 0xc4, 0x84, 0x6e,
                ],
            ),
            (
                0xdc,
                109,
                [
                    0xb8, 0x5f, 0x98, 0xfd, 0xf2, 0x2b, 0xc7, 0xdd, 0x4c, 0x5b, 0xca, 0xa7, 0x63,
                    0x64, 0x5f, 0xd7, 0x60, 0xb6, 0xda, 0x78, 0xf7, 0x35, 0xeb, 0x2f, 0xe7, 0x63,
                    0xe6, 0xc4, 0xb7, 0xfc, 0x5a, 0x1f,
                ],
            ),
        ];
        for (f, (tag, len, digest)) in frames().into_iter().zip(vectors) {
            let b = f.encode_for_context(9, 5).unwrap();
            assert_eq!(
                (b[4], b.len(), Sha256::digest(&b).into()),
                (tag, len, digest)
            );
            assert_eq!(StreamFrame::decode_for_context(9, 5, &b), Ok(f));
            assert!(StreamFrame::decode_for_context(8, 5, &b).is_err());
            assert!(StreamFrame::decode_for_context(9, 4, &b).is_err());
        }
        for raw in 1..=6 {
            assert!(StreamResultCode::decode(raw).is_ok());
        }
        assert!(StreamResultCode::decode(0).is_err());
        assert!(StreamResultCode::decode(7).is_err());
    }
    #[test]
    fn data_header_is_bounded_before_body_allocation() {
        assert_eq!(
            MAX_STREAM_DATA_FRAME_BYTES,
            STREAM_DATA_FIXED_BYTES + MAX_STREAM_EXTENT_BYTES
        );
        let b = frames()[2].encode_for_context(9, 5).unwrap();
        let h =
            StreamDataHeaderV1::decode_for_context(9, 5, &b[..STREAM_DATA_FIXED_BYTES]).unwrap();
        assert_eq!(h.extent_len, 32);
        assert!(
            h.decode_body(&b[STREAM_DATA_FIXED_BYTES..b.len() - 1])
                .is_err()
        );
        let mut h = b[..STREAM_DATA_FIXED_BYTES].to_vec();
        h[85..].copy_from_slice(&(MAX_STREAM_EXTENT_BYTES as u32 + 1).to_be_bytes());
        assert!(StreamDataHeaderV1::decode_for_context(9, 5, &h).is_err());
    }
    #[test]
    fn data_frame_splits_into_a_canonical_header_and_exact_body() {
        let data = match frames().remove(2) {
            StreamFrame::Data(data) => data,
            _ => unreachable!(),
        };
        let (header, body) = data.clone().into_header_and_body().unwrap();
        let encoded_header = header.encode_for_context(9, 5).unwrap();

        assert_eq!(encoded_header.len(), STREAM_DATA_FIXED_BYTES);
        assert_eq!(body, data.bytes);
        assert_eq!(
            StreamDataHeaderV1::decode_for_context(9, 5, &encoded_header)
                .unwrap()
                .decode_body(&body)
                .unwrap(),
            data
        );
    }
    #[test]
    fn composite_data_record_keeps_the_segment_body_outside_the_protected_header() {
        let protected_header = vec![0xa1; 137];
        let body = vec![0xb2; 32];
        let encoded = encode_composite_data_record(&protected_header, body.clone()).unwrap();

        assert_eq!(&encoded[..4], b"ASD1");
        assert_eq!(encoded.len(), 4 + 4 + protected_header.len() + body.len());
        let (decoded_header, decoded_body) = split_composite_data_record(&encoded).unwrap();
        assert_eq!(decoded_header, protected_header);
        assert_eq!(decoded_body, body);
    }
    #[test]
    fn composite_data_record_rejects_unbounded_or_truncated_protected_headers() {
        let mut truncated = b"ASD1".to_vec();
        truncated.extend_from_slice(&137_u32.to_be_bytes());
        truncated.extend_from_slice(&[0xa1; 16]);
        assert!(split_composite_data_record(&truncated).is_err());

        let mut unbounded = b"ASD1".to_vec();
        unbounded.extend_from_slice(&2049_u32.to_be_bytes());
        unbounded.extend_from_slice(&[0xa1; 16]);
        assert!(split_composite_data_record(&unbounded).is_err());

        assert!(split_composite_data_record(b"full-mission-record").is_err());
    }
    #[test]
    fn composite_data_record_matches_the_independent_wire_corpus() {
        for line in
            include_str!("../../../conformance/vectors/profile5-composite-data-record-v1.tsv")
                .lines()
                .filter(|line| !line.starts_with('#'))
        {
            let mut fields = line.split('\t');
            let disposition = fields.next().unwrap();
            let name = fields.next().unwrap();
            let hex = fields.next().unwrap();
            assert!(fields.next().is_none(), "unexpected vector field: {name}");
            let wire = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                split_composite_data_record(&wire).is_ok(),
                disposition == "ACCEPT",
                "vector disposition differs: {name}"
            );
        }
    }

    #[test]
    fn production_composite_seeds_are_structurally_bounded() {
        assert_eq!(MAX_COMPOSITE_STREAM_DATA_BYTES, 1_050_766);
        for bytes in [
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-composite-valid.bin"
            )
            .as_slice(),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-composite-maximum.bin"
            )
            .as_slice(),
        ] {
            assert!(bytes.len() <= MAX_COMPOSITE_STREAM_DATA_BYTES);
            let (header, body) = split_composite_data_record(bytes).expect("ASD1 seed");
            assert!(header.starts_with(b"ASTRFR01"));
            let segment = inspect_native_pack_record(body).expect("native ASTRBS02 pack record");
            assert_eq!(segment.index(), 0);
            assert_eq!(segment.offset(), 0);
        }
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn production_composite_valid_seed_opens_and_segment_authenticates() {
        let bytes = include_bytes!(
            "../../../fuzz/corpus/stream_transfer_decode/profile5-composite-valid.bin"
        );
        let data = crate::runtime::blob_stream::fuzz_open_profile5_data_extent(bytes)
            .expect("production MissionBlobRecordCodec opens seed");
        let encoded = data
            .bytes
            .get(PROFILE5_PACK_RECORD_PREFIX_BYTES..)
            .expect("length-prefixed segment");
        let opener = aster_mesh::BlobStreamSegmentOpener::from_test_key(
            [0x10; 32], [0x20; 32], 7, [0x30; 32], [0x40; 12],
        );
        let (header, plaintext, _) = opener
            .open_encoded(encoded)
            .expect("authenticated ASTRBS02 seed");
        assert_eq!(header.index(), 0);
        assert_eq!(plaintext.as_slice(), &[0x5a; 17]);

        let mut malformed = encoded.to_vec();
        *malformed.last_mut().expect("segment tag") ^= 1;
        assert!(opener.open_encoded(&malformed).is_err());
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn transcript_seed_expectations_match_model_and_production_states() {
        let seeds: [&[u8]; 6] = [
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-empty.bin"
            ),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-nonempty.bin"
            ),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-reject-binding.bin"
            ),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-reject-rollback.bin"
            ),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-reject-replay.bin"
            ),
            include_bytes!(
                "../../../fuzz/corpus/stream_transfer_decode/profile5-transcript-reject-terminal-change.bin"
            ),
        ];
        for (seed_index, seed) in seeds.into_iter().enumerate() {
            let (expected, frames) = decode_fuzz_transcript(seed).expect("decode transcript seed");
            assert_eq!(
                model_fuzz_transcript(&frames),
                expected,
                "seed {seed_index}"
            );
            assert_eq!(
                drive_fuzz_transcript(&frames),
                expected,
                "seed {seed_index}"
            );
        }
    }
    #[test]
    fn profile5_stream_records_match_the_independent_wire_corpus() {
        let mut accepted_tags = std::collections::BTreeSet::new();
        for line in include_str!("../../../conformance/vectors/profile5-stream-records-v1.tsv")
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 3, "unexpected profile-5 vector row");
            let wire = fields[2]
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            let decoded = StreamFrame::decode_for_context(9, 5, &wire);
            let valid = decoded.as_ref().is_ok_and(|frame| match frame {
                StreamFrame::Data(data) => inspect_native_pack_record(&data.bytes).is_ok(),
                _ => true,
            });
            assert_eq!(
                valid,
                fields[0] == "ACCEPT",
                "vector disposition differs: {}",
                fields[1]
            );
            if valid && let Ok(frame) = decoded {
                assert_eq!(frame.encode_for_context(9, 5).unwrap(), wire);
                accepted_tags.insert(wire[4]);
            }
        }
        assert_eq!(accepted_tags, STREAM_TAGS.collect());
    }
    #[test]
    fn codec_rejects_truncation_trailing_empty_and_overflow() {
        for f in frames() {
            let mut b = f.encode_for_context(9, 5).unwrap();
            assert!(StreamFrame::decode_for_context(9, 5, &b[..b.len() - 1]).is_err());
            b.push(0);
            assert!(StreamFrame::decode_for_context(9, 5, &b).is_err());
        }
        let id = [1; 32];
        let n = [2; 32];
        for (offset, bytes) in [(0, vec![]), (u64::MAX, vec![1])] {
            assert!(
                StreamFrame::Data(StreamDataV1 {
                    transfer_id: id,
                    attempt_nonce: n,
                    sequence: 0,
                    offset,
                    bytes
                })
                .encode_for_context(9, 5)
                .is_err()
            );
        }
        let mut open = frames()[0].encode_for_context(9, 5).unwrap();
        let custody_presence = open.len() - (1 + 32 + 4 + 32);
        open[custody_presence] = 2;
        assert!(StreamFrame::decode_for_context(9, 5, &open).is_err());
        let mut open = match frames().remove(0) {
            StreamFrame::Open(open) => open,
            _ => unreachable!(),
        };
        open.source_len = 0;
        assert!(
            StreamFrame::Open(open.clone())
                .encode_for_context(9, 5)
                .is_err()
        );
        let mut data = match frames().remove(2) {
            StreamFrame::Data(data) => data,
            _ => unreachable!(),
        };
        data.attempt_nonce = [0; 32];
        assert!(StreamFrame::Data(data).encode_for_context(9, 5).is_err());
    }

    #[test]
    fn authenticated_source_enforces_the_production_bound_with_a_small_fixture() {
        assert_eq!(MAX_STREAM_AUTHENTICATED_OPEN_BYTES, 401_902);
        assert!(validate_authenticated_open_with_max(&[], 4).is_err());
        assert!(validate_authenticated_open_with_max(&[0; 4], 4).is_ok());
        assert!(validate_authenticated_open_with_max(&[0; 5], 4).is_err());
    }

    #[test]
    fn selected_frame_context_rejects_stream_tags_outside_v9_profile_five() {
        let frame = crate::frame::Frame::Stream(frames().remove(2));
        let encoded = frame.encode_for_semantic_profile(9, 5).unwrap();
        assert_eq!(
            crate::frame::Frame::decode_for_semantic_profile(&encoded, 9, 5).unwrap(),
            frame
        );
        assert!(frame.encode_for_semantic_profile(8, 5).is_err());
        assert!(crate::frame::Frame::decode_for_semantic_profile(&encoded, 9, 4).is_err());
    }

    #[test]
    #[ignore = "explicit 1 GiB codec performance measurement"]
    fn stream_codec_ceiling_processes_one_gib_in_bounded_extents() {
        const TOTAL: u64 = 1 << 30;
        let payload = vec![0xa5; MAX_STREAM_EXTENT_BYTES];
        let started = std::time::Instant::now();
        let mut offset = 0u64;
        let mut sequence = 0u64;
        while offset < TOTAL {
            let frame = StreamFrame::Data(StreamDataV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence,
                offset,
                bytes: payload.clone(),
            });
            let encoded = frame.encode_for_context(9, 5).unwrap();
            let decoded = StreamFrame::decode_for_context(9, 5, &encoded).unwrap();
            std::hint::black_box(decoded);
            offset += MAX_STREAM_EXTENT_BYTES as u64;
            sequence += 1;
        }
        let elapsed = started.elapsed();
        let mib_per_second = TOTAL as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!(
            "stream_codec_ceiling bytes={TOTAL} extents={sequence} elapsed_ns={} mib_per_second={mib_per_second:.3}",
            elapsed.as_nanos()
        );
    }
}

#[cfg(test)]
mod stream_state {
    use super::*;

    fn open(total_len: u64, nonce: [u8; 32]) -> StreamOpenV1 {
        StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [3; 32],
            exchange_id: 4,
            transfer_id: [1; 32],
            source_transfer_id: [5; 32],
            publication_id: [6; 32],
            variant_id: [7; 32],
            total_len,
            attempt_nonce: nonce,
            checkpoint_generation: 1,
            custody_digest: None,
            source_len: 1,
            source_digest: [7; 32],
        }
    }

    #[test]
    fn sender_pipelines_against_absolute_credit_and_accepts_cumulative_checkpoint() {
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 64);
        assert_eq!(
            sender
                .accept(StreamAcceptV1 {
                    transfer_id: [1; 32],
                    attempt_nonce: [2; 32],
                    sequence: 0,
                    durable_offset: 0,
                    checkpoint_generation: 1,
                    absolute_receive_limit: 32,
                    max_extent_bytes: 16,
                    checkpoint_batch_bytes: 32,
                })
                .unwrap(),
            StreamAction::SendData
        );
        assert!(matches!(
            sender.send_extent(vec![3; 16]).unwrap(),
            StreamExtentAction::Send(_)
        ));
        assert!(matches!(
            sender.send_extent(vec![4; 16]).unwrap(),
            StreamExtentAction::Send(_)
        ));
        let rejected = vec![5];
        let allocation = rejected.as_ptr();
        let StreamExtentAction::Retry { reason, bytes } = sender.send_extent(rejected).unwrap()
        else {
            panic!("extent exceeded credit")
        };
        assert_eq!(reason, StreamRetry::CreditBlocked);
        assert_eq!(bytes.as_ptr(), allocation, "credit retry copied the extent");
        sender
            .checkpoint(StreamCheckpointV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 1,
                durable_offset: 16,
                checkpoint_generation: 2,
                absolute_receive_limit: 48,
            })
            .unwrap();
        sender
            .checkpoint(StreamCheckpointV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 2,
                durable_offset: 16,
                checkpoint_generation: 2,
                absolute_receive_limit: 48,
            })
            .unwrap();
        assert!(matches!(
            sender.send_extent(vec![5; 16]).unwrap(),
            StreamExtentAction::Send(_)
        ));
    }

    #[test]
    fn fully_checkpointed_retry_sends_finish_without_waiting_for_data() {
        let transfer_id = [0x41; 32];
        let attempt_nonce = [0x42; 32];
        let total = 64;
        let mut sender = StreamSenderState::new(transfer_id, attempt_nonce, total);

        assert_eq!(
            sender.accept(StreamAcceptV1 {
                transfer_id,
                attempt_nonce,
                sequence: 0,
                durable_offset: total,
                checkpoint_generation: 7,
                absolute_receive_limit: total,
                max_extent_bytes: 16,
                checkpoint_batch_bytes: 32,
            }),
            Ok(StreamAction::SendFinish)
        );

        let StreamAction::Send(StreamFrame::Finish(finish)) =
            sender.finish(vec![0x43; 32]).expect("terminal FINISH")
        else {
            panic!("fully checkpointed sender did not emit FINISH");
        };
        assert_eq!(finish.transfer_id, transfer_id);
        assert_eq!(finish.attempt_nonce, attempt_nonce);
        assert_eq!(finish.sequence, 0);
        assert_eq!(finish.final_offset, total);

        let mut open = open(total, attempt_nonce);
        open.transfer_id = transfer_id;
        let mut receiver =
            StreamReceiverState::new(&open, total, 7, total, 16).expect("terminal receiver");
        assert!(matches!(
            receiver.accept(32).expect("terminal ACCEPT"),
            StreamAction::Send(StreamFrame::Accept(_))
        ));
        assert_eq!(
            receiver.finish(finish).expect("validate terminal FINISH"),
            StreamAction::Promote
        );
        let result = receiver
            .promoted(StreamResultCode::AlreadyPresent, [0x44; 32])
            .expect("terminal RESULT");
        assert_eq!(
            receiver
                .promoted(StreamResultCode::AlreadyPresent, [0x44; 32])
                .expect("idempotent terminal RESULT"),
            result
        );
        let StreamAction::Send(StreamFrame::Result(result)) = result else {
            panic!("receiver did not emit RESULT");
        };
        let first = sender.result(result.clone()).expect("settle sender");
        assert_eq!(
            sender.result(result).expect("idempotent sender settlement"),
            first
        );
        let (StreamAction::Send(StreamFrame::ResultAck(ack)), terminal) = first else {
            panic!("sender did not emit RESULT ACK and terminal action");
        };
        assert_eq!(
            terminal,
            StreamAction::Terminal(StreamResultCode::AlreadyPresent)
        );
        assert_eq!(
            receiver
                .result_ack(ack.clone(), StreamResultCode::AlreadyPresent)
                .expect("terminal ACK"),
            StreamAction::Terminal(StreamResultCode::AlreadyPresent)
        );
        assert_eq!(
            receiver
                .result_ack(ack, StreamResultCode::AlreadyPresent)
                .expect("idempotent terminal ACK"),
            StreamAction::Terminal(StreamResultCode::AlreadyPresent)
        );
    }

    #[test]
    fn receiver_separates_received_from_durable_and_rejects_gap_credit_and_replay() {
        let mut receiver = StreamReceiverState::new(&open(64, [2; 32]), 0, 1, 32, 16).unwrap();
        assert!(matches!(
            receiver.accept(32).unwrap(),
            StreamAction::Send(_)
        ));
        let data = |sequence, offset, nonce| StreamDataV1 {
            transfer_id: [1; 32],
            attempt_nonce: nonce,
            sequence,
            offset,
            bytes: vec![9; 16],
        };
        assert_eq!(
            receiver.data(&data(0, 0, [2; 32])),
            Ok(StreamAction::Persist { through: 16 })
        );
        assert!(receiver.data(&data(1, 17, [2; 32])).is_err(), "gap");
        assert!(
            receiver.data(&data(1, 16, [8; 32])).is_err(),
            "attempt replay"
        );
        assert_eq!(
            receiver.persisted(16, 2, 32).unwrap(),
            StreamAction::Send(StreamFrame::Checkpoint(StreamCheckpointV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 1,
                durable_offset: 16,
                checkpoint_generation: 2,
                absolute_receive_limit: 32,
            }))
        );
        assert_eq!(
            receiver.data(&data(1, 16, [2; 32])),
            Ok(StreamAction::Persist { through: 32 })
        );
        assert!(
            receiver.data(&data(2, 32, [2; 32])).is_err(),
            "credit violation"
        );
    }

    #[test]
    fn terminal_result_and_ack_are_idempotent_and_digest_bound() {
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 0);
        sender
            .accept(StreamAcceptV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                durable_offset: 0,
                checkpoint_generation: 1,
                absolute_receive_limit: 0,
                max_extent_bytes: 16,
                checkpoint_batch_bytes: 16,
            })
            .unwrap();
        assert!(matches!(
            sender.finish(vec![9]).unwrap(),
            StreamAction::Send(_)
        ));
        let result = StreamResultV1 {
            transfer_id: [1; 32],
            attempt_nonce: [2; 32],
            sequence: 1,
            final_offset: 0,
            code: StreamResultCode::AlreadyPresent,
            result_digest: [7; 32],
        };
        let first = sender.result(result.clone()).unwrap();
        assert_eq!(sender.result(result), Ok(first));
    }

    #[test]
    fn finish_requires_one_bounded_semantic_commitment() {
        assert_eq!(MAX_STREAM_SEMANTIC_COMMITMENT_BYTES, 64 * 1024);
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 0);
        sender
            .accept(StreamAcceptV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                durable_offset: 0,
                checkpoint_generation: 1,
                absolute_receive_limit: 0,
                max_extent_bytes: 16,
                checkpoint_batch_bytes: 16,
            })
            .unwrap();
        assert!(sender.finish(Vec::new()).is_err());
        assert!(validate_semantic_commitment_with_max(&[0; 4], 4).is_ok());
        assert!(validate_semantic_commitment_with_max(&[0; 5], 4).is_err());
    }

    #[test]
    fn sender_rejects_out_of_bounds_accept_configuration() {
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 64);
        assert!(
            sender
                .accept(StreamAcceptV1 {
                    transfer_id: [1; 32],
                    attempt_nonce: [2; 32],
                    sequence: 0,
                    durable_offset: 0,
                    checkpoint_generation: 1,
                    absolute_receive_limit: 32,
                    max_extent_bytes: 16,
                    checkpoint_batch_bytes: MAX_STREAM_CHECKPOINT_BATCH_BYTES + 1,
                })
                .is_err()
        );
    }

    #[test]
    fn durable_progress_and_checkpoint_generation_advance_together() {
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 32);
        sender
            .accept(StreamAcceptV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                durable_offset: 0,
                checkpoint_generation: 1,
                absolute_receive_limit: 32,
                max_extent_bytes: 16,
                checkpoint_batch_bytes: 16,
            })
            .unwrap();
        sender.send_extent(vec![3; 16]).unwrap();
        assert!(
            sender
                .checkpoint(StreamCheckpointV1 {
                    transfer_id: [1; 32],
                    attempt_nonce: [2; 32],
                    sequence: 1,
                    durable_offset: 16,
                    checkpoint_generation: 1,
                    absolute_receive_limit: 32,
                })
                .is_err()
        );

        let mut receiver = StreamReceiverState::new(&open(32, [2; 32]), 0, 1, 32, 16).unwrap();
        receiver
            .data(&StreamDataV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                offset: 0,
                bytes: vec![3; 16],
            })
            .unwrap();
        assert!(receiver.persisted(16, 1, 32).is_err());
    }

    #[test]
    fn reopen_requires_a_fresh_attempt_nonce() {
        assert!(StreamReceiverState::reopen(&[2; 32], &open(64, [2; 32]), 0, 1, 32, 16).is_err());
        assert!(StreamReceiverState::reopen(&[2; 32], &open(64, [3; 32]), 0, 1, 32, 16).is_ok());
    }

    #[test]
    fn completion_promotes_once_and_replays_bound_result_and_ack() {
        let mut receiver = StreamReceiverState::new(&open(0, [2; 32]), 0, 1, 0, 16).unwrap();
        receiver.accept(16).unwrap();
        let finish = StreamFinishV1 {
            transfer_id: [1; 32],
            attempt_nonce: [2; 32],
            sequence: 0,
            final_offset: 0,
            semantic_commitment: vec![9],
        };
        assert_eq!(receiver.finish(finish.clone()), Ok(StreamAction::Promote));
        assert_eq!(
            receiver.finish(finish.clone()),
            Ok(StreamAction::Retry(StreamRetry::SettlementPending))
        );
        let result = receiver
            .promoted(StreamResultCode::Promoted, [8; 32])
            .unwrap();
        assert_eq!(receiver.finish(finish), Ok(result.clone()));
        let StreamAction::Send(StreamFrame::Result(result_frame)) = result else {
            panic!("result")
        };
        let ack = StreamResultAckV1 {
            transfer_id: [1; 32],
            attempt_nonce: [2; 32],
            sequence: 1,
            result_digest: result_frame.result_digest,
        };
        assert!(
            receiver
                .result_ack(ack.clone(), StreamResultCode::RejectedPolicy)
                .is_err()
        );
        assert_eq!(
            receiver.result_ack(ack.clone(), StreamResultCode::Promoted),
            Ok(StreamAction::Terminal(StreamResultCode::Promoted))
        );
        assert_eq!(
            receiver.result_ack(ack, StreamResultCode::Promoted),
            Ok(StreamAction::Terminal(StreamResultCode::Promoted))
        );
    }

    #[test]
    fn transport_loss_is_retryable() {
        let mut sender = StreamSenderState::new([1; 32], [2; 32], 64);
        sender
            .accept(StreamAcceptV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                durable_offset: 0,
                checkpoint_generation: 1,
                absolute_receive_limit: 0,
                max_extent_bytes: 16,
                checkpoint_batch_bytes: 16,
            })
            .unwrap();
        assert!(matches!(
            sender.send_extent(vec![1]),
            Ok(StreamExtentAction::Retry {
                reason: StreamRetry::CreditBlocked,
                ..
            })
        ));
        assert_eq!(
            sender.transport_lost(),
            StreamAction::Retry(StreamRetry::TransportLost)
        );
    }

    #[test]
    fn duplicate_data_below_durable_checkpoint_is_discarded_after_binding_checks() {
        let mut receiver = StreamReceiverState::new(&open(64, [2; 32]), 16, 2, 32, 16).unwrap();
        assert_eq!(
            receiver.data(&StreamDataV1 {
                transfer_id: [1; 32],
                attempt_nonce: [2; 32],
                sequence: 0,
                offset: 0,
                bytes: vec![9; 16],
            }),
            Ok(StreamAction::Retry(StreamRetry::DuplicateBelowCheckpoint))
        );
    }
}
