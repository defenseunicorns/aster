//! Engineering-only transport validation for semantic-v9 Profile-5 records.
//!
//! The driver emits the exact length-prefixed, independently authenticated
//! `ASTRBS02` records used by the production pack transport. It exercises the
//! production stream state machine, credit/checkpoint protocol, settlement,
//! and selected transport. It intentionally does not replace a public Blob API
//! end-to-end test, which also measures publication and lifecycle work.

use crate::{
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, PROFILE5_PACK_TRANSPORT_FRAME_BYTES, StreamAction,
        StreamClass, StreamDirection, StreamExtentAction, StreamFrame, StreamOpenV1,
        StreamReceiverState, StreamResultCode, StreamSenderState, blob_pack_wire_len,
        profile5_attempt_bounds_for_extents, profile5_attempt_hard_timeout, profile5_receive_limit,
    },
    stream_transport::{AttemptOpenRequest, IrohQuicV1Adapter, StreamTransportAdapter},
};
use aster_iroh::Connection;
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobStreamPlainPartition, BlobStreamSegmentOpener,
    BlobStreamSegmentSealer, EncryptedBlobStreamSegment,
};
use sha2::{Digest, Sha256};
use std::time::Instant as StdInstant;
use tokio::time::Instant;

pub use crate::runtime::blob_stream::BlobNetworkReport;

const VALIDATION_AUTHENTICATED_OPEN: &[u8] = b"aster/device-validation/profile5-open/v1";

pub fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, String> {
    crate::runtime::blob_stream::expected_pack_wire_len(plaintext_len)
        .map_err(|error| error.to_string())
}

pub async fn send_completed_pack(
    connection: Connection,
    open: &aster_mesh::BlobStreamOpen,
    root: &std::path::Path,
    roots: ([u8; 32], [u8; 32]),
) -> Result<BlobNetworkReport, String> {
    crate::runtime::blob_stream::send_completed_pack(
        connection,
        open,
        VALIDATION_AUTHENTICATED_OPEN.to_vec(),
        root,
        roots,
        open.digest().to_vec(),
    )
    .await
    .map_err(|error| error.to_string())
}

pub async fn receive_completed_pack(
    connection: Connection,
    open: &aster_mesh::BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: &std::path::Path,
    wire_len: u64,
    limits: crate::stream_pipeline::PipelineLimits,
) -> Result<BlobNetworkReport, String> {
    crate::runtime::blob_stream::receive_completed_pack(
        connection, open, opener, root, wire_len, limits,
    )
    .await
    .map_err(|error| error.to_string())
}

const VALIDATION_STREAM_ID: [u8; 32] = [0x31; 32];
const VALIDATION_OPEN_DIGEST: [u8; 32] = [0x32; 32];
const VALIDATION_KEY: [u8; 32] = [0x33; 32];
const VALIDATION_NONCE: [u8; 12] = [0x34; 12];

#[derive(Clone, Debug, PartialEq)]
pub struct StreamValidationReport {
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub mib_per_second: f64,
    pub checkpoints: u64,
    pub digest: [u8; 32],
}

fn payload(offset: u64, len: usize) -> Vec<u8> {
    let segment = offset / BLOB_STREAM_SEGMENT_BYTES as u64;
    vec![(segment as u8).wrapping_mul(31).wrapping_add(0x5a); len]
}

fn validation_wire_len(payload_len: u64) -> Result<u64, String> {
    blob_pack_wire_len(payload_len).map_err(|error| error.to_string())
}

fn validation_segment_count(payload_len: u64) -> Result<usize, String> {
    usize::try_from(payload_len.div_ceil(BLOB_STREAM_SEGMENT_BYTES as u64))
        .map_err(|_| "validation segment count overflow".into())
}

fn rate(bytes: u64, elapsed_ns: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / (elapsed_ns as f64 / 1_000_000_000.0)
}

fn encoded(frame: StreamFrame) -> Result<Vec<u8>, String> {
    frame
        .encode_for_context(9, 5)
        .map_err(|error| error.to_string())
}

fn decoded(bytes: &[u8]) -> Result<StreamFrame, String> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| error.to_string())
}

fn validation_sealer() -> BlobStreamSegmentSealer {
    BlobStreamSegmentSealer::from_test_key(
        VALIDATION_STREAM_ID,
        VALIDATION_OPEN_DIGEST,
        1,
        VALIDATION_KEY,
        VALIDATION_NONCE,
    )
}

fn validation_opener() -> BlobStreamSegmentOpener {
    BlobStreamSegmentOpener::from_test_key(
        VALIDATION_STREAM_ID,
        VALIDATION_OPEN_DIGEST,
        1,
        VALIDATION_KEY,
        VALIDATION_NONCE,
    )
}

fn encode_validation_record(
    sealer: &BlobStreamSegmentSealer,
    total_len: u64,
    index: u64,
    offset: u64,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let partition = BlobStreamPlainPartition::new(
        VALIDATION_STREAM_ID,
        VALIDATION_OPEN_DIGEST,
        1,
        index,
        offset,
        total_len,
        plaintext,
    )
    .map_err(|error| error.to_string())?;
    let (segment, _) = sealer.seal(partition).map_err(|error| error.to_string())?;
    let segment = segment.encode();
    let len = u32::try_from(segment.len()).map_err(|_| "validation record too large")?;
    let mut record = Vec::with_capacity(4 + segment.len());
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(&segment);
    if record.len() > PROFILE5_PACK_TRANSPORT_FRAME_BYTES {
        return Err("validation record exceeds native Profile-5 frame".into());
    }
    Ok(record)
}

fn decode_validation_record(
    opener: &BlobStreamSegmentOpener,
    bytes: &[u8],
) -> Result<
    (
        aster_mesh::EncryptedBlobStreamSegmentHeader,
        zeroize::Zeroizing<Vec<u8>>,
    ),
    String,
> {
    let (prefix, encoded) = bytes
        .split_at_checked(4)
        .ok_or("native Profile-5 record lacks length prefix")?;
    let declared = u32::from_be_bytes(prefix.try_into().expect("four-byte prefix")) as usize;
    if declared == 0
        || declared != encoded.len()
        || bytes.len() > PROFILE5_PACK_TRANSPORT_FRAME_BYTES
    {
        return Err("native Profile-5 record length is invalid".into());
    }
    let segment = EncryptedBlobStreamSegment::decode(encoded).map_err(|error| error.to_string())?;
    let header = segment.header();
    let (plaintext, _) = opener.open(&segment).map_err(|error| error.to_string())?;
    Ok((header, plaintext))
}

pub async fn send(connection: Connection, bytes: u64) -> Result<StreamValidationReport, String> {
    if bytes == 0 {
        return Err("validation payload must be nonempty".into());
    }
    let wire_len = validation_wire_len(bytes)?;
    let segment_count = validation_segment_count(bytes)?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds_for_extents(wire_len, segment_count)
            .map_err(|error| error.to_string())?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(wire_len),
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| format!("open attempt: {error:?}"))?;
    let transfer_id = [0x41; 32];
    let attempt_nonce = [0x42; 32];
    let open = StreamOpenV1 {
        class: StreamClass::Blob,
        direction: StreamDirection::ToSessionResponder,
        session_transcript: [0x21; 32],
        exchange_id: 1,
        transfer_id,
        source_transfer_id: [0x43; 32],
        publication_id: VALIDATION_STREAM_ID,
        variant_id: [0x44; 32],
        total_len: wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
        source_len: 1,
        source_digest: VALIDATION_OPEN_DIGEST,
    };
    attempt
        .send_data(&encoded(StreamFrame::Open(open))?)
        .await
        .map_err(|error| format!("send open: {error:?}"))?;
    let accept = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive accept: {error:?}"))?
        .ok_or("control stream closed before accept")?;
    let StreamFrame::Accept(accept) = decoded(&accept)? else {
        return Err("first control frame was not accept".into());
    };
    let mut state = StreamSenderState::new(transfer_id, attempt_nonce, wire_len);
    state.accept(accept).map_err(|error| error.to_string())?;
    let started = StdInstant::now();
    let sealer = validation_sealer();
    let mut plaintext_offset = 0_u64;
    let mut segment_index = 0_u64;
    let mut checkpoints = 0_u64;
    let mut hasher = Sha256::new();
    let mut pending: Option<(Vec<u8>, usize)> = None;
    while plaintext_offset < bytes {
        let plaintext_len =
            usize::try_from((bytes - plaintext_offset).min(BLOB_STREAM_SEGMENT_BYTES as u64))
                .expect("bounded native segment");
        let (record, accepted_plaintext) = match pending.take() {
            Some(pending) => pending,
            None => {
                let plaintext = payload(plaintext_offset, plaintext_len);
                hasher.update(&plaintext);
                (
                    encode_validation_record(
                        &sealer,
                        bytes,
                        segment_index,
                        plaintext_offset,
                        plaintext,
                    )?,
                    plaintext_len,
                )
            }
        };
        match state
            .send_extent(record)
            .map_err(|error| error.to_string())?
        {
            StreamExtentAction::Send(data) => {
                attempt
                    .send_data(&encoded(StreamFrame::Data(data))?)
                    .await
                    .map_err(|error| format!("send data: {error:?}"))?;
                plaintext_offset += accepted_plaintext as u64;
                segment_index += 1;
            }
            StreamExtentAction::Retry {
                reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                bytes,
            } => {
                pending = Some((bytes, accepted_plaintext));
                let checkpoint = attempt
                    .receive_control()
                    .await
                    .map_err(|error| format!("receive checkpoint: {error:?}"))?
                    .ok_or("control stream closed before checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = decoded(&checkpoint)? else {
                    return Err("credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| error.to_string())?;
                checkpoints += 1;
            }
            StreamExtentAction::Retry { .. } => {
                return Err("sender produced an invalid extent retry".into());
            }
        }
    }
    let final_checkpoint = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive final checkpoint: {error:?}"))?
        .ok_or("control stream closed before final checkpoint")?;
    let StreamFrame::Checkpoint(final_checkpoint) = decoded(&final_checkpoint)? else {
        return Err("final data control frame was not checkpoint".into());
    };
    state
        .checkpoint(final_checkpoint)
        .map_err(|error| error.to_string())?;
    checkpoints += 1;
    let digest: [u8; 32] = hasher.finalize().into();
    let StreamAction::Send(finish) = state
        .finish(digest.to_vec())
        .map_err(|error| error.to_string())?
    else {
        return Err("sender did not produce finish".into());
    };
    attempt
        .send_data(&encoded(finish)?)
        .await
        .map_err(|error| format!("send finish: {error:?}"))?;
    let result = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive result: {error:?}"))?
        .ok_or("control stream closed before result")?;
    let StreamFrame::Result(result) = decoded(&result)? else {
        return Err("terminal control frame was not result".into());
    };
    if result.code != StreamResultCode::Promoted || result.result_digest != digest {
        return Err("receiver result did not verify the complete payload".into());
    }
    let (StreamAction::Send(ack), StreamAction::Terminal(StreamResultCode::Promoted)) =
        state.result(result).map_err(|error| error.to_string())?
    else {
        return Err("sender settlement action differed".into());
    };
    attempt
        .send_data(&encoded(ack)?)
        .await
        .map_err(|error| format!("send result ack: {error:?}"))?;
    attempt
        .finish_data()
        .await
        .map_err(|error| format!("finish data stream: {error:?}"))?;
    if attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive control EOF: {error:?}"))?
        .is_some()
    {
        return Err("control stream contained data after terminal result".into());
    }
    let elapsed_ns = started.elapsed().as_nanos();
    Ok(StreamValidationReport {
        bytes,
        elapsed_ns,
        mib_per_second: rate(bytes, elapsed_ns),
        checkpoints,
        digest,
    })
}

pub async fn receive(
    connection: Connection,
    expected_bytes: u64,
) -> Result<StreamValidationReport, String> {
    receive_with_batch(
        connection,
        expected_bytes,
        MAX_STREAM_CHECKPOINT_BATCH_BYTES,
    )
    .await
}

async fn receive_with_batch(
    connection: Connection,
    expected_bytes: u64,
    checkpoint_batch: u32,
) -> Result<StreamValidationReport, String> {
    if expected_bytes == 0 {
        return Err("validation payload must be nonempty".into());
    }
    let expected_wire = validation_wire_len(expected_bytes)?;
    let segment_count = validation_segment_count(expected_bytes)?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds_for_extents(expected_wire, segment_count)
            .map_err(|error| error.to_string())?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(expected_wire),
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| format!("accept attempt: {error:?}"))?;
    let open = attempt
        .receive_data()
        .await
        .map_err(|error| format!("receive open: {error:?}"))?
        .ok_or("data stream closed before open")?;
    let StreamFrame::Open(open) = decoded(&open)? else {
        return Err("first data frame was not open".into());
    };
    if open.class != StreamClass::Blob
        || open.total_len != expected_wire
        || open.publication_id != VALIDATION_STREAM_ID
        || open.source_digest != VALIDATION_OPEN_DIGEST
    {
        return Err("stream open differs from expected native Blob transfer".into());
    }
    let batch = u64::from(checkpoint_batch);
    let mut state = StreamReceiverState::new(
        &open,
        0,
        0,
        profile5_receive_limit(expected_wire, 0, checkpoint_batch),
        PROFILE5_PACK_TRANSPORT_FRAME_BYTES as u32,
    )
    .map_err(|error| error.to_string())?;
    let StreamAction::Send(accept) = state
        .accept(checkpoint_batch)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver did not produce accept".into());
    };
    attempt
        .send_control(&encoded(accept)?)
        .await
        .map_err(|error| format!("send accept: {error:?}"))?;
    let started = StdInstant::now();
    let opener = validation_opener();
    let mut hasher = Sha256::new();
    let mut durable = 0_u64;
    let mut generation = 0_u64;
    let mut checkpoints = 0_u64;
    let mut plaintext_bytes = 0_u64;
    let mut segment_index = 0_u64;
    loop {
        let bytes = attempt
            .receive_data()
            .await
            .map_err(|error| format!("receive data: {error:?}"))?
            .ok_or("data stream closed before settlement")?;
        match decoded(&bytes)? {
            StreamFrame::Data(data) => {
                let through = data.offset + data.bytes.len() as u64;
                let StreamAction::Persist { through: accepted } =
                    state.data(&data).map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not persist new data".into());
                };
                if through != accepted {
                    return Err("receiver persistence offset differed".into());
                }
                let (header, plaintext) = decode_validation_record(&opener, &data.bytes)?;
                if header.index() != segment_index
                    || header.offset() != plaintext_bytes
                    || header.total_len() != expected_bytes
                    || header.stream_id() != &VALIDATION_STREAM_ID
                    || header.open_digest() != &VALIDATION_OPEN_DIGEST
                {
                    return Err(
                        "native Profile-5 segment header is not the expected partition".into(),
                    );
                }
                plaintext_bytes = plaintext_bytes
                    .checked_add(plaintext.len() as u64)
                    .ok_or("validation payload length overflow")?;
                if plaintext_bytes > expected_bytes {
                    return Err("validation payload exceeds expected length".into());
                }
                segment_index += 1;
                hasher.update(plaintext.as_slice());
                if through == expected_wire || through - durable >= batch {
                    generation += 1;
                    let limit = profile5_receive_limit(expected_wire, through, checkpoint_batch);
                    let StreamAction::Send(checkpoint) = state
                        .persisted(through, generation, limit)
                        .map_err(|error| error.to_string())?
                    else {
                        return Err("receiver did not produce checkpoint".into());
                    };
                    attempt
                        .send_control(&encoded(checkpoint)?)
                        .await
                        .map_err(|error| format!("send checkpoint: {error:?}"))?;
                    durable = through;
                    checkpoints += 1;
                }
            }
            StreamFrame::Finish(finish) => {
                if plaintext_bytes != expected_bytes {
                    return Err("validation payload ended before expected length".into());
                }
                let StreamAction::Promote =
                    state.finish(finish).map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not promote complete stream".into());
                };
                let digest: [u8; 32] = hasher.finalize().into();
                let StreamAction::Send(result) = state
                    .promoted(StreamResultCode::Promoted, digest)
                    .map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not produce result".into());
                };
                attempt
                    .send_control(&encoded(result)?)
                    .await
                    .map_err(|error| format!("send result: {error:?}"))?;
                let ack = attempt
                    .receive_data()
                    .await
                    .map_err(|error| format!("receive result ack: {error:?}"))?
                    .ok_or("data stream closed before result ack")?;
                let StreamFrame::ResultAck(ack) = decoded(&ack)? else {
                    return Err("settlement frame was not result ack".into());
                };
                let StreamAction::Terminal(StreamResultCode::Promoted) = state
                    .result_ack(ack, StreamResultCode::Promoted)
                    .map_err(|error| error.to_string())?
                else {
                    return Err("receiver settlement action differed".into());
                };
                if attempt
                    .receive_data()
                    .await
                    .map_err(|error| format!("receive data EOF: {error:?}"))?
                    .is_some()
                {
                    return Err("data stream contained data after result ack".into());
                }
                attempt
                    .finish_control()
                    .await
                    .map_err(|error| format!("finish control stream: {error:?}"))?;
                let elapsed_ns = started.elapsed().as_nanos();
                return Ok(StreamValidationReport {
                    bytes: expected_bytes,
                    elapsed_ns,
                    mib_per_second: rate(expected_bytes, elapsed_ns),
                    checkpoints,
                    digest,
                });
            }
            _ => return Err("unexpected frame on data stream".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use std::collections::BTreeSet;

    #[test]
    fn validation_record_is_exact_native_profile5_record() {
        let record = encode_validation_record(&validation_sealer(), 32, 0, 0, vec![0x5a; 32])
            .expect("native record");
        assert_eq!(&record[4..12], b"ASTRBS02");
        let (header, plaintext) = decode_validation_record(&validation_opener(), &record)
            .expect("authenticated native record");
        assert_eq!(header.index(), 0);
        assert_eq!(header.offset(), 0);
        assert_eq!(plaintext.as_slice(), &[0x5a; 32]);
        let mut legacy = Vec::from(16_u32.to_be_bytes());
        legacy.extend_from_slice(b"ABX1");
        legacy.extend_from_slice(&[0; 12]);
        assert!(decode_validation_record(&validation_opener(), &legacy).is_err());
    }

    async fn endpoint_pair() -> (Endpoint, Endpoint, std::net::SocketAddr) {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let address = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .expect("IPv4 server address");
        (server, client, address)
    }

    async fn assert_transfer(bytes: u64, checkpoint_batch: u32) {
        let (server, client, address) = endpoint_pair().await;
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                receive_with_batch(connection, bytes, checkpoint_batch)
                    .await
                    .expect("receive")
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent =
            tokio::time::timeout(std::time::Duration::from_secs(10), send(connection, bytes))
                .await
                .expect("native transfer must not deadlock")
                .expect("send");
        let received = receiver.await.expect("receiver task");
        assert_eq!(sent.bytes, bytes);
        assert_eq!(received.bytes, bytes);
        assert_eq!(sent.digest, received.digest);
        assert_eq!(received.checkpoints, sent.checkpoints);
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn native_profile5_driver_transfers_and_settles_over_selected_transport() {
        assert_transfer(2 * 1024 * 1024, MAX_STREAM_CHECKPOINT_BATCH_BYTES).await;
    }

    #[tokio::test]
    async fn native_profile5_driver_crosses_credit_checkpoint_without_deadlock() {
        const TEST_CHECKPOINT_BATCH: u32 = 8 * 1_048_576;
        assert_transfer(
            u64::from(TEST_CHECKPOINT_BATCH) + BLOB_STREAM_SEGMENT_BYTES as u64,
            TEST_CHECKPOINT_BATCH,
        )
        .await;
    }
}
