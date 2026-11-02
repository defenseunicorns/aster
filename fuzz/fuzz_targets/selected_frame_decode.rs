#![no_main]

use aster_fuzz::corpus_input;
use aster_mesh::MAX_SELECTED_BRIDGE_WRAPPER_BYTES;
use aster_redb_store::{BlobTransferId, ControlTransferId, EventTransferId};
use libfuzzer_sys::fuzz_target;

const TAGS: [u8; 78] = [
    0x09, 0x0a, 0x0b, 0x0c, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x21, 0x22,
    0x23, 0x24, 0x25, 0x26, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x51, 0x52, 0x53, 0x54, 0x61, 0x62, 0x69, 0x6a, 0x6b, 0x6c, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7a, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x91, 0x92, 0xa1, 0xa2, 0xa5,
    0xa6, 0xb1, 0xb2, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
];

fn structured_transfer_id(payload: &[u8]) -> EventTransferId {
    let mut bytes = [0u8; 32];
    let copied = payload.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&payload[..copied]);
    EventTransferId::new(bytes)
}

fn structured_control_id(payload: &[u8]) -> ControlTransferId {
    let mut bytes = [0u8; 32];
    let copied = payload.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&payload[..copied]);
    ControlTransferId::new(bytes)
}

fn structured_blob_id(payload: &[u8]) -> BlobTransferId {
    let mut bytes = [0u8; 32];
    let copied = payload.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&payload[..copied]);
    BlobTransferId::new(bytes)
}

fn append_blob_tuple(candidate: &mut Vec<u8>, payload: &[u8], requested_len: u32) {
    candidate.push(1);
    candidate.extend_from_slice(structured_blob_id(payload).as_bytes());
    candidate.push(2);
    candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
    candidate.extend_from_slice(&u64::from(requested_len).to_be_bytes());
    candidate.extend_from_slice(&0u64.to_be_bytes());
    candidate.extend_from_slice(&requested_len.to_be_bytes());
}

fn structured_candidate(input: &[u8]) -> Vec<u8> {
    let (selector, payload) = input.split_first().unwrap_or((&0, &[]));
    let tag = TAGS[usize::from(*selector) % TAGS.len()];
    if let Some(candidate) = aster_node::fuzz_structured_v7_mechanics_frame(tag, *selector, payload)
    {
        return candidate;
    }
    let event_direction = 1 + (selector & 1);
    let mutable_class = 1 + ((selector >> 1) % 3);
    let mut candidate = b"ASM\x01".to_vec();
    candidate.push(tag);
    match tag {
        0x09 | 0x0a => candidate.extend_from_slice(&0u16.to_be_bytes()),
        0x0b | 0x0c => {
            candidate.push(0);
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
            candidate.extend_from_slice(&0u64.to_be_bytes());
            candidate.extend_from_slice(&0u16.to_be_bytes());
        }
        0x11 | 0x12 | 0x15 | 0x16 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x41 | 0x42 | 0x45 | 0x46 => {
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x13 | 0x14 | 0x17 | 0x18 | 0x19 | 0x1a | 0x31 | 0x32 => {
            candidate.push(event_direction);
        }
        0x21 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
        }
        0x22 | 0x23 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x24 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.push(selector & 1);
        }
        0x25 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
            candidate.extend_from_slice(&0u32.to_be_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x26 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
            candidate.push(selector & 1);
            candidate.push(1 + (selector & 1));
        }
        0x33 | 0x34 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
        }
        0x51 => candidate.extend_from_slice(structured_control_id(payload).as_bytes()),
        0x52 | 0x53 => {
            candidate.extend_from_slice(structured_control_id(payload).as_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x54 => {
            candidate.extend_from_slice(structured_control_id(payload).as_bytes());
            candidate.push(selector & 1);
        }
        0x49 => {
            candidate.push(0);
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x69 | 0x6a => {
            candidate.push(1 + (selector & 1));
            candidate.extend_from_slice(&0u16.to_be_bytes());
        }
        0x6b | 0x6c => candidate.extend_from_slice(&0u16.to_be_bytes()),
        0x71 | 0x72 | 0x75 | 0x76 => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x73 | 0x74 | 0x77 | 0x78 | 0x79 | 0x7a => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
        }
        0x81 => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
        }
        0x82 | 0x83 => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x84 | 0x85 | 0x86 => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.push(selector % 3);
        }
        0x91 | 0x92 => {
            candidate.push(mutable_class);
            candidate.push(event_direction);
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
        }
        0xa1 => {
            append_blob_tuple(&mut candidate, payload, 1);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
        }
        0xa2 => {
            let range = if payload.is_empty() {
                &[0u8][..]
            } else {
                &payload[..payload.len().min(16 * 1024)]
            };
            let requested_len = u32::try_from(range.len()).expect("bounded Blob range length");
            append_blob_tuple(&mut candidate, payload, requested_len);
            candidate.push(1);
            candidate.extend_from_slice(&requested_len.to_be_bytes());
            candidate.extend_from_slice(range);
        }
        0xa5 | 0xa6 => {
            let disposition = 1 + (selector % 5);
            let accepted_len = u32::from(disposition <= 2);
            let total_len: u64 = if disposition == 1 { 2 } else { 1 };
            candidate.push(1);
            candidate.extend_from_slice(structured_blob_id(payload).as_bytes());
            candidate.push(2);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.extend_from_slice(&total_len.to_be_bytes());
            candidate.extend_from_slice(&0u64.to_be_bytes());
            candidate.extend_from_slice(&accepted_len.to_be_bytes());
            candidate.push(disposition);
        }
        0xb1 | 0xb2 => {
            candidate.push(1);
            candidate.extend_from_slice(&u64::from(*selector).to_be_bytes());
        }
        0xc1 | 0xc2 => candidate.push(selector & 1),
        0xc3 => {
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            let route = payload.get(32..).unwrap_or_default();
            let wrapper_len = (route.len() / 2).min(MAX_SELECTED_BRIDGE_WRAPPER_BYTES);
            let wrapper = &route[..wrapper_len];
            let source = &route[wrapper_len..route.len().min(wrapper_len + 1024 * 1024)];
            candidate.extend_from_slice(
                &u32::try_from(wrapper.len())
                    .expect("bounded bridge wrapper length")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(wrapper);
            candidate.extend_from_slice(
                &u32::try_from(source.len())
                    .expect("bounded bridge source length")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(source);
        }
        0xc4 => {
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.push(selector % 4);
        }
        0xc5 | 0xc6 => candidate.extend_from_slice(&u64::from(*selector).to_be_bytes()),
        0xd1..=0xd5 => unreachable!("v7 tags use the production encoder"),
        0x43 | 0x44 | 0x47 | 0x48 | 0x61 | 0x62 => {}
        _ => unreachable!("tag selected from the complete fixed table"),
    }
    candidate
}

fn structured_v8_candidate(input: &[u8]) -> Vec<u8> {
    const CLAIM: &str = "41535452424c30380001000800041111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000";
    let selector = input.first().copied().unwrap_or(0);
    let mut candidate = structured_candidate(input);
    let Some((&tag, body)) = candidate.get(4).zip(candidate.get(5..)) else {
        return candidate;
    };
    let is_blob = body.first() == Some(&3);
    if is_blob && matches!(tag, 0x82 | 0x83) {
        if selector & 1 == 0 {
            candidate.push(0);
        } else {
            candidate.extend_from_slice(&[1, 0, 208]);
            for offset in (0..CLAIM.len()).step_by(2) {
                candidate.push(
                    u8::from_str_radix(&CLAIM[offset..offset + 2], 16)
                        .expect("fixed Blob claim seed is hexadecimal"),
                );
            }
        }
    } else if is_blob && matches!(tag, 0x84 | 0x85 | 0x86) {
        if selector & 1 == 0 {
            candidate.push(0);
        } else {
            candidate.push(1);
            let digest = payload_digest(input.get(1..).unwrap_or_default());
            candidate.extend_from_slice(&digest);
        }
    }
    candidate
}

fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let copied = payload.len().min(digest.len());
    digest[..copied].copy_from_slice(&payload[..copied]);
    digest
}

fuzz_target!(|input: &[u8]| {
    const MAX_FUZZ_FRAME_BYTES: usize = 2 * 1024 * 1024;
    const MAX_FUZZ_TURN_BYTES: usize = 64 * 1024 * 1024;

    let decoded_input = corpus_input(input);
    let _accepted = aster_node::fuzz_decode_mechanics_frame(&decoded_input);
    let _accepted_v8 =
        aster_node::fuzz_decode_mechanics_frame_for_semantic_version(&decoded_input, 8);
    let _accepted_turn =
        aster_iroh::fuzz_decode_uni_turn(input, MAX_FUZZ_FRAME_BYTES, MAX_FUZZ_TURN_BYTES);
    let frame = structured_candidate(input);
    assert!(aster_node::fuzz_decode_mechanics_frame(&frame));
    let frame_v8 = structured_v8_candidate(input);
    assert!(aster_node::fuzz_decode_mechanics_frame_for_semantic_version(&frame_v8, 8));
    let mut turn = b"ASTU\x01".to_vec();
    turn.extend_from_slice(
        &u32::try_from(frame.len())
            .expect("structured frame fits the uni-turn length")
            .to_be_bytes(),
    );
    turn.extend_from_slice(&frame);
    assert!(aster_iroh::fuzz_decode_uni_turn(
        &turn,
        MAX_FUZZ_FRAME_BYTES,
        MAX_FUZZ_TURN_BYTES,
    ));
});
