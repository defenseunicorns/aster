#![no_main]

use std::hint::black_box;

use aster_systemd_credentials::{admin::fuzz_decode_admin_records, provisioning_secret_ref};
use libfuzzer_sys::fuzz_target;

fn reference() -> Vec<u8> {
    provisioning_secret_ref(1, [0x33; 32])
        .expect("fixed fuzz provider reference must be valid")
        .to_bytes()
}

fn valid_ledger() -> Vec<u8> {
    let reference = reference();
    let mut encoded = Vec::with_capacity(204 + reference.len());
    encoded.extend_from_slice(b"ASTRSDL1");
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&[0, 0]);
    encoded.extend_from_slice(&[0xa0; 32]);
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&[1, 0, 0, 0]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x11; 32]);
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&[0x44; 32]);
    encoded.extend_from_slice(&[0x55; 32]);
    encoded.extend_from_slice(&(reference.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&reference);
    encoded
}

fn valid_manifest() -> Vec<u8> {
    let reference = reference();
    let mut encoded = Vec::with_capacity(88 + reference.len());
    encoded.extend_from_slice(b"ASTRSDM1");
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&[0x55; 32]);
    encoded.extend_from_slice(&(reference.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&reference);
    encoded
}

fn mutate(mut candidate: Vec<u8>, input: &[u8]) -> Vec<u8> {
    for command in input.chunks_exact(4) {
        let index = usize::from(u16::from_be_bytes([command[1], command[2]]));
        match command[0] & 0x03 {
            0 if !candidate.is_empty() => {
                let position = index % candidate.len();
                candidate[position] ^= command[3];
            }
            1 if !candidate.is_empty() => candidate.truncate(index % candidate.len()),
            2 => candidate.push(command[3]),
            _ => {}
        }
    }
    candidate
}

fuzz_target!(|input: &[u8]| {
    assert_eq!(
        fuzz_decode_admin_records(&valid_ledger()),
        (true, false),
        "canonical ledger fixture must reach only the ledger decoder"
    );
    assert_eq!(
        fuzz_decode_admin_records(&valid_manifest()),
        (false, true),
        "canonical manifest fixture must reach only the manifest decoder"
    );
    black_box(fuzz_decode_admin_records(input));
    black_box(fuzz_decode_admin_records(&mutate(valid_ledger(), input)));
    black_box(fuzz_decode_admin_records(&mutate(valid_manifest(), input)));
});
