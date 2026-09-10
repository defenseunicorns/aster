#![no_main]

use aster_systemd_credentials::{admin::ProtectedBackupArtifact, provisioning_secret_ref};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

fn valid_backup() -> Vec<u8> {
    let reference = provisioning_secret_ref(2, [0x33; 32])
        .expect("fixed v2 reference")
        .to_bytes();
    let ciphertext = b"protected ciphertext fixture";
    // SHA-256 of the literal ciphertext and its independently encoded v2 manifest.
    let manifest_digest = [
        0x10, 0xb0, 0xc9, 0xc4, 0x71, 0x73, 0x0f, 0x6d, 0x26, 0x90, 0xde, 0x0b, 0xa5, 0x5b, 0x5a,
        0x52, 0xad, 0x82, 0x14, 0x81, 0x81, 0x62, 0x85, 0xf8, 0xa2, 0x95, 0xb8, 0x77, 0x15, 0xcf,
        0x4b, 0xf0,
    ];
    let ciphertext_digest = [
        0xfd, 0x50, 0x44, 0x87, 0xbf, 0x66, 0xf5, 0xe3, 0xe1, 0x41, 0xba, 0x23, 0x75, 0xf4, 0x4a,
        0xb6, 0xd9, 0xd0, 0xc5, 0xd6, 0x4c, 0xf1, 0x91, 0x01, 0x46, 0x8b, 0x20, 0x29, 0x53, 0x33,
        0xf3, 0xb2,
    ];
    let mut bytes = b"ASTRSDB1\x00\x02\x00\x00".to_vec();
    bytes.extend_from_slice(&[0x11; 32]);
    bytes.extend_from_slice(&[0xa0; 32]);
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.extend_from_slice(&[0x22; 32]);
    bytes.extend_from_slice(&(reference.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&reference);
    bytes.extend_from_slice(&manifest_digest);
    bytes.extend_from_slice(&ciphertext_digest);
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    bytes
}

fn mutate(mut bytes: Vec<u8>, input: &[u8]) -> Vec<u8> {
    for command in input.chunks_exact(4) {
        let index = usize::from(u16::from_be_bytes([command[1], command[2]]));
        match command[0] & 3 {
            0 if !bytes.is_empty() => {
                let position = index % bytes.len();
                bytes[position] ^= command[3];
            }
            1 if !bytes.is_empty() => bytes.truncate(index % bytes.len()),
            2 => bytes.push(command[3]),
            _ => {}
        }
    }
    bytes
}

fuzz_target!(|input: &[u8]| {
    let fixture = valid_backup();
    let artifact = ProtectedBackupArtifact::from_bytes(&fixture)
        .expect("canonical v2 backup fixture must pass the production decoder");
    assert_eq!(artifact.as_bytes(), fixture);
    black_box(ProtectedBackupArtifact::from_bytes(input).is_ok());
    black_box(ProtectedBackupArtifact::from_bytes(&mutate(fixture, input)).is_ok());
});
