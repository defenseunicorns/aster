#![no_main]

use std::{cell::RefCell, hint::black_box};

use aster_mesh::{ProvisioningLoadId, UnprotectedProvisioning};
use aster_systemd_credentials::{
    encode_credential_envelope, fuzz_decode_credential_envelope, provisioning_secret_ref,
};
use libfuzzer_sys::fuzz_target;

struct Harness {
    operation: ProvisioningLoadId,
    secret_ref: aster_mesh::ProvisioningSecretRef,
    valid_envelope: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        let operation = ProvisioningLoadId::new([0xa6; 32]);
        let secret_ref = provisioning_secret_ref(7, [0xa7; 32])
            .expect("fixed fuzz provider reference must be valid");
        let plaintext = UnprotectedProvisioning::new(
            include_bytes!("../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
        )
        .expect("fixed non-production fuzz provisioning must be bounded");
        let valid_envelope = encode_credential_envelope(&secret_ref, operation, &plaintext)
            .expect("fixed fuzz envelope must encode")
            .to_vec();
        Self {
            operation,
            secret_ref,
            valid_envelope,
        }
    }

    fn candidate(&self, input: &[u8]) -> Vec<u8> {
        if input.first() != Some(&b'M') {
            return input.to_vec();
        }
        let mut candidate = self.valid_envelope.clone();
        for command in input[1..].chunks_exact(4) {
            let index = usize::from(u16::from_be_bytes([command[1], command[2]]));
            match command[0] & 0x03 {
                0 if !candidate.is_empty() => {
                    let position = index % candidate.len();
                    candidate[position] ^= command[3];
                }
                1 if !candidate.is_empty() => {
                    candidate.truncate(index % candidate.len());
                }
                2 => candidate.push(command[3]),
                _ => {}
            }
        }
        candidate
    }

    fn decode(&self, input: &[u8]) {
        let candidate = self.candidate(input);
        black_box(fuzz_decode_credential_envelope(
            &candidate,
            self.operation,
            &self.secret_ref,
        ));
    }
}

thread_local! {
    static HARNESS: RefCell<Harness> = RefCell::new(Harness::new());
}

fuzz_target!(|input: &[u8]| {
    HARNESS.with(|harness| harness.borrow().decode(input));
});
