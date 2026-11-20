use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_OUTPUT_BYTES: usize = 32;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

fn require_zeroize_on_drop<T: ZeroizeOnDrop>(value: T) -> T {
    value
}

/// Computes HMAC-SHA-256 while owning derived pads and digests in
/// zeroize-on-drop storage.
pub fn zeroizing_hmac_sha256(key: &[u8; 32], message_parts: &[&[u8]]) -> [u8; 32] {
    let mut pad = Zeroizing::new([0_u8; SHA256_BLOCK_BYTES]);
    pad[..key.len()].copy_from_slice(key);

    pad.iter_mut().for_each(|byte| *byte ^= HMAC_IPAD);
    let mut inner = require_zeroize_on_drop(Sha256::new());
    inner.update(&pad[..]);
    for part in message_parts {
        inner.update(part);
    }
    let inner_digest = Zeroizing::new(inner.finalize());

    pad.iter_mut()
        .for_each(|byte| *byte ^= HMAC_IPAD ^ HMAC_OPAD);
    let mut outer = require_zeroize_on_drop(Sha256::new());
    outer.update(&pad[..]);
    outer.update(&inner_digest[..]);
    let digest = Zeroizing::new(outer.finalize());

    let mut result = [0_u8; SHA256_OUTPUT_BYTES];
    result.copy_from_slice(&digest);
    result
}

#[cfg(test)]
mod tests {
    use super::zeroizing_hmac_sha256;

    #[test]
    fn matches_independent_sha256_vector_with_split_message() {
        let key = [0x0b; 32];
        assert_eq!(
            zeroizing_hmac_sha256(&key, &[b"Hi ", b"There"]),
            [
                0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b,
                0xbd, 0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96,
                0xa0, 0xb6, 0x8c, 0xf7,
            ]
        );
    }
}
