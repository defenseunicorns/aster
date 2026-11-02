/// Resolves an explicit `HEX:` corpus fixture into the wire bytes consumed by
/// a fuzz target. Invalid hexadecimal remains unmodified so it still exercises
/// the hostile-input path instead of disappearing during corpus loading.
pub fn corpus_input(input: &[u8]) -> Vec<u8> {
    let Some(hexadecimal) = input.strip_prefix(b"HEX:") else {
        return input.to_vec();
    };
    let hexadecimal = hexadecimal.trim_ascii();
    if hexadecimal.len() % 2 != 0 {
        return input.to_vec();
    }
    let mut decoded = Vec::with_capacity(hexadecimal.len() / 2);
    for pair in hexadecimal.chunks_exact(2) {
        let (Some(high), Some(low)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
            return input.to_vec();
        };
        decoded.push((high << 4) | low);
    }
    decoded
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::corpus_input;

    #[test]
    fn ascii_hex_payload_decodes_to_wire_bytes() {
        assert_eq!(corpus_input(b"HEX:41534d01\n"), b"ASM\x01");
    }

    #[test]
    fn non_ascii_hex_payload_is_left_unchanged() {
        let input = b"HEX:41534d018603012222222\xd6\x995ce29bc\n";

        assert_eq!(corpus_input(input), input);
    }

    #[test]
    fn malformed_or_odd_hex_payload_is_left_unchanged() {
        for input in [b"HEX:0\n".as_slice(), b"HEX:0g\n".as_slice()] {
            assert_eq!(corpus_input(input), input);
        }
    }
}
