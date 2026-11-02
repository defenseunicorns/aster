#![no_main]

use aster_fuzz::corpus_input;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let wire = corpus_input(input);
    aster_node::fuzz_stream_transfer_decode(&wire);
});
