#![no_main]

use aster_ble_l2cap::fuzz_inspect_record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = fuzz_inspect_record(input, 2 * 1024 * 1024);
});
