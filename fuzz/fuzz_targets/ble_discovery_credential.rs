#![no_main]

use aster_host::fuzz_parse_discovery_credential_artifact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    fuzz_parse_discovery_credential_artifact(input);
});
