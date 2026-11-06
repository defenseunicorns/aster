#![no_main]

use aster_ble_linux::{
    AsterRosterBeaconV1, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
    LeasedDiscoveryCredentialSet,
};
use libfuzzer_sys::fuzz_target;
use std::{hint::black_box, time::{Duration, Instant}};

fuzz_target!(|input: &[u8]| {
    let now = Instant::now();
    let credentials = LeasedDiscoveryCredentialSet::new(
        DiscoveryCredential::new(
            DiscoveryGeneration::new(1).expect("fixed generation is nonzero"),
            DiscoverySecret::new([0x42; 32]).expect("fixed secret is nonzero"),
        ),
        None,
        now + Duration::from_secs(1),
    )
    .expect("fixed credential set has distinct generations");
    let _ = black_box(AsterRosterBeaconV1::decode_and_verify(
        input,
        &credentials,
        now,
    ));
});
