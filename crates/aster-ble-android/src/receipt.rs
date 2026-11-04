use crate::{ValidatorConfig, ValidatorError, ValidatorErrorCategory};
use aster_mesh::{
    TransferProfileOfferV1, negotiate_transfer_profiles_for_semantic_version,
    transfer_profile_digest,
};
use aster_node::PeerReceipt;
use serde::Serialize;
use std::fmt::Write as _;

const SEMANTIC_V9: u16 = 9;
const V9_PROFILES: [u16; 5] = [2, 1, 1, 5, 1];

/// Sanitized evidence returned after an exact Android Ring-1 validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationReceipt {
    /// Authenticated semantic version.
    pub semantic_version: u16,
    /// Selected Event/State/Record/Blob/EventBridge profiles.
    pub negotiated_transfer_profiles: [u16; 5],
    /// Canonical lowercase transfer-profile digest.
    pub transfer_profile_digest: String,
    /// Whether the authenticated peer equals the configured mission identity.
    pub mission_peer_match: bool,
    /// Whether the profile digest equals the canonical v9 digest.
    pub profile_digest_match: bool,
    /// Android's maximum transmit packet size for this socket.
    pub send_packet_bytes: usize,
    /// Android's maximum receive packet size for this socket.
    pub receive_packet_bytes: usize,
    /// Event page entries consumed from the peer.
    pub event_page_entries_received: usize,
    /// Protected source Event bytes consumed from the peer.
    pub event_page_bytes_received: usize,
    /// Newly and durably inserted Event page entries.
    pub event_page_inserts: usize,
    /// Whether Event page bytes exceeded the reported receive packet size.
    pub event_larger_than_receive_packet: bool,
    /// Whether every Blob attempt counter remained zero.
    pub no_blob_attempt: bool,
}

/// Validates a completed contact against the exact Android Ring-1 acceptance profile.
pub fn validate_ring1_receipt(
    config: &ValidatorConfig,
    receipt: &PeerReceipt,
) -> Result<ValidationReceipt, ValidatorError> {
    let expected_digest = canonical_v9_profile_digest()?;
    if receipt.mission_peer != Some(config.mission_peer()) {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Authentication,
            "validator authenticated an unexpected mission peer",
        ));
    }
    if receipt.semantic_version != SEMANTIC_V9
        || receipt.negotiated_transfer_profiles != Some(V9_PROFILES)
        || receipt.transfer_profile_digest != Some(expected_digest)
    {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Protocol,
            "validator contact differs from the exact semantic-v9 profile",
        ));
    }
    let no_blob_attempt = receipt.blob_ranges_fetched == 0
        && receipt.blob_bytes_fetched == 0
        && receipt.blob_remaining == 0
        && receipt.blob_deferred == 0
        && receipt.blob_stream == Default::default();
    if !no_blob_attempt {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Protocol,
            "validator contact unexpectedly attempted Blob transfer",
        ));
    }
    if receipt.fetched != 1
        || receipt.inserted != 1
        || receipt.duplicates != 0
        || receipt.event_pages_received != 1
        || receipt.event_page_entries_received != 1
        || receipt.event_page_inserts != 1
        || receipt.event_page_duplicates != 0
    {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Protocol,
            "validator contact did not durably insert exactly one Event",
        ));
    }
    let event_larger_than_receive_packet =
        receipt.event_page_bytes_received > config.receive_packet_bytes();
    if config.require_event_larger_than_mtu() && !event_larger_than_receive_packet {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Protocol,
            "validator Event did not exceed the receive packet size",
        ));
    }
    Ok(ValidationReceipt {
        semantic_version: receipt.semantic_version,
        negotiated_transfer_profiles: V9_PROFILES,
        transfer_profile_digest: format_digest(expected_digest),
        mission_peer_match: true,
        profile_digest_match: true,
        send_packet_bytes: config.send_packet_bytes(),
        receive_packet_bytes: config.receive_packet_bytes(),
        event_page_entries_received: receipt.event_page_entries_received,
        event_page_bytes_received: receipt.event_page_bytes_received,
        event_page_inserts: receipt.event_page_inserts,
        event_larger_than_receive_packet,
        no_blob_attempt,
    })
}

fn canonical_v9_profile_digest() -> Result<[u8; 32], ValidatorError> {
    let offer = TransferProfileOfferV1::for_semantic_version(SEMANTIC_V9).map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Internal,
            "validator canonical profile is unavailable",
        )
    })?;
    let negotiated = negotiate_transfer_profiles_for_semantic_version(SEMANTIC_V9, &offer, &offer)
        .map_err(|_| {
            ValidatorError::new(
                ValidatorErrorCategory::Internal,
                "validator canonical profile negotiation failed",
            )
        })?;
    Ok(transfer_profile_digest(&offer, &offer, &negotiated))
}

fn format_digest(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ValidatorConfig, ValidatorErrorCategory};
    use aster_node::PeerReceipt;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const V9_PROFILE_DIGEST: [u8; 32] = [
        0xac, 0xe5, 0xad, 0x78, 0xfa, 0x87, 0x20, 0x39, 0x40, 0x22, 0x1a, 0xbc, 0x2a, 0x90, 0x61,
        0x44, 0xbf, 0xb0, 0xca, 0xd7, 0x4f, 0xca, 0xfc, 0x50, 0x89, 0xb5, 0x75, 0x97, 0x1d, 0x63,
        0x59, 0x6f,
    ];
    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    struct TestConfig {
        root: PathBuf,
        config: ValidatorConfig,
    }

    impl TestConfig {
        fn new() -> Self {
            let suffix = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-ble-android-receipt-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create test root");
            let mission = root.join("mission.bundle");
            fs::write(&mission, b"mission").expect("write mission fixture");
            let input = format!(
                concat!(
                    "{{",
                    "\"state_path\":\"{}\",",
                    "\"mission_bundle_path\":\"{}\",",
                    "\"mission_peer\":\"{}\",",
                    "\"bluetooth_address\":\"7C:FA:80:72:3B:7A\",",
                    "\"psm\":128,",
                    "\"send_packet_bytes\":512,",
                    "\"receive_packet_bytes\":256,",
                    "\"require_event_larger_than_mtu\":true",
                    "}}"
                ),
                root.join("state").display(),
                mission.display(),
                "11".repeat(32),
            );
            let config = ValidatorConfig::from_json(&input).expect("valid config");
            Self { root, config }
        }
    }

    impl Drop for TestConfig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn valid_receipt() -> PeerReceipt {
        PeerReceipt {
            semantic_version: 9,
            transfer_profile_digest: Some(V9_PROFILE_DIGEST),
            negotiated_transfer_profiles: Some([2, 1, 1, 5, 1]),
            mission_peer: Some([0x11; 32]),
            fetched: 1,
            inserted: 1,
            event_pages_received: 1,
            event_page_entries_received: 1,
            event_page_bytes_received: 513,
            event_page_inserts: 1,
            ..PeerReceipt::default()
        }
    }

    #[test]
    fn accepts_one_inserted_v9_event_larger_than_receive_packet() {
        let test = TestConfig::new();

        let validated =
            validate_ring1_receipt(&test.config, &valid_receipt()).expect("valid receipt");

        assert_eq!(validated.semantic_version, 9);
        assert_eq!(validated.negotiated_transfer_profiles, [2, 1, 1, 5, 1]);
        assert_eq!(validated.receive_packet_bytes, 256);
        assert_eq!(validated.event_page_entries_received, 1);
        assert_eq!(validated.event_page_bytes_received, 513);
        assert_eq!(validated.event_page_inserts, 1);
        assert!(validated.mission_peer_match);
        assert!(validated.profile_digest_match);
        assert!(validated.event_larger_than_receive_packet);
        assert!(validated.no_blob_attempt);
    }

    #[test]
    fn rejects_wrong_peer_or_profile_digest() {
        let test = TestConfig::new();
        let mut wrong_peer = valid_receipt();
        wrong_peer.mission_peer = Some([0x22; 32]);
        let error = validate_ring1_receipt(&test.config, &wrong_peer).expect_err("wrong peer");
        assert_eq!(error.category(), ValidatorErrorCategory::Authentication);

        let mut wrong_digest = valid_receipt();
        wrong_digest.transfer_profile_digest = Some([0x33; 32]);
        let error = validate_ring1_receipt(&test.config, &wrong_digest).expect_err("wrong digest");
        assert_eq!(error.category(), ValidatorErrorCategory::Protocol);
    }

    #[test]
    fn rejects_blob_attempt_and_missing_durable_insert() {
        let test = TestConfig::new();
        let mut blob = valid_receipt();
        blob.blob_stream.received_bytes = 1;
        let error = validate_ring1_receipt(&test.config, &blob).expect_err("Blob attempt");
        assert_eq!(error.category(), ValidatorErrorCategory::Protocol);

        let mut missing_insert = valid_receipt();
        missing_insert.inserted = 0;
        missing_insert.event_page_inserts = 0;
        let error =
            validate_ring1_receipt(&test.config, &missing_insert).expect_err("missing insert");
        assert_eq!(error.category(), ValidatorErrorCategory::Protocol);
    }

    #[test]
    fn rejects_event_not_larger_than_receive_packet() {
        let test = TestConfig::new();
        let mut receipt = valid_receipt();
        receipt.event_page_bytes_received = 256;

        let error = validate_ring1_receipt(&test.config, &receipt).expect_err("small Event");

        assert_eq!(error.category(), ValidatorErrorCategory::Protocol);
    }
}
