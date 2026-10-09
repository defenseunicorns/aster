//! Selected-stack Aster node composition.
//!
//! The selected runtime composes a mission-authenticated Iroh carrier, bounded
//! Negentropy reconciliation, mission-bound redb state, and the existing
//! `aster-core` source-authenticated Event semantics. Negotiated semantic v3
//! adds authenticated custody age, finite-TTL forwarding, bounded global and
//! per-scope quotas, priority-aware scheduling, and live
//! [`EventEmissionPolicy`] control (including receive-only operation), while
//! v1/v2 remain compatible for durable Events. Its application boundary also
//! composes source-authenticated latest-value State, explicit-conflict Record,
//! and immutable Blob operations. State exposes durable positive-current-version
//! delivery, Record exposes durable whole-projection delivery that never splits
//! an explicit conflict or runs merge code, and Blob exposes durable metadata-
//! only delivery for each exact signed immutable publication. Blob bytes remain
//! behind the separate authenticated read surface. [`RunningNode::selected_state`],
//! [`RunningNode::selected_records`], and [`RunningNode::selected_blobs`] return
//! cloneable handles that share the running actor's bounded application lane;
//! live Blob work is isolated on a bounded worker and returns only bounded,
//! zeroize-on-drop plaintext pages. The corresponding stopped facades retain
//! exclusive maintenance/application access and streaming Blob I/O. State and
//! Record additionally use class-specific, explicitly interested reconciliation
//! lanes; semantic v5 adds an explicitly interested, resumable Blob lane.
//! Shutdown and zeroization close live application
//! admission before releasing the actor's store authority, so retained handles
//! fail closed with [`application::ApplicationErrorKind::StateUnavailable`].
//! Representative physical/mixed-implementation acceptance and a retained live
//! Blob receipt remain open.
//! The caller-identified opaque API remains isolated for compatibility and is
//! not advertised by the production Event reconciliation path.

#![forbid(unsafe_code)]

pub mod application;
pub mod bridge_runtime;
pub mod control_admin;
mod demo_publication;
mod event_pages;
mod frame;
mod identity;
pub mod mission;
pub mod publication_journal;
mod runtime;

pub use aster_redb_store::{BlobDepotLimits, CustodyQuota, StoreLimits};
pub use control_admin::{
    ControlAdminError, ControlAdminErrorKind, MAX_SELECTED_REKEY_RECIPIENTS,
    MAX_SELECTED_REKEY_REGISTRY_BYTES, MAX_SELECTED_REKEY_TOPIC_GRANTS, RegistryGenerationWitness,
    RevocationRequest, ScopeRekeyRequest, SelectedControlAdmin, SelectedControlHandle,
};
pub use identity::{IdentityError, NodeIdentity};
pub use mission::{
    CLASSICAL_CHANNEL_BINDING_CONTEXT_BYTES, CarrierBoundClassicalMissionSession,
    ClassicalChannelBindingContext, MissionPeerBinding, MissionProvisioningOrigin,
    MissionSessionError, UnprotectedClassicalMission, initiate_classical_over_iroh,
    respond_classical_over_iroh,
};
pub use runtime::{
    ControlPublicationReceipt, DemoScenario, EventEmissionPolicy,
    MAX_CUSTODY_FINALIZATION_CHARGE_MS, MissionExpectedPeer, MutableSourceInterests,
    NodeApplication, NodeBootstrapError, NodeBootstrapErrorKind, NodeConfig, NodeConfigOptions,
    NodeError, NodeOperatorOutputPolicy, NodeReceipt, PeerReceipt, RunningNode,
    SelectedForwardingConfig, SoftwareZeroizationPathState, SoftwareZeroizationReceipt,
    SoftwareZeroizationState, SourceInterestSelector, StoreReceipt, audit_store_event_operations,
    ensure_state_accepts_normal_operation, format_control_transfer_id, inspect_store, put_opaque,
    run_demo, run_demo_scenario, run_node, run_node_with_forwarding, start_node,
    start_node_with_forwarding, start_node_with_forwarding_and_output_policy,
    start_supervised_node_with_forwarding_and_output_policy, zeroize_node,
};
#[cfg(feature = "nearby-discovery")]
pub use runtime::{
    MAX_NEARBY_DISCOVERY_IPV4_INTERFACES, MAX_NEARBY_DISCOVERY_WINDOW, MissionNearbyPeer,
};

use aster_mesh::NodeId;
use aster_profile::ItemId;

/// Parses a complete lowercase or uppercase hexadecimal item identifier.
pub fn parse_item_id(value: &str) -> Result<ItemId, NodeError> {
    parse_hex_32(value, "item").map(ItemId::new)
}

/// Formats a complete item identifier as lowercase hexadecimal.
pub fn format_item_id(id: ItemId) -> String {
    let mut output = String::with_capacity(64);
    for byte in id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Parses a complete hexadecimal mission NodeId without accepting short forms.
pub fn parse_node_id(value: &str) -> Result<NodeId, NodeError> {
    parse_hex_32(value, "mission node")
}

/// Formats the complete independently authenticated mission NodeId.
pub fn format_node_id(id: NodeId) -> String {
    format_hex_32(&id)
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], NodeError> {
    let encoded = value.as_bytes();
    if encoded.len() != 64 {
        return Err(NodeError::Configuration(format!(
            "{label} identifier must contain exactly 64 hexadecimal characters"
        )));
    }
    let mut bytes = [0u8; 32];
    for (pair, output) in encoded.chunks_exact(2).zip(&mut bytes) {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            NodeError::Configuration(format!("{label} identifier is not hexadecimal"))
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            NodeError::Configuration(format!("{label} identifier is not hexadecimal"))
        })?;
        *output = (high << 4) | low;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Encodes a path as one delimiter-safe structured receipt field.
pub fn format_path_field(path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        format_receipt_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        format_receipt_bytes(path.to_string_lossy().as_bytes())
    }
}

/// Encodes arbitrary text as one delimiter-safe structured receipt field.
pub fn format_receipt_field(value: &str) -> String {
    format_receipt_bytes(value.as_bytes())
}

fn format_receipt_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'/' | b':') {
            output.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut output, "%{byte:02X}");
        }
    }
    output
}

fn format_hex_32(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Builds one canonical semantic-v7 mechanics frame for structured fuzz coverage.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_structured_v7_mechanics_frame(
    tag: u8,
    selector: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    use crate::event_pages::{
        ChangePageEntry, ChangePageV7, ChangeTurnFinishedV1, ChangeTurnHeaderV1, EventTurnPlanV1,
        LegacyDifference, TransferProfileId, TransferProfileOfferV1, empty_set_commitment,
        event_difference_set_commitment, schedule_digest,
    };
    use crate::frame::{EventDirection, Frame};
    use aster_redb_store::EventTransferId;

    let direction = if selector & 1 == 0 {
        EventDirection::ToSessionInitiator
    } else {
        EventDirection::ToSessionResponder
    };
    let mut id_bytes = [0u8; 32];
    let copied = payload.len().min(id_bytes.len());
    id_bytes[..copied].copy_from_slice(&payload[..copied]);
    let scheduled_id = EventTransferId::new(id_bytes);
    let scheduled = vec![scheduled_id];
    let set_commitment =
        event_difference_set_commitment(&scheduled).expect("one structured Event ID is canonical");
    let schedule = schedule_digest(&scheduled);
    let transfer_profile_digest = [0x21; 32];
    let frame = match tag {
        0xd1 => Frame::TransferProfileOffer(TransferProfileOfferV1::current()),
        0xd2 => Frame::EventTurnPlan(match 1 + (selector % 4) {
            1 => EventTurnPlanV1::PageActive {
                direction,
                transfer_profile_digest,
                difference_count: 1,
                set_commitment,
                scheduled_count: 1,
                unscheduled_count: 0,
            },
            2 => EventTurnPlanV1::LegacyActive {
                direction,
                transfer_profile_digest,
                difference: LegacyDifference::Exact {
                    difference_count: 1,
                    set_commitment,
                },
            },
            3 => EventTurnPlanV1::Empty {
                direction,
                transfer_profile_digest,
                selected_profile: TransferProfileId::EventPagesV1,
                set_commitment: empty_set_commitment(),
            },
            4 => EventTurnPlanV1::Suppressed {
                direction,
                transfer_profile_digest,
            },
            _ => unreachable!("variant is reduced modulo four"),
        }),
        0xd3 => Frame::ChangeTurnHeader(ChangeTurnHeaderV1 {
            direction,
            transfer_profile_digest,
            set_commitment,
            scheduled: scheduled.clone(),
            schedule_digest: schedule,
        }),
        0xd4 => Frame::ChangePage(ChangePageV7 {
            direction,
            transfer_profile_digest,
            schedule_digest: schedule,
            page_number: 0,
            entries: vec![ChangePageEntry {
                id: scheduled_id,
                custody: None,
                source_event: payload
                    .get(32..)
                    .filter(|source| !source.is_empty())
                    .unwrap_or(&[0])
                    .to_vec(),
            }],
            remaining: 0,
        }),
        0xd5 => Frame::ChangeTurnFinished(ChangeTurnFinishedV1 {
            direction,
            transfer_profile_digest,
            set_commitment,
            schedule_digest: schedule,
            final_page_count: 1,
        }),
        _ => return None,
    };
    Some(
        frame
            .encode_for_semantic_version(event_pages::SEMANTIC_PROTOCOL_V7)
            .expect("structured semantic-v7 frame must encode"),
    )
}

/// Exercises the selected-stack mechanics-frame decoder for hostile-input fuzzing.
///
/// This deliberately returns only an accepted/rejected disposition. Accepted
/// frames are also required to survive a canonical encode/decode round trip.
/// The opt-in API carries no protocol, mission-security, or semantic credit.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_mechanics_frame(input: &[u8]) -> bool {
    let Ok(frame) = frame::Frame::decode(input) else {
        return false;
    };
    let canonical = frame
        .encode()
        .expect("an accepted mechanics frame must re-encode");
    assert_eq!(canonical.as_slice(), input);
    assert_eq!(
        frame::Frame::decode(&canonical).expect("canonical mechanics frame must decode"),
        frame
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_id_text_round_trips_without_short_forms() {
        let id = ItemId::new([0xab; 32]);
        let text = format_item_id(id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_item_id(&text).expect("parse"), id);
        assert!(parse_item_id("ab").is_err());
    }

    #[test]
    fn mission_node_id_text_round_trips_without_short_forms() {
        let id = [0xcd; 32];
        let text = format_node_id(id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_node_id(&text).expect("parse"), id);
        assert!(parse_node_id("cd").is_err());
    }

    #[test]
    fn non_ascii_hex_and_receipt_control_characters_fail_closed() {
        let mut hostile = "0".repeat(61);
        hostile.push('€');
        assert_eq!(hostile.len(), 64);
        assert!(parse_item_id(&hostile).is_err());
        assert!(parse_node_id(&hostile).is_err());
        assert_eq!(
            format_path_field(std::path::Path::new("safe/line\nfield=value%")),
            "safe/line%0Afield%3Dvalue%25"
        );
    }
}
