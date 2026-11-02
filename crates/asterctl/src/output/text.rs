use std::fmt::{Display, Write};

use buffa::{EnumValue, Enumeration};

use super::{Bytes, Double};
use crate::{api, blob_read};

pub(super) fn status(s: &api::GetStatusResponse) -> String {
    let mut text = String::from("NODE:\n");
    field(&mut text, "Identity", scalar(Bytes(&s.identity)));
    field(
        &mut text,
        "Mission authority",
        scalar(Bytes(&s.mission_authority)),
    );
    field(&mut text, "Sync", state(s.sync, "SYNC_STATUS_"));
    field(
        &mut text,
        "Configured emission",
        state(s.configured_emission_mode, "EMISSION_MODE_"),
    );
    field(
        &mut text,
        "Effective emission",
        state(s.effective_emission_mode, "EMISSION_MODE_"),
    );
    field(
        &mut text,
        "Authenticated contacts",
        count(s.authenticated_contacts),
    );
    field(
        &mut text,
        "Failed contacts",
        count(s.failed_contact_attempts),
    );

    writeln!(text, "\nPEERS ({}):", s.peers.len()).expect("write to string");
    for (index, peer) in s.peers.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        field(&mut text, "Identity", scalar(Bytes(&peer.peer)));
        field(
            &mut text,
            "Authorization",
            state(peer.authorization, "PEER_AUTHORIZATION_"),
        );
        field(
            &mut text,
            "Authenticated contacts",
            count(peer.authenticated_contacts),
        );
        field(
            &mut text,
            "Last contact",
            state(peer.last_contact, "CONTACT_STATUS_"),
        );
    }

    if let Some(s) = s.store_capacity.as_option() {
        text.push_str("\nSTORAGE:\n");
        field(
            &mut text,
            "Items",
            format!("{} / {}", count(s.items), count(s.item_limit)),
        );
        field(
            &mut text,
            "Payload",
            format!("{} / {}", size(s.payload_bytes), size(s.payload_byte_limit)),
        );
    }
    if let Some(s) = s.publish_operation_capacity.as_option() {
        text.push_str("\nPUBLICATION OPERATIONS:\n");
        field(
            &mut text,
            "Capacity state",
            state(s.warning_state, "OPERATION_CAPACITY_WARNING_"),
        );
        field(
            &mut text,
            "Rows",
            format!("{} / {}", count(s.rows), count(s.row_hard_limit)),
        );
        field(
            &mut text,
            "Size",
            format!("{} / {}", size(s.bytes), size(s.byte_hard_limit)),
        );
        field(&mut text, "Active rows", count(s.active_rows));
        field(&mut text, "Retired rows", count(s.retired_rows));
        field(&mut text, "Reverse index rows", count(s.reverse_rows));
        field(&mut text, "Profile boundary", count(s.profile_boundary));
        field(&mut text, "Profile remaining", count(s.profile_remaining));
        field(&mut text, "Profile warning", yes_no(s.profile_warning));
        field(&mut text, "Profile exhausted", yes_no(s.profile_exhausted));
        field(&mut text, "Ordinary remaining", count(s.ordinary_remaining));
        field(
            &mut text,
            "Emergency remaining",
            count(s.emergency_remaining),
        );
        let rate = if s.rolling_accept_rate.is_finite() {
            s.rolling_accept_rate.to_string()
        } else {
            scalar(Double(s.rolling_accept_rate))
        };
        field(&mut text, "Acceptance rate", format!("{rate} records/s"));
        field(
            &mut text,
            "Estimated exhaustion",
            duration(s.estimated_seconds_to_exhaustion),
        );
        if let Some(audit) = s.audit.as_option() {
            field(
                &mut text,
                "Audit",
                format!(
                    "{} ({} / {} rows scanned)",
                    state(audit.state, "OPERATION_LEDGER_AUDIT_"),
                    count(audit.scanned),
                    count(audit.total)
                ),
            );
        }
    }
    if let Some(s) = s.delivery_capacity.as_option() {
        text.push_str("\nDELIVERY:\n");
        field(
            &mut text,
            "Pending",
            format!("{} / {}", count(s.pending), count(s.hard_limit)),
        );
        field(&mut text, "Profile boundary", count(s.profile_boundary));
        field(&mut text, "Profile saturated", yes_no(s.profile_saturated));
    }
    if let Some(s) = s.blob_capacity.as_option() {
        text.push_str("\nBLOB CAPACITY (OBSERVED PREFLIGHT):\n");
        field(
            &mut text,
            "Reserved bytes",
            format!("{} / {}", size(s.reserved_bytes), size(s.byte_limit)),
        );
        field(
            &mut text,
            "Byte remaining",
            size(s.byte_limit.saturating_sub(s.reserved_bytes)),
        );
        field(
            &mut text,
            "Variants",
            format!("{} / {}", count(s.variants), count(s.variant_limit)),
        );
        field(
            &mut text,
            "Variant remaining",
            count(s.variant_limit.saturating_sub(s.variants)),
        );
        field(
            &mut text,
            "Expected chunks",
            format!("{} / {}", count(s.expected_chunks), count(s.chunk_limit)),
        );
        field(
            &mut text,
            "Chunk remaining",
            count(s.chunk_limit.saturating_sub(s.expected_chunks)),
        );
        field(&mut text, "Pending sources", count(s.pending_sources));
        field(&mut text, "Network staging", size(s.network_staging_bytes));
        field(&mut text, "Bytes exhausted", yes_no(s.bytes_exhausted));
        field(
            &mut text,
            "Variants exhausted",
            yes_no(s.variants_exhausted),
        );
        field(&mut text, "Chunks exhausted", yes_no(s.chunks_exhausted));
    }
    text
}

pub(super) fn publish_blob(blob: &api::PublishBlobReceipt, operation_key: &str) -> String {
    let mut text = String::from("BLOB:\n");
    field(&mut text, "ID", scalar(Bytes(&blob.id)));
    field(
        &mut text,
        "Publication ID",
        scalar(Bytes(&blob.publication_id)),
    );
    field(
        &mut text,
        "Operation key",
        operation_key.escape_default().to_string(),
    );
    field(&mut text, "Publisher", scalar(Bytes(&blob.publisher)));
    field(
        &mut text,
        "Publisher counter",
        count(blob.publisher_counter),
    );
    field(&mut text, "Priority", state(blob.priority, "PRIORITY_"));
    field(
        &mut text,
        "Total length",
        format!("{} bytes", blob.total_len),
    );
    if let Some(media_type) = &blob.media_type {
        field(&mut text, "Media type", format!("{media_type:?}"));
    }
    field(&mut text, "Schema ID", scalar(Bytes(&blob.schema_id)));
    field(
        &mut text,
        "Acceptance marker",
        count(blob.acceptance_marker),
    );
    field(&mut text, "Inserted", yes_no(blob.inserted));
    writeln!(text, "  TTL: {}", blob_ttl(blob.ttl_ms)).expect("write to string");
    text
}

pub(super) fn blob_status(status: &api::InspectBlobPublicationResponse) -> String {
    let mut text = String::from("BLOB PUBLICATION:\n");
    field(
        &mut text,
        "Publication ID",
        scalar(Bytes(&status.publication_id)),
    );
    field(
        &mut text,
        "State",
        state(status.phase, "BLOB_PUBLICATION_PHASE_"),
    );
    field(
        &mut text,
        "Plaintext bytes",
        format!(
            "{} / {} bytes",
            count(status.durable_plaintext_bytes),
            count(status.plaintext_total_bytes)
        ),
    );
    field(
        &mut text,
        "Authenticated transfer bytes",
        format!(
            "{} / {} bytes",
            count(status.durable_transfer_bytes),
            count(status.transfer_total_bytes)
        ),
    );
    field(
        &mut text,
        "Durable units",
        format!(
            "{} / {}",
            count(status.durable_units),
            count(status.total_units)
        ),
    );
    if let Some(blob_id) = &status.blob_id {
        field(&mut text, "Blob ID", scalar(Bytes(blob_id)));
    }
    text
}

pub(super) fn read_blob(blob: &blob_read::Metadata) -> String {
    let mut text = String::from("BLOB:\n");
    field(&mut text, "ID", scalar(Bytes(&blob.id)));
    field(&mut text, "Publisher", scalar(Bytes(&blob.publisher)));
    field(
        &mut text,
        "Publisher counter",
        count(blob.publisher_counter),
    );
    field(&mut text, "Topic", format!("{:?}", blob.topic));
    field(&mut text, "Scope", format!("{:?}", blob.scope));
    field(&mut text, "Priority", state(blob.priority, "PRIORITY_"));
    field(
        &mut text,
        "Total length",
        format!("{} bytes", blob.total_len),
    );
    if let Some(media_type) = &blob.media_type {
        field(&mut text, "Media type", format!("{media_type:?}"));
    }
    field(&mut text, "Schema ID", scalar(Bytes(&blob.schema_id)));
    field(
        &mut text,
        "Acceptance marker",
        count(blob.acceptance_marker),
    );
    writeln!(text, "  TTL: {}", blob_ttl(blob.ttl_ms)).expect("write to string");
    text
}

fn blob_ttl(ttl_ms: Option<u64>) -> String {
    match ttl_ms {
        None => "durable".to_owned(),
        Some(ttl_ms) => format!("{ttl_ms} ms"),
    }
}

pub(super) fn event(event: &api::Event) -> String {
    let mut text = String::from("EVENT:\n");
    field(&mut text, "ID", scalar(Bytes(&event.id)));
    field(&mut text, "Publisher", scalar(Bytes(&event.publisher)));
    field(
        &mut text,
        "Publisher counter",
        count(event.publisher_counter),
    );
    field(&mut text, "Event sequence", count(event.event_sequence));
    field(&mut text, "Topic", format!("{:?}", event.topic));
    field(&mut text, "Scope", format!("{:?}", event.scope));
    field(&mut text, "Priority", state(event.priority, "PRIORITY_"));
    bytes_field(&mut text, "Logical key", &event.logical_key);
    bytes_field(&mut text, "Payload", &event.payload);
    field(&mut text, "Tombstone", yes_no(event.tombstone));
    field(
        &mut text,
        "Acceptance marker",
        count(event.acceptance_marker),
    );
    field(&mut text, "TTL", ttl(event.ttl_ms));
    text
}

pub(super) fn subscription(subscription: &api::EventSubscription) -> String {
    let mut text = String::from("SUBSCRIPTION:\n");
    field(
        &mut text,
        "ID",
        scalar(Bytes(&subscription.subscription_id)),
    );
    field(&mut text, "Topic", format!("{:?}", subscription.topic));
    let scope = if subscription.include_descendant_scopes {
        format!("{}/*", subscription.scope)
    } else {
        subscription.scope.clone()
    };
    field(&mut text, "Scope", format!("{scope:?}"));
    bytes_field(&mut text, "Operation key", &subscription.operation_key);
    text
}

fn bytes_field(text: &mut String, label: &str, value: &[u8]) {
    match std::str::from_utf8(value) {
        Ok(value) => field(text, label, format!("{value:?}")),
        Err(_) => field(text, &format!("{label} (Base64)"), scalar(Bytes(value))),
    }
}

fn ttl(ttl_ms: Option<u64>) -> String {
    match ttl_ms {
        None => "None".to_owned(),
        Some(ms) if ms < 1000 => format!("{ms} ms"),
        Some(ms) if ms % 1000 == 0 => duration(ms / 1000),
        Some(ms) => format!("{} {}ms", duration(ms / 1000), ms % 1000),
    }
}

fn field(text: &mut String, label: &str, value: impl Display) {
    let label = format!("{label}:");
    if label.len() >= 25 {
        writeln!(text, "  {label} {value}").expect("write to string");
    } else {
        writeln!(text, "  {label:<25}{value}").expect("write to string");
    }
}

fn scalar(value: impl serde::Serialize) -> String {
    match serde_json::to_value(value).expect("status scalar") {
        serde_json::Value::String(s) => s,
        value => value.to_string(),
    }
}

fn state<E: Enumeration>(value: EnumValue<E>, prefix: &str) -> String {
    let Some(known) = value.as_known() else {
        return format!("Unknown ({})", value.to_i32());
    };
    let name = known.proto_name();
    let name = name.strip_prefix(prefix).unwrap_or(name);
    if name == "OK" {
        return name.to_owned();
    }
    let mut name = name.to_ascii_lowercase().replace('_', " ");
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    name
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{} B", count(bytes));
    }
    // Round to hundredths with integer arithmetic, including near u64::MAX.
    let bytes = u128::from(bytes);
    let mut unit = 1;
    let mut divisor = 1024;
    loop {
        let hundredths = (bytes * 100 + divisor / 2) / divisor;
        if hundredths >= 102_400 && unit + 1 < UNITS.len() {
            divisor *= 1024;
            unit += 1;
            continue;
        }
        let number = format!("{}.{:02}", hundredths / 100, hundredths % 100);
        return format!(
            "{} {}",
            number.trim_end_matches('0').trim_end_matches('.'),
            UNITS[unit]
        );
    }
}

fn duration(mut seconds: u64) -> String {
    if seconds == 0 {
        return "0 s".to_owned();
    }
    let mut parts = Vec::new();
    for (unit, suffix) in [(86400, "d"), (3600, "h"), (60, "m"), (1, "s")] {
        let value = seconds / unit;
        seconds %= unit;
        if value > 0 {
            parts.push(format!("{}{suffix}", count(value)));
        }
    }
    parts.join(" ")
}
