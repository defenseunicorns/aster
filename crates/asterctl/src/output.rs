use crate::{api, blob_read};
use serde::{Serialize, ser::SerializeMap};
use serde_json::Value;
use std::io::{self, Write};

mod text;

type Fields = Vec<(&'static str, Output)>;

// Keep display order local to this binary. Enabling serde_json/preserve_order
// would also change the JSON output of other workspace packages.
enum Output {
    Object(Fields),
    Array(Vec<Output>),
    Scalar(Value),
}

impl Serialize for Output {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (name, value) in fields {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
            Self::Array(items) => items.serialize(serializer),
            Self::Scalar(value) => value.serialize(serializer),
        }
    }
}

macro_rules! fields {
    ($($name:literal: $value:expr),* $(,)?) => {
        vec![$(($name, Output::Scalar(serde_json::to_value($value).expect("RPC scalar")))),*]
    };
}

#[derive(Serialize)]
struct Bytes<'a>(#[serde(with = "buffa::json_helpers::bytes")] &'a [u8]);

#[derive(Serialize)]
struct Double(#[serde(with = "buffa::json_helpers::double")] f64);

pub fn status(response: &api::GetStatusResponse, json: bool) -> Result<String, serde_json::Error> {
    if json {
        Ok(serde_json::to_string_pretty(&Output::Object(status_fields(response)))? + "\n")
    } else {
        Ok(text::status(response))
    }
}

pub fn numbered_publish_response(
    response: &api::PublishNumberedEventResponse,
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(response).map(|text| text + "\n");
    }
    numbered_publication(
        response.result.as_option().expect("validated result"),
        false,
    )
}

pub fn numbered_publication(
    result: &api::CommittedPublicationResult,
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(result).map(|text| text + "\n");
    }
    let receipt = result.receipt.as_option().expect("validated receipt");
    let event_id = serde_json::to_value(Bytes(&receipt.event_id))?;
    let content = match result.content.as_known() {
        Some(api::CommittedContentStatus::Available) => "Available",
        Some(api::CommittedContentStatus::Retired) => "Retired",
        _ => "Unknown",
    };
    Ok(format!(
        "EVENT:\nCommitted locally\nOperation sequence: {}\nEvent ID (Base64): {}\nAcceptance marker: {}\nContent: {}\nAcknowledge after applying this result with publication-ack.\n",
        result.operation_sequence,
        event_id.as_str().expect("Base64 Event ID"),
        receipt.acceptance_marker,
        content
    ))
}

pub fn publish_blob(
    response: &api::PublishBlobReceipt,
    operation_key: &str,
    json: bool,
) -> Result<String, serde_json::Error> {
    if !json {
        return Ok(text::publish_blob(response, operation_key));
    }
    let mut fields = fields! {
        "id": Bytes(&response.id),
        "publicationId": Bytes(&response.publication_id),
        "publisher": Bytes(&response.publisher),
        "publisherCounter": response.publisher_counter.to_string(),
        "priority": response.priority,
        "totalLen": response.total_len.to_string(),
        "schemaId": Bytes(&response.schema_id),
        "acceptanceMarker": response.acceptance_marker.to_string(),
        "inserted": response.inserted,
        "operation_key": operation_key,
    };
    if let Some(media_type) = &response.media_type {
        fields.push((
            "mediaType",
            Output::Scalar(Value::String(media_type.clone())),
        ));
    }
    if let Some(ttl_ms) = response.ttl_ms {
        fields.extend(fields! { "ttlMs": ttl_ms.to_string() });
    }
    Ok(serde_json::to_string_pretty(&Output::Object(fields))? + "\n")
}

pub fn blob_status(
    response: &api::InspectBlobPublicationResponse,
    json: bool,
) -> Result<String, serde_json::Error> {
    if !json {
        return Ok(text::blob_status(response));
    }
    let mut value = fields! {
        "publicationId": Bytes(&response.publication_id),
        "phase": response.phase,
        "plaintextTotalBytes": response.plaintext_total_bytes.to_string(),
        "durablePlaintextBytes": response.durable_plaintext_bytes.to_string(),
        "transferTotalBytes": response.transfer_total_bytes.to_string(),
        "durableTransferBytes": response.durable_transfer_bytes.to_string(),
        "totalUnits": response.total_units.to_string(),
        "durableUnits": response.durable_units.to_string(),
    };
    if let Some(blob_id) = &response.blob_id {
        value.push((
            "blobId",
            Output::Scalar(serde_json::to_value(Bytes(blob_id))?),
        ));
    }
    Ok(serde_json::to_string_pretty(&Output::Object(value))? + "\n")
}

pub fn read_blob(metadata: &blob_read::Metadata, json: bool) -> Result<String, serde_json::Error> {
    if !json {
        return Ok(text::read_blob(metadata));
    }
    let mut fields = fields! {
        "id": Bytes(&metadata.id),
        "publisher": Bytes(&metadata.publisher),
        "publisherCounter": metadata.publisher_counter.to_string(),
        "topic": &metadata.topic,
        "scope": &metadata.scope,
        "priority": metadata.priority,
        "totalLen": metadata.total_len.to_string(),
        "schemaId": Bytes(&metadata.schema_id),
        "acceptanceMarker": metadata.acceptance_marker.to_string(),
    };
    if let Some(media_type) = &metadata.media_type {
        fields.push((
            "mediaType",
            Output::Scalar(Value::String(media_type.clone())),
        ));
    }
    if let Some(ttl_ms) = metadata.ttl_ms {
        fields.extend(fields! { "ttlMs": ttl_ms.to_string() });
    }
    Ok(serde_json::to_string_pretty(&Output::Object(fields))? + "\n")
}

pub fn subscribe(
    response: &api::CreateEventSubscriptionResponse,
    operation_key: &str,
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        let fields = fields! {
            "subscriptionId": Bytes(&response.subscription_id),
            "inserted": response.inserted,
            "operation_key": operation_key,
        };
        Ok(serde_json::to_string_pretty(&Output::Object(fields))? + "\n")
    } else {
        let id = serde_json::to_value(Bytes(&response.subscription_id))?;
        Ok(format!(
            "{}\n",
            id.as_str().expect("Base64 subscription ID")
        ))
    }
}

pub fn unsubscribe(
    response: &api::DeleteEventSubscriptionResponse,
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        Ok(serde_json::to_string_pretty(&Output::Object(fields! {
            "alreadyAbsent": response.already_absent,
        }))? + "\n")
    } else if response.already_absent {
        Ok("Subscription already absent\n".to_owned())
    } else {
        Ok("Subscription removed\n".to_owned())
    }
}

pub fn subscriptions(
    response: &api::ListEventSubscriptionsResponse,
    json: bool,
) -> Result<String, serde_json::Error> {
    Ok(if json {
        let rows = response
            .subscriptions
            .iter()
            .map(|row| {
                Output::Object(fields! {
                    "subscriptionId": Bytes(&row.subscription_id),
                    "topic": &row.topic,
                    "scope": &row.scope,
                    "includeDescendantScopes": row.include_descendant_scopes,
                    "operationKey": Bytes(&row.operation_key),
                })
            })
            .collect();
        serde_json::to_string_pretty(&Output::Array(rows))? + "\n"
    } else {
        response
            .subscriptions
            .iter()
            .map(text::subscription)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

pub struct QueryWriter<W> {
    writer: W,
    json: bool,
    started: bool,
}

impl<W: Write> QueryWriter<W> {
    pub fn new(writer: W, json: bool) -> Self {
        Self {
            writer,
            json,
            started: false,
        }
    }

    pub fn event(&mut self, event: &api::Event) -> io::Result<()> {
        if self.json {
            if self.started {
                self.writer.write_all(b",\n")?;
            } else {
                self.writer.write_all(b"[\n")?;
            }
            let json = serde_json::to_string_pretty(&Output::Object(event_fields(event)))
                .map_err(io::Error::other)?;
            for (index, line) in json.lines().enumerate() {
                if index > 0 {
                    self.writer.write_all(b"\n")?;
                }
                self.writer.write_all(b"  ")?;
                self.writer.write_all(line.as_bytes())?;
            }
        } else {
            if self.started {
                self.writer.write_all(b"\n")?;
            }
            self.writer.write_all(text::event(event).as_bytes())?;
        }
        self.started = true;
        self.writer.flush()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.json {
            self.writer
                .write_all(if self.started { b"\n]\n" } else { b"[]\n" })?;
        }
        self.writer.flush()
    }
}

fn event_fields(event: &api::Event) -> Fields {
    let mut fields = fields! {
        "id": Bytes(&event.id),
        "publisher": Bytes(&event.publisher),
        "publisherCounter": event.publisher_counter.to_string(),
        "eventSequence": event.event_sequence.to_string(),
        "topic": &event.topic,
        "scope": &event.scope,
        "priority": event.priority,
        "logicalKey": Bytes(&event.logical_key),
        "payload": Bytes(&event.payload),
        "tombstone": event.tombstone,
        "acceptanceMarker": event.acceptance_marker.to_string(),
    };
    if let Some(ttl_ms) = event.ttl_ms {
        fields.extend(fields! { "ttlMs": ttl_ms.to_string() });
    }
    fields
}

// buffa's generated Serialize implementation omits scalar defaults. List the
// status fields explicitly so zero/false values are always visible, while
// preserving message presence and the library's enum/bytes/double encodings.
fn status_fields(s: &api::GetStatusResponse) -> Fields {
    let mut value = fields! {
        "identity": Bytes(&s.identity),
        "missionAuthority": Bytes(&s.mission_authority),
        "sync": s.sync,
        "authenticatedContacts": s.authenticated_contacts.to_string(),
        "failedContactAttempts": s.failed_contact_attempts.to_string(),
    };
    value.push((
        "peers",
        Output::Array(
            s.peers
                .iter()
                .map(|p| {
                    Output::Object(fields! {
                        "peer": Bytes(&p.peer),
                        "authorization": p.authorization,
                        "authenticatedContacts": p.authenticated_contacts.to_string(),
                        "lastContact": p.last_contact,
                    })
                })
                .collect(),
        ),
    ));
    value.extend(fields! {
        "configuredEmissionMode": s.configured_emission_mode,
        "effectiveEmissionMode": s.effective_emission_mode,
    });
    if let Some(s) = s.store_capacity.as_option() {
        value.push(("storeCapacity", Output::Object(fields! {
            "items": s.items.to_string(), "itemLimit": s.item_limit.to_string(),
            "payloadBytes": s.payload_bytes.to_string(), "payloadByteLimit": s.payload_byte_limit.to_string(),
        })));
    }
    if let Some(s) = s.publish_operation_capacity.as_option() {
        let mut capacity = fields! {
            "rows": s.rows.to_string(), "bytes": s.bytes.to_string(),
            "rowHardLimit": s.row_hard_limit.to_string(), "byteHardLimit": s.byte_hard_limit.to_string(),
            "profileBoundary": s.profile_boundary.to_string(), "profileRemaining": s.profile_remaining.to_string(),
            "profileWarning": s.profile_warning, "profileExhausted": s.profile_exhausted,
            "activeRows": s.active_rows.to_string(), "retiredRows": s.retired_rows.to_string(),
            "reverseRows": s.reverse_rows.to_string(), "ordinaryRemaining": s.ordinary_remaining.to_string(),
            "emergencyRemaining": s.emergency_remaining.to_string(), "rollingAcceptRate": Double(s.rolling_accept_rate),
            "estimatedSecondsToExhaustion": s.estimated_seconds_to_exhaustion.to_string(),
            "warningState": s.warning_state,
        };
        if let Some(audit) = s.audit.as_option() {
            capacity.push(("audit", Output::Object(fields! {
                "state": audit.state, "scanned": audit.scanned.to_string(), "total": audit.total.to_string(),
            })));
        }
        value.push(("publishOperationCapacity", Output::Object(capacity)));
    }
    if let Some(s) = s.delivery_capacity.as_option() {
        value.push((
            "deliveryCapacity",
            Output::Object(fields! {
                "pending": s.pending.to_string(), "profileBoundary": s.profile_boundary.to_string(),
                "profileSaturated": s.profile_saturated, "hardLimit": s.hard_limit.to_string(),
            }),
        ));
    }
    if let Some(s) = s.blob_capacity.as_option() {
        value.push((
            "blobCapacity",
            Output::Object(fields! {
                "reservedBytes": s.reserved_bytes.to_string(),
                "byteLimit": s.byte_limit.to_string(),
                "byteRemaining": s.byte_limit.saturating_sub(s.reserved_bytes).to_string(),
                "variants": s.variants.to_string(),
                "variantLimit": s.variant_limit.to_string(),
                "variantRemaining": s.variant_limit.saturating_sub(s.variants).to_string(),
                "expectedChunks": s.expected_chunks.to_string(),
                "chunkLimit": s.chunk_limit.to_string(),
                "chunkRemaining": s.chunk_limit.saturating_sub(s.expected_chunks).to_string(),
                "pendingSources": s.pending_sources.to_string(),
                "networkStagingBytes": s.network_staging_bytes.to_string(),
                "bytesExhausted": s.bytes_exhausted,
                "variantsExhausted": s.variants_exhausted,
                "chunksExhausted": s.chunks_exhausted,
            }),
        ));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Enumeration as _;
    use serde_json::{Value, json};

    fn fixture() -> Value {
        json!({
            "identity": "AAECAw==", "missionAuthority": "/+4=",
            "sync": "SYNC_STATUS_LAST_CONTACT_COMPLETE",
            "authenticatedContacts": "18446744073709551615", "failedContactAttempts": "0",
            "peers": [{"peer": "qg==", "authorization": "PEER_AUTHORIZATION_ACTIVE",
                "authenticatedContacts": "9007199254740993",
                "lastContact": "CONTACT_STATUS_COMPLETE_FOR_LAST_NEGOTIATED_CONTACT"}],
            "configuredEmissionMode": "EMISSION_MODE_NORMAL", "effectiveEmissionMode": "EMISSION_MODE_RECEIVE_ONLY",
            "storeCapacity": {"items": "0", "itemLimit": "100", "payloadBytes": "0", "payloadByteLimit": "4096"},
            "publishOperationCapacity": {
                "rows": "2", "bytes": "48", "rowHardLimit": "10000", "byteHardLimit": "65536",
                "profileBoundary": "1000", "profileRemaining": "998", "profileWarning": false,
                "profileExhausted": false, "activeRows": "2", "retiredRows": "0", "reverseRows": "0",
                "ordinaryRemaining": "9998", "emergencyRemaining": "100", "rollingAcceptRate": 1.25,
                "estimatedSecondsToExhaustion": "0", "warningState": "OPERATION_CAPACITY_WARNING_OK",
                "audit": {"state": "OPERATION_LEDGER_AUDIT_COMPLETE", "scanned": "2", "total": "2"}
            },
            "deliveryCapacity": {"pending": "0", "profileBoundary": "1000", "profileSaturated": false, "hardLimit": "10000"}
        })
    }

    #[test]
    fn numbered_receipt_output_preserves_commit_identity_and_retirement() {
        for content in [
            api::CommittedContentStatus::Available,
            api::CommittedContentStatus::Retired,
        ] {
            let result = api::CommittedPublicationResult {
                operation_sequence: u64::MAX,
                receipt: api::CommittedEventReceipt {
                    event_id: vec![1; 32],
                    transfer_id: vec![2; 32],
                    acceptance_marker: u64::MAX,
                    ..Default::default()
                }
                .into(),
                content: content.into(),
                retirement_reason: (content == api::CommittedContentStatus::Retired)
                    .then_some(api::RetirementReason::Expired.into()),
                ..Default::default()
            };
            let text = numbered_publication(&result, false).unwrap();
            assert!(text.contains("Committed locally"));
            assert!(text.contains("publication-ack"));
            let json: Value =
                serde_json::from_str(&numbered_publication(&result, true).unwrap()).unwrap();
            assert_eq!(json["operationSequence"], u64::MAX.to_string());
            assert_eq!(json["receipt"]["acceptanceMarker"], u64::MAX.to_string());
            assert_eq!(
                json["receipt"]["eventId"],
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
            );
            assert_eq!(
                json.get("retirementReason").is_some(),
                content == api::CommittedContentStatus::Retired
            );
        }
    }

    #[test]
    fn blob_metadata_output_uses_exact_ttl_and_never_contains_plaintext() {
        let response = api::PublishBlobReceipt {
            id: vec![1; 32],
            publication_id: vec![3; 32],
            publisher: vec![2; 32],
            publisher_counter: u64::MAX,
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(u64::MAX),
            total_len: 65_537,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            acceptance_marker: 9,
            inserted: true,
            ..Default::default()
        };
        let json: Value =
            serde_json::from_str(&publish_blob(&response, "blob-key", true).unwrap()).unwrap();
        assert_eq!(json["ttlMs"], u64::MAX.to_string());
        assert_eq!(json["totalLen"], "65537");
        assert_eq!(json["operation_key"], "blob-key");
        assert_eq!(
            json["publicationId"],
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
        );
        assert_eq!(json["inserted"], true);
        assert_eq!(json.get("chunk"), None);
        let text = publish_blob(&response, "blob-key", false).unwrap();
        assert!(
            text.lines()
                .any(|line| line == format!("  TTL: {} ms", u64::MAX))
        );
        assert_eq!(text_value(&text, "TTL"), format!("{} ms", u64::MAX));
        assert_eq!(text_value(&text, "Inserted"), "Yes");
        assert_eq!(text_value(&text, "Operation key"), "blob-key");
        assert_eq!(
            text_value(&text, "Publication ID"),
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
        );

        let metadata = blob_read::Metadata {
            id: response.id,
            publisher: response.publisher,
            publisher_counter: response.publisher_counter,
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: response.priority,
            ttl_ms: None,
            total_len: response.total_len,
            media_type: response.media_type,
            schema_id: response.schema_id,
            acceptance_marker: response.acceptance_marker,
        };
        let json: Value = serde_json::from_str(&read_blob(&metadata, true).unwrap()).unwrap();
        assert_eq!(json.get("ttlMs"), None);
        assert_eq!(json.get("chunk"), None);
        let text = read_blob(&metadata, false).unwrap();
        assert!(text.lines().any(|line| line == "  TTL: durable"));
        assert_eq!(text_value(&text, "TTL"), "durable");
    }

    #[test]
    fn blob_publish_text_escapes_operation_key_controls() {
        let response = api::PublishBlobReceipt {
            id: vec![1; 32],
            publication_id: vec![2; 32],
            publisher: vec![3; 32],
            priority: api::Priority::Routine.into(),
            ..Default::default()
        };
        let operation_key = "ok\nInjected: yes\u{1b}[2J";
        let text = publish_blob(&response, operation_key, false).unwrap();

        assert!(!text.contains("\nInjected: yes"));
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains(r#"ok\nInjected: yes\u{1b}[2J"#));
    }

    #[test]
    fn blob_status_text_names_transfer_byte_domain() {
        let response = api::InspectBlobPublicationResponse {
            publication_id: vec![4; 32],
            phase: api::BlobPublicationPhase::Receiving.into(),
            plaintext_total_bytes: 800,
            durable_plaintext_bytes: 400,
            transfer_total_bytes: 1_000,
            durable_transfer_bytes: 500,
            total_units: 10,
            durable_units: 5,
            ..Default::default()
        };
        let text = blob_status(&response, false).unwrap();
        assert_eq!(text_value(&text, "Plaintext bytes"), "400 / 800 bytes");
        assert_eq!(
            text_value(&text, "Authenticated transfer bytes"),
            "500 / 1,000 bytes"
        );
    }

    #[test]
    fn blob_status_json_is_stable_for_all_states() {
        for phase in [
            api::BlobPublicationPhase::Missing,
            api::BlobPublicationPhase::AwaitingData,
            api::BlobPublicationPhase::Receiving,
            api::BlobPublicationPhase::ReadyToFinalize,
            api::BlobPublicationPhase::Available,
            api::BlobPublicationPhase::ExpiredOrRetired,
        ] {
            let response = api::InspectBlobPublicationResponse {
                publication_id: vec![4; 32],
                phase: phase.into(),
                plaintext_total_bytes: 8,
                durable_plaintext_bytes: 4,
                transfer_total_bytes: 10,
                durable_transfer_bytes: 5,
                total_units: 2,
                durable_units: 1,
                blob_id: (phase == api::BlobPublicationPhase::Available).then(|| vec![5; 32]),
                ..Default::default()
            };
            let value: Value =
                serde_json::from_str(&blob_status(&response, true).unwrap()).unwrap();
            assert_eq!(
                value["publicationId"],
                "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
            );
            assert_eq!(value["phase"], phase.proto_name());
            assert_eq!(value["plaintextTotalBytes"], "8");
            assert_eq!(value["durablePlaintextBytes"], "4");
            assert_eq!(value["transferTotalBytes"], "10");
            assert_eq!(value["durableTransferBytes"], "5");
            assert_eq!(value["totalUnits"], "2");
            assert_eq!(value["durableUnits"], "1");
            assert_eq!(
                value.get("blobId").is_some(),
                phase == api::BlobPublicationPhase::Available
            );
        }
    }

    #[test]
    fn blob_status_missing_snapshot_succeeds() {
        let response = api::InspectBlobPublicationResponse {
            publication_id: vec![6; 32],
            phase: api::BlobPublicationPhase::Missing.into(),
            ..Default::default()
        };
        assert!(blob_status(&response, false).unwrap().contains("Missing"));
        assert!(blob_status(&response, true).is_ok());
    }

    #[test]
    fn status_capacity_uses_saturating_remaining_values() {
        let response = api::GetStatusResponse {
            blob_capacity: api::BlobCapacityStatus {
                reserved_bytes: u64::MAX,
                byte_limit: 1,
                variants: 5,
                variant_limit: 3,
                expected_chunks: 7,
                chunk_limit: 0,
                bytes_exhausted: true,
                variants_exhausted: true,
                chunks_exhausted: true,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let value: Value = serde_json::from_str(&status(&response, true).unwrap()).unwrap();
        assert_eq!(value["blobCapacity"]["byteRemaining"], "0");
        assert_eq!(value["blobCapacity"]["variantRemaining"], "0");
        assert_eq!(value["blobCapacity"]["chunkRemaining"], "0");
        let text = status(&response, false).unwrap();
        assert!(text.contains("BLOB CAPACITY (OBSERVED PREFLIGHT):"));
        assert_eq!(text_value(&text, "Byte remaining"), "0 B");
    }

    #[test]
    fn json_preserves_every_field_type_and_exact_value() {
        let expected = fixture();
        let response: api::GetStatusResponse = serde_json::from_value(expected.clone()).unwrap();
        let output = status(&response, true).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&output).unwrap(), expected);
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn text_groups_all_fields_and_formats_values_for_people() {
        let response: api::GetStatusResponse = serde_json::from_value(fixture()).unwrap();
        assert_eq!(
            status(&response, false).unwrap(),
            include_str!("../tests/status.txt")
        );
    }

    #[test]
    fn scalar_defaults_are_visible_but_absent_messages_remain_absent() {
        let value: Value =
            serde_json::from_str(&status(&api::GetStatusResponse::default(), true).unwrap())
                .unwrap();
        assert_eq!(
            value,
            json!({
                "identity": "", "missionAuthority": "", "sync": "SYNC_STATUS_UNSPECIFIED",
                "authenticatedContacts": "0", "failedContactAttempts": "0", "peers": [],
                "configuredEmissionMode": "EMISSION_MODE_UNSPECIFIED", "effectiveEmissionMode": "EMISSION_MODE_UNSPECIFIED"
            })
        );
        let text = status(&api::GetStatusResponse::default(), false).unwrap();
        assert!(text.contains("PEERS (0):\n"));
        for section in ["STORAGE:", "PUBLICATION OPERATIONS:", "DELIVERY:"] {
            assert!(!text.contains(section));
        }
    }

    #[test]
    fn empty_present_messages_keep_defaults_and_unknown_enums_keep_numbers() {
        let response: api::GetStatusResponse = serde_json::from_value(json!({
            "sync": 123, "storeCapacity": {}, "publishOperationCapacity": {"audit": {}},
            "deliveryCapacity": {}, "peers": [{"authorization": 99}]
        }))
        .unwrap();
        let value: Value = serde_json::from_str(&status(&response, true).unwrap()).unwrap();
        assert_eq!(value["sync"], 123);
        assert_eq!(value["storeCapacity"]["items"], "0");
        assert_eq!(value["peers"][0]["authorization"], 99);
        assert_eq!(value["peers"][0]["authenticatedContacts"], "0");
        assert_eq!(value["publishOperationCapacity"]["rollingAcceptRate"], 0.0);
        assert_eq!(
            value["publishOperationCapacity"]["audit"]["state"],
            "OPERATION_LEDGER_AUDIT_UNSPECIFIED"
        );
        assert_eq!(value["deliveryCapacity"]["profileSaturated"], false);
        let text = status(&response, false).unwrap();
        assert_eq!(text_value(&text, "Sync"), "Unknown (123)");
        assert_eq!(text_value(&text, "Authorization"), "Unknown (99)");
        assert_eq!(text_value(&text, "Payload"), "0 B / 0 B");
        assert_eq!(text_value(&text, "Profile warning"), "No");
        assert_eq!(
            text_value(&text, "Audit"),
            "Unspecified (0 / 0 rows scanned)"
        );
    }

    #[test]
    fn nonfinite_doubles_follow_protojson() {
        for name in ["NaN", "Infinity", "-Infinity"] {
            let response: api::GetStatusResponse = serde_json::from_value(json!({
                "publishOperationCapacity": {"rollingAcceptRate": name}
            }))
            .unwrap();
            let value: Value = serde_json::from_str(&status(&response, true).unwrap()).unwrap();
            assert_eq!(value["publishOperationCapacity"]["rollingAcceptRate"], name);
            let text = status(&response, false).unwrap();
            assert_eq!(
                text_value(&text, "Acceptance rate"),
                format!("{name} records/s")
            );
        }
    }

    fn text_value<'a>(text: &'a str, label: &str) -> &'a str {
        text.lines()
            .find_map(|line| line.trim_start().strip_prefix(&format!("{label}:")))
            .expect("displayed field")
            .trim()
    }

    #[test]
    fn text_formats_binary_sizes_and_durations_at_boundaries_without_overflow() {
        for (bytes, expected) in [
            (0, "0 B"),
            (1, "1 B"),
            (1023, "1,023 B"),
            (1024, "1 KiB"),
            (1536, "1.5 KiB"),
            (1_048_575, "1 MiB"),
            (1_048_576, "1 MiB"),
            (1_572_864, "1.5 MiB"),
            (1_073_741_824, "1 GiB"),
            (1_099_511_627_776, "1 TiB"),
            (1_125_899_906_842_624, "1 PiB"),
            (1_152_921_504_606_846_976, "1 EiB"),
            (u64::MAX, "16 EiB"),
        ] {
            let response: api::GetStatusResponse = serde_json::from_value(json!({
                "storeCapacity": {"payloadBytes": bytes.to_string()}
            }))
            .unwrap();
            let text = status(&response, false).unwrap();
            assert_eq!(text_value(&text, "Payload"), format!("{expected} / 0 B"));
        }
        for (seconds, expected) in [
            (0, "0 s"),
            (1, "1s"),
            (59, "59s"),
            (60, "1m"),
            (65, "1m 5s"),
            (3599, "59m 59s"),
            (3600, "1h"),
            (7200, "2h"),
            (86400, "1d"),
            (90061, "1d 1h 1m 1s"),
            (u64::MAX, "213,503,982,334,601d 7h 15s"),
        ] {
            let response: api::GetStatusResponse = serde_json::from_value(json!({
                "publishOperationCapacity": {"estimatedSecondsToExhaustion": seconds.to_string()}
            }))
            .unwrap();
            let text = status(&response, false).unwrap();
            assert_eq!(text_value(&text, "Estimated exhaustion"), expected);
        }
    }

    #[test]
    fn text_keeps_peers_separate_full_identities_and_positive_flags_visible() {
        let identity = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let response: api::GetStatusResponse = serde_json::from_value(json!({
            "identity": identity, "sync": "SYNC_STATUS_WORK_REMAINED",
            "peers": [
                {"peer": "qg==", "authorization": "PEER_AUTHORIZATION_ACTIVE"},
                {"peer": "uw==", "authorization": "PEER_AUTHORIZATION_REVOKED",
                    "lastContact": "CONTACT_STATUS_POLICY_CHANGED_SINCE_CONTACT"}
            ],
            "publishOperationCapacity": {
                "profileWarning": true, "profileExhausted": true,
                "warningState": "OPERATION_CAPACITY_WARNING_EXHAUSTED", "rollingAcceptRate": 0.000001
            },
            "deliveryCapacity": {"profileSaturated": true}
        })).unwrap();
        let text = status(&response, false).unwrap();
        assert_eq!(text_value(&text, "Identity"), identity);
        assert_eq!(text_value(&text, "Sync"), "Work remained");
        let peers = text
            .split_once("PEERS (2):\n")
            .unwrap()
            .1
            .split_once("\nPUBLICATION OPERATIONS:")
            .unwrap()
            .0;
        let peers: Vec<_> = peers.trim_end().split("\n\n").collect();
        assert_eq!(peers.len(), 2);
        assert_eq!(text_value(peers[0], "Identity"), "qg==");
        assert_eq!(text_value(peers[0], "Authorization"), "Active");
        assert_eq!(text_value(peers[1], "Identity"), "uw==");
        assert_eq!(text_value(peers[1], "Authorization"), "Revoked");
        assert_eq!(
            text_value(peers[1], "Last contact"),
            "Policy changed since contact"
        );
        for label in ["Profile warning", "Profile exhausted", "Profile saturated"] {
            assert_eq!(text_value(&text, label), "Yes");
        }
        assert_eq!(text_value(&text, "Capacity state"), "Exhausted");
        assert_eq!(text_value(&text, "Acceptance rate"), "0.000001 records/s");
        assert!(!text.contains("  Audit:"));
    }
}
