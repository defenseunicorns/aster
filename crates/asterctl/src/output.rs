use crate::api;
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

pub fn publish(
    response: &api::PublishEventResponse,
    operation_key: &str,
    json: bool,
) -> Result<String, serde_json::Error> {
    if !json {
        return Ok(text::publish(response));
    }
    let mut fields = fields! {
        "id": Bytes(&response.id),
        "publisher": Bytes(&response.publisher),
        "publisherCounter": response.publisher_counter.to_string(),
        "eventSequence": response.event_sequence.to_string(),
        "priority": response.priority,
        "acceptanceMarker": response.acceptance_marker.to_string(),
        "inserted": response.inserted,
        "operation_key": operation_key,
    };
    if let Some(ttl_ms) = response.ttl_ms {
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
    value
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn publication_receipts_preserve_scalar_defaults_unknown_enums_and_ttl_precision() {
        for (ttl_ms, display) in [
            (None, "None"),
            (Some(1), "1 ms"),
            (Some(999), "999 ms"),
            (Some(1000), "1s"),
            (Some(30001), "30s 1ms"),
            (Some(u64::MAX), "213,503,982,334d 14h 25m 51s 615ms"),
        ] {
            let receipt = api::PublishEventResponse {
                ttl_ms,
                priority: 123.into(),
                ..Default::default()
            };
            let text = publish(&receipt, "test", false).unwrap();
            assert_eq!(text_value(&text, "TTL"), display);
            assert_eq!(text_value(&text, "Priority"), "Unknown (123)");
            assert_eq!(text_value(&text, "Result"), "Already published");
            let json: Value =
                serde_json::from_str(&publish(&receipt, "test", true).unwrap()).unwrap();
            assert_eq!(json["publisherCounter"], "0");
            assert_eq!(json["eventSequence"], "0");
            assert_eq!(json["acceptanceMarker"], "0");
            assert_eq!(json["id"], "");
            assert_eq!(json["publisher"], "");
            assert_eq!(json["priority"], 123);
            assert_eq!(json["inserted"], false);
            assert_eq!(
                json.get("ttlMs").cloned(),
                ttl_ms.map(|ms| json!(ms.to_string()))
            );
        }
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
