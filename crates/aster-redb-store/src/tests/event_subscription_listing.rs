use super::*;

pub(super) fn assert_listing_does_not_mutate_delivery(store: &Store) {
    let image = || {
        let read = store.database.begin_read().unwrap();
        let rows = [
            EVENT_SUBSCRIPTIONS,
            EVENT_SUBSCRIPTION_PENDING,
            EVENT_DELIVERY_ACKNOWLEDGEMENTS,
        ]
        .into_iter()
        .map(|table| {
            read.open_table(table)
                .unwrap()
                .iter()
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.value().to_vec(), value.value().to_vec())
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
        let metadata = read
            .open_table(METADATA)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.value().to_owned(), value.value())
            })
            .collect::<Vec<_>>();
        (rows, metadata)
    };
    let before = image();
    let first = store.list_event_subscriptions().unwrap();
    assert_eq!(store.list_event_subscriptions().unwrap(), first);
    assert_eq!(
        image(),
        before,
        "listing must not change cursors, attempts, acknowledgements, or revisions"
    );
}

#[test]
fn list_event_subscriptions_preserves_distinct_binary_keys_excludes_carry_and_restarts() {
    let file = TestFile::new("list-event-subscriptions");
    let services = event_services(0x45);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    assert!(store.list_event_subscriptions().unwrap().is_empty());
    let carry = store
        .create_event_subscription_with_policy(
            &policy,
            &EventSubscriptionKey::new(b"carry".to_vec()).unwrap(),
            subscription_spec(EventSubscriptionMode::Carry),
        )
        .unwrap();
    assert!(store.list_event_subscriptions().unwrap().is_empty());
    let spec = EventSubscriptionSpec {
        mode: EventSubscriptionMode::Consume,
        topic: Topic::new("t".repeat(aster_profile::MAX_TOPIC_BYTES)).unwrap(),
        scope: Scope::new("s".repeat(aster_profile::MAX_SCOPE_BYTES)).unwrap(),
        include_descendant_scopes: true,
    };
    let mut expected = Vec::new();
    for index in 0..MAX_EVENT_SUBSCRIPTIONS - 1 {
        let mut bytes = vec![0xff; MAX_EVENT_SUBSCRIPTION_KEY_BYTES];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        let key = EventSubscriptionKey::new(bytes).unwrap();
        let created = store
            .create_event_subscription_with_policy(&policy, &key, spec.clone())
            .unwrap();
        assert!(created.inserted);
        let replay = store
            .create_event_subscription_with_policy(&policy, &key, spec.clone())
            .unwrap();
        assert!(!replay.inserted);
        assert_eq!(replay.id, created.id);
        expected.push(EventSubscriptionSnapshot {
            id: created.id,
            operation_key: key,
            spec: spec.clone(),
        });
    }
    expected.sort_by_key(|row| row.id);
    assert_eq!(store.list_event_subscriptions().unwrap(), expected);
    assert_listing_does_not_mutate_delivery(&store);
    store
        .remove_event_subscription_with_policy(&policy, carry.id)
        .unwrap();
    let key = EventSubscriptionKey::new(vec![0xfe; MAX_EVENT_SUBSCRIPTION_KEY_BYTES]).unwrap();
    let created = store
        .create_event_subscription_with_policy(&policy, &key, spec.clone())
        .unwrap();
    expected.push(EventSubscriptionSnapshot {
        id: created.id,
        operation_key: key,
        spec,
    });
    expected.sort_by_key(|row| row.id);
    assert_eq!(expected.len() as u64, MAX_EVENT_SUBSCRIPTIONS);
    assert_eq!(store.list_event_subscriptions().unwrap(), expected);
    drop(store);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    assert_eq!(store.list_event_subscriptions().unwrap(), expected);
    let policy = store.control_policy_snapshot().unwrap();
    let removed = expected.remove(0);
    store
        .remove_event_subscription_with_policy(&policy, removed.id)
        .unwrap();
    assert_eq!(store.list_event_subscriptions().unwrap(), expected);
}

#[test]
fn list_event_subscriptions_does_not_audit_unrelated_delivery_rows() {
    let file = TestFile::new("list-event-subscriptions-metadata-only");
    let services = event_services(0x45);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let key = EventSubscriptionKey::new(vec![0, 0xff, 0x80]).unwrap();
    let spec = subscription_spec(EventSubscriptionMode::Consume);
    let created = store
        .create_event_subscription_with_policy(&policy, &key, spec.clone())
        .unwrap();
    let expected = vec![EventSubscriptionSnapshot {
        id: created.id,
        operation_key: key,
        spec,
    }];
    // Deliberately poison each unrelated ledger: the full integrity audit must
    // reject it, but a bounded subscription metadata read must never decode it.
    for table in [EVENT_SUBSCRIPTION_PENDING, EVENT_DELIVERY_ACKNOWLEDGEMENTS] {
        let write = store.database.begin_write().unwrap();
        write
            .open_table(table)
            .unwrap()
            .insert(&b"invalid"[..], &b"invalid"[..])
            .unwrap();
        write.commit().unwrap();
        assert!(store.event_subscription_stats().is_err());
        assert_eq!(store.list_event_subscriptions().unwrap(), expected);
        let write = store.database.begin_write().unwrap();
        write
            .open_table(table)
            .unwrap()
            .remove(&b"invalid"[..])
            .unwrap();
        write.commit().unwrap();
    }
}

#[test]
fn list_event_subscriptions_validates_stored_mission_binding() {
    let file = TestFile::new("list-event-subscriptions-binding");
    let services = event_services(0x45);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    store
        .create_event_subscription_with_policy(
            &policy,
            &EventSubscriptionKey::new(b"bound".to_vec()).unwrap(),
            subscription_spec(EventSubscriptionMode::Consume),
        )
        .unwrap();
    let write = store.database.begin_write().unwrap();
    write
        .open_table(SEMANTIC_DOMAIN)
        .unwrap()
        .insert(MISSION_AUTHORITY_ID, &[0x99; 32][..])
        .unwrap();
    write.commit().unwrap();
    assert!(store.list_event_subscriptions().is_err());
}

#[test]
fn list_event_subscriptions_rejects_corrupt_rows_and_cursor_metadata() {
    for corruption in [
        "row",
        "id",
        "key",
        "cursor",
        "carry-cursor",
        "revision",
        "marker",
    ] {
        let file = TestFile::new("list-event-subscriptions-integrity");
        let services = event_services(0x45);
        let store = Store::open_for_mission(&file.0, services.authority).unwrap();
        let policy = store.control_policy_snapshot().unwrap();
        let key = EventSubscriptionKey::new(b"integrity".to_vec()).unwrap();
        let spec = subscription_spec(if corruption == "carry-cursor" {
            EventSubscriptionMode::Carry
        } else {
            EventSubscriptionMode::Consume
        });
        let created = store
            .create_event_subscription_with_policy(&policy, &key, spec.clone())
            .unwrap();
        let mut record = EventSubscriptionRecord {
            operation_key: key,
            spec,
            discovered_through: 0,
        };
        let write = store.database.begin_write().unwrap();
        match corruption {
            "row" => {
                write
                    .open_table(EVENT_SUBSCRIPTIONS)
                    .unwrap()
                    .insert(created.id.as_bytes().as_slice(), &b"invalid"[..])
                    .unwrap();
            }
            "id" => {
                let mut table = write.open_table(EVENT_SUBSCRIPTIONS).unwrap();
                table.remove(created.id.as_bytes().as_slice()).unwrap();
                table
                    .insert(
                        &b"invalid"[..],
                        encode_event_subscription_record(&record)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
            }
            "key" | "cursor" | "carry-cursor" => {
                if corruption == "key" {
                    record.operation_key =
                        EventSubscriptionKey::new(b"wrong-key".to_vec()).unwrap();
                } else {
                    record.discovered_through = 1;
                }
                if corruption == "carry-cursor" {
                    write
                        .open_table(METADATA)
                        .unwrap()
                        .insert(LAST_SEMANTIC_ACCEPTANCE_MARKER, 1)
                        .unwrap();
                }
                write
                    .open_table(EVENT_SUBSCRIPTIONS)
                    .unwrap()
                    .insert(
                        created.id.as_bytes().as_slice(),
                        encode_event_subscription_record(&record)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
            }
            "revision" => {
                write
                    .open_table(METADATA)
                    .unwrap()
                    .insert(EVENT_SELECTOR_REVISION, 2)
                    .unwrap();
            }
            "marker" => {
                write
                    .open_table(METADATA)
                    .unwrap()
                    .remove(LAST_SEMANTIC_ACCEPTANCE_MARKER)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        write.commit().unwrap();
        assert!(store.list_event_subscriptions().is_err(), "{corruption}");
    }
}

#[test]
fn list_event_subscriptions_fails_closed_on_corrupt_accounting() {
    let file = TestFile::new("list-event-subscriptions-corrupt");
    let services = event_services(0x45);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let write = store.database.begin_write().unwrap();
    write
        .open_table(METADATA)
        .unwrap()
        .insert(EVENT_SUBSCRIPTION_COUNT, 1)
        .unwrap();
    write.commit().unwrap();
    assert!(store.list_event_subscriptions().is_err());
}
