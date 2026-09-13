use super::*;
use crate::event_operation::{
    ACTIVE_OPERATION_BY_EVENT_V1, EVENT_OPERATION_LEDGER_V3,
    inspect_event_operation_accounting_read,
};

pub(super) fn open(file: &TestFile, authority: NodeId, records: u64, bytes: u64) -> Store {
    Store::open_with_limits_and_operation_limits_for_mission(
        &file.0,
        StoreLimits::default(),
        BlobDepotLimits::DEFAULT,
        EventOperationLimits::new(records, bytes, 1).expect("operation limits"),
        authority,
    )
    .expect("store")
}

pub(super) fn publish(
    store: &Store,
    services: &mut EventServices,
    key: &[u8],
    payload: &[u8],
    tombstone: bool,
) -> Result<EventOnceOutcome, StoreError> {
    let policy = store.control_policy_snapshot()?;
    let reservation = store.reserve_event_with_policy(
        &policy,
        services.publisher.identity(),
        &event_topic(),
        &event_scope(),
    )?;
    let header = reservation.header(
        Priority::Routine,
        b"ledger".to_vec(),
        None,
        payload.len() as u64,
        tombstone,
        1,
    )?;
    let intent = event_publication_intent(&header, payload);
    let operation = EventOperationKey::new(key.to_vec())?;
    let request = EventOperationRequest::new(&operation, &intent, payload, None)?;
    let sealed = services
        .publisher
        .seal_event(&header, payload)
        .expect("seal");
    let verified = content_event(&mut services.reader, &sealed.bytes);
    store.commit_reserved_event_once_with_policy(
        &policy,
        &request,
        &reservation,
        &verified,
        &sealed.bytes,
    )
}

fn stats(store: &Store) -> EventOperationStats {
    inspect_event_operation_accounting_read(&store.database.begin_read().expect("read"))
        .expect("ledger stats")
}

type LogicalSnapshot = Vec<(String, Vec<(String, String)>)>;

fn logical_snapshot(store: &Store) -> LogicalSnapshot {
    use redb::TableHandle;
    let read = store.database.begin_read().expect("snapshot read");
    read.list_tables()
        .expect("tables")
        .map(|table| {
            let name = table.name().to_owned();
            let rows = super::event_operation_migration::snapshot_table(&read, &name);
            (name, rows)
        })
        .collect()
}

#[test]
fn publication_ledger_compact_retirement_classifies_both_intents_without_event_data() {
    use crate::event_operation::*;
    let file = TestFile::new("compact replay");
    let mut services = event_services(0x95);
    let store = open(&file, services.authority, 3, 486);
    publish(&store, &mut services, b"retired", b"same", false).expect("publish");
    let operation = EventOperationKey::new(b"retired".to_vec()).expect("key");
    let stored = store
        .event_for_operation(&operation)
        .expect("read")
        .expect("event");
    let intent = event_publication_intent(&stored.header, b"same");
    let fingerprint = event_operation_fingerprint(&services.authority, &operation);
    let write = store.database.begin_write().expect("write");
    let encoded = encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
        intent_digest: event_operation_intent_digest(&intent, None).expect("digest"),
        reason: CustodyRetirementReason::Expired,
    });
    write
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .insert(fingerprint.as_slice(), encoded.as_slice())
        .expect("compact fixture");
    write
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse")
        .remove(encode_active_operation_by_event_key(stored.transfer_id, fingerprint).as_slice())
        .expect("remove edge");
    write_event_operation_stats(
        &mut write.open_table(METADATA).expect("metadata"),
        EventOperationStats {
            records_total: 1,
            records_active: 0,
            records_retired: 1,
            reverse_rows: 0,
            logical_bytes: 67,
        },
    )
    .expect("stats");
    // Poison both representations: classification must use only the compact ledger.
    write
        .open_table(EVENT_BYTES)
        .expect("bytes")
        .insert(
            stored.transfer_id.as_bytes().as_slice(),
            b"invalid".as_slice(),
        )
        .expect("poison bytes");
    write
        .open_table(EVENTS)
        .expect("events")
        .insert(
            stored.transfer_id.as_bytes().as_slice(),
            b"invalid".as_slice(),
        )
        .expect("poison metadata");
    write.commit().expect("commit fixture");
    assert!(matches!(
        publish(&store, &mut services, b"retired", b"evil", false),
        Err(StoreError::EventOperationConflict)
    ));
    assert_eq!(
        publish(&store, &mut services, b"retired", b"same", false).expect("compact exact retry"),
        EventOnceOutcome::RetiredOperation {
            reason: CustodyRetirementReason::Expired
        },
    );
    assert_eq!(
        store
            .event_operation_resolution(&operation)
            .expect("resolution"),
        Some(EventOperationResolution::RetiredOperation {
            reason: CustodyRetirementReason::Expired
        })
    );
    assert_eq!(stats(&store).logical_bytes, 67);
}

#[test]
fn publication_ledger_active_conflict_precedes_loading_corrupt_event_bytes() {
    let file = TestFile::new("active conflict before load");
    let mut services = event_services(0x96);
    let store = open(&file, services.authority, 3, 486);
    let EventOnceOutcome::Inserted { transfer_id, .. } =
        publish(&store, &mut services, b"active", b"same", false).expect("publish")
    else {
        panic!("insert")
    };
    let write = store.database.begin_write().expect("write");
    write
        .open_table(EVENTS)
        .expect("events")
        .insert(transfer_id.as_bytes().as_slice(), b"invalid".as_slice())
        .expect("poison");
    write.commit().expect("commit");
    assert!(matches!(
        publish(&store, &mut services, b"active", b"evil", false),
        Err(StoreError::EventOperationConflict)
    ));
}

#[test]
fn publication_ledger_mission_fingerprint_cannot_resolve_copied_key() {
    let first_file = TestFile::new("first mission");
    let second_file = TestFile::new("second mission");
    let mut first = event_services(0x97);
    let mut second = event_services(0x98);
    let first_store = open(&first_file, first.authority, 3, 486);
    let second_store = open(&second_file, second.authority, 3, 486);
    publish(&first_store, &mut first, b"same-key", b"same", false).expect("publish first");
    let read = first_store.database.begin_read().expect("read");
    let ledger = read.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
    let (key, value) = ledger
        .iter()
        .expect("iter")
        .next()
        .expect("row")
        .expect("entry");
    let write = second_store.database.begin_write().expect("write");
    write
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .insert(key.value(), value.value())
        .expect("copied record");
    write.commit().expect("commit copied record");
    assert!(
        second_store
            .event_operation_resolution(&EventOperationKey::new(b"same-key".to_vec()).expect("key"))
            .expect("resolve")
            .is_none()
    );
    // The copied record is intentionally not audited as a valid second store;
    // remove it before independent second-mission publication.
    let write = second_store.database.begin_write().expect("write");
    write
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .remove(key.value())
        .expect("remove copied row");
    write.commit().expect("commit");
    publish(&second_store, &mut second, b"same-key", b"same", false).expect("publish second");
    let second_read = second_store.database.begin_read().expect("read");
    let second_ledger = second_read
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger");
    let (second_key, _) = second_ledger
        .iter()
        .expect("iter")
        .next()
        .expect("row")
        .expect("entry");
    assert_ne!(key.value(), second_key.value());
}

#[test]
fn publication_ledger_new_alias_to_retired_event_uses_only_compact_capacity() {
    let file = TestFile::new("retired alias capacity");
    let mut services = event_services(0x99);
    // Three compact fences (201) plus reserve (162); initially fits one
    // active alias (162), which retirement compacts before new alias admission.
    let store = open(&file, services.authority, 10, 363);
    let policy = store.control_policy_snapshot().expect("policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let sample = aster_mesh::CustodySample {
        clock_id: [0x99; 16],
        tick_ms: 1_000,
    };
    let transfer = accept_local_finite_event(&store, &mut services, 1, b"same", 100, sample);
    let stored = store.get_event(transfer).expect("read").expect("event");
    let event = content_event(&mut services.reader, &stored.sealed);
    let intent = event_publication_intent(&stored.header, b"same");
    store
        .collect_custody_garbage(
            Some(aster_mesh::CustodySample {
                tick_ms: 1_100,
                ..sample
            }),
            store.custody_policy_revision().expect("revision"),
            10,
        )
        .expect("retire");
    let alias = EventOperationKey::new(b"retired-alias".to_vec()).expect("key");
    let request = EventOperationRequest::new(&alias, &intent, b"same", None).expect("request");
    let commit = |request: &EventOperationRequest<'_>| {
        store.commit_reserved_event_once_with_custody_policy(
            &policy,
            LocalCustodyCheckpoint::new(
                store.custody_policy_revision().expect("revision"),
                aster_mesh::CustodySample {
                    tick_ms: 1_100,
                    ..sample
                },
            ),
            request,
            &reservation,
            &event,
            &stored.sealed,
        )
    };
    assert_eq!(
        commit(&request).expect("bind retired alias"),
        EventOnceOutcome::RetiredOperation {
            reason: CustodyRetirementReason::Expired
        }
    );
    let extra = EventOperationKey::new(b"another-retired-alias".to_vec()).expect("key");
    let extra_request =
        EventOperationRequest::new(&extra, &intent, b"same", None).expect("request");
    assert_eq!(
        commit(&extra_request).expect("fill compact capacity"),
        EventOnceOutcome::RetiredOperation {
            reason: CustodyRetirementReason::Expired
        }
    );
    assert_eq!(
        stats(&store),
        EventOperationStats {
            records_total: 3,
            records_active: 0,
            records_retired: 3,
            reverse_rows: 0,
            logical_bytes: 201
        }
    );
    let full_alias = EventOperationKey::new(b"one-too-many".to_vec()).expect("key");
    let rejected =
        EventOperationRequest::new(&full_alias, &intent, b"same", None).expect("request");
    assert!(matches!(
        commit(&rejected),
        Err(StoreError::EventOperationByteLimitExceeded {
            current: 201,
            incoming: 67,
            limit: 201
        })
    ));
    assert!(
        store
            .event_operation_resolution(&full_alias)
            .expect("missing rejected alias")
            .is_none()
    );
    assert_eq!(
        commit(&request).expect("retry at capacity"),
        EventOnceOutcome::RetiredOperation {
            reason: CustodyRetirementReason::Expired
        }
    );
}

#[test]
fn publication_ledger_recovers_indeterminate_success_and_restart_without_raw_keys() {
    let file = TestFile::new("publication restart");
    let mut services = event_services(0x91);
    let store = open(&file, services.authority, 3, 486);
    let EventOnceOutcome::Inserted {
        transfer_id,
        semantic_id,
        acceptance_marker,
    } = publish(&store, &mut services, b"secret-operation", b"same", false).expect("publish")
    else {
        panic!("expected insertion")
    };
    // Discarding the first result models an unknown response after commit.
    assert_eq!(
        publish(&store, &mut services, b"secret-operation", b"same", false).expect("retry"),
        EventOnceOutcome::Existing {
            transfer_id,
            semantic_id,
            acceptance_marker
        },
    );
    assert_eq!(
        stats(&store),
        EventOperationStats {
            records_total: 1,
            records_active: 1,
            records_retired: 0,
            reverse_rows: 1,
            logical_bytes: 162,
        }
    );
    let read = store.database.begin_read().expect("read");
    assert_eq!(
        read.open_table(EVENT_OPERATIONS)
            .expect("legacy")
            .len()
            .expect("len"),
        0
    );
    assert_eq!(
        read.open_table(EVENT_OPERATION_WITNESSES)
            .expect("witnesses")
            .len()
            .expect("len"),
        0
    );
    let ledger = read.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
    let (key, value) = ledger
        .iter()
        .expect("rows")
        .next()
        .expect("row")
        .expect("entry");
    assert_eq!(key.value().len(), 32);
    assert_eq!(value.value().len(), 66);
    drop(value);
    drop(key);
    drop(ledger);
    drop(read);
    drop(store);
    let store = open(&file, services.authority, 3, 486);
    assert_eq!(
        publish(&store, &mut services, b"secret-operation", b"same", false).expect("restart retry"),
        EventOnceOutcome::Existing {
            transfer_id,
            semantic_id,
            acceptance_marker
        },
    );
    assert!(matches!(
        publish(&store, &mut services, b"secret-operation", b"evil", false),
        Err(StoreError::EventOperationConflict)
    ));
    assert_eq!(stats(&store).records_total, 1);
}

#[test]
fn publication_ledger_count_exhaustion_preserves_retry_and_tombstone_reserve() {
    let file = TestFile::new("publication count reserve");
    let mut services = event_services(0x92);
    let store = open(&file, services.authority, 3, 1_000);
    publish(&store, &mut services, b"one", b"same", false).expect("first ordinary");
    publish(&store, &mut services, b"two", b"same", false).expect("last ordinary");
    let before = logical_snapshot(&store);
    assert!(matches!(
        publish(&store, &mut services, b"three", b"same", false),
        Err(StoreError::EventOperationLimitExceeded {
            current: 2,
            limit: 2
        })
    ));
    assert_eq!(logical_snapshot(&store), before);
    assert!(matches!(
        publish(&store, &mut services, b"one", b"same", false),
        Ok(EventOnceOutcome::Existing { .. })
    ));
    publish(&store, &mut services, b"delete", b"", true).expect("emergency tombstone");
    assert!(matches!(
        publish(&store, &mut services, b"delete-two", b"", true),
        Err(StoreError::EventOperationLimitExceeded {
            current: 3,
            limit: 3
        })
    ));
    assert_eq!(stats(&store).logical_bytes, 486);
}

#[test]
fn publication_ledger_byte_exhaustion_preserves_retry_and_tombstone_reserve() {
    let file = TestFile::new("publication bytes reserve");
    let mut services = event_services(0x93);
    let store = open(&file, services.authority, 10, 486);
    publish(&store, &mut services, b"one", b"same", false).expect("first ordinary");
    publish(&store, &mut services, b"two", b"same", false).expect("last ordinary");
    let before = logical_snapshot(&store);
    assert!(matches!(
        publish(&store, &mut services, b"three", b"same", false),
        Err(StoreError::EventOperationByteLimitExceeded {
            current: 324,
            incoming: 162,
            limit: 324
        })
    ));
    assert_eq!(logical_snapshot(&store), before);
    assert!(matches!(
        publish(&store, &mut services, b"one", b"same", false),
        Ok(EventOnceOutcome::Existing { .. })
    ));
    publish(&store, &mut services, b"delete", b"", true).expect("emergency tombstone");
    assert!(matches!(
        publish(&store, &mut services, b"delete-two", b"", true),
        Err(StoreError::EventOperationByteLimitExceeded {
            current: 486,
            incoming: 162,
            limit: 486
        })
    ));
}

#[test]
fn publication_ledger_alias_64_succeeds_and_65_has_no_mutation() {
    let file = TestFile::new("publication aliases");
    let mut services = event_services(0x94);
    let store = open(&file, services.authority, 100, 20_000);
    let policy = store.control_policy_snapshot().expect("policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    publish(&store, &mut services, b"primary", b"same", false).expect("publish");
    let stored = store
        .event_for_operation(&EventOperationKey::new(b"primary".to_vec()).expect("key"))
        .expect("lookup")
        .expect("event");
    let event = content_event(&mut services.reader, &stored.sealed);
    let intent = event_publication_intent(&stored.header, b"same");
    for index in 1..=64u8 {
        let operation = EventOperationKey::new(vec![index]).expect("alias");
        let request =
            EventOperationRequest::new(&operation, &intent, b"same", None).expect("request");
        let before = logical_snapshot(&store);
        let result =
            store.commit_reserved_event_once(&request, &reservation, &event, &stored.sealed);
        if index < 64 {
            assert!(matches!(result, Ok(EventOnceOutcome::BoundExisting { .. })));
        } else {
            assert!(matches!(
                result,
                Err(StoreError::EventOperationLimitExceeded {
                    current: 64,
                    limit: 64
                })
            ));
            assert_eq!(logical_snapshot(&store), before);
        }
    }
    assert_eq!(stats(&store).records_total, 64);
    assert_eq!(stats(&store).logical_bytes, 10_368);
    assert_eq!(
        store
            .database
            .begin_read()
            .expect("read")
            .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
            .expect("reverse")
            .len()
            .expect("len"),
        64
    );
    assert!(matches!(
        publish(&store, &mut services, b"primary", b"same", false),
        Ok(EventOnceOutcome::Existing { .. })
    ));
}
