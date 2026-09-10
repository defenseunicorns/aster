use super::event_operation_publication::{open, publish};
use super::*;
use crate::event_operation::*;

fn retired_rows(store: &Store, count: u64) {
    let write = store.database.begin_write().expect("write");
    {
        let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
        for index in 0..count {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&index.to_be_bytes());
            let value = encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
                intent_digest: [7; 32],
                reason: CustodyRetirementReason::Expired,
            });
            ledger
                .insert(key.as_slice(), value.as_slice())
                .expect("row");
        }
        write_event_operation_stats(
            &mut write.open_table(METADATA).expect("metadata"),
            EventOperationStats {
                records_total: count,
                records_retired: count,
                logical_bytes: count * 67,
                ..EventOperationStats::default()
            },
        )
        .expect("counters");
    }
    write.commit().expect("commit");
}

#[test]
fn operation_audit_bounds_pages_and_completes_all_retired_rows_after_reopen() {
    let file = TestFile::new("audit retired pages");
    let store = open(&file, [0xa6; 32], 3_000, 500_000);
    retired_rows(&store, 2_050);
    drop(store);
    let store = open(&file, [0xa6; 32], 3_000, 500_000);
    let mut pages = Vec::new();
    let result = store
        .audit_event_operations(usize::MAX, |progress| pages.push(progress))
        .expect("audit");
    assert_eq!(
        result,
        EventOperationAuditProgress {
            scanned: 2_050,
            total: 2_050
        }
    );
    assert_eq!(
        pages.iter().map(|p| p.scanned).collect::<Vec<_>>(),
        [0, 1_024, 2_048, 2_050]
    );
    assert!(pages.iter().all(|p| p.total == 2_050));
    assert!(store.audit_event_operations(0, |_| {}).is_err());
    drop(store);
    let offline = Store::audit_existing_event_operations(&file.0, 17, |_| {})
        .expect("offline complete audit");
    assert_eq!(offline, result);
}

#[test]
#[cfg(unix)]
fn operation_audit_offline_accepts_read_only_backing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let file = TestFile::new("audit read-only permissions");
    let store = open(&file, [0xa6; 32], 10, 2_000);
    retired_rows(&store, 3);
    drop(store);
    let before = std::fs::read(&file.0).unwrap();
    std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        Store::audit_existing_event_operations(&file.0, 1, |_| {})
            .expect("read-only audit")
            .total,
        3
    );
    Store::inspect_existing(&file.0).expect("the accompanying inspection is read-only too");
    assert_eq!(std::fs::read(&file.0).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&file.0).unwrap().permissions().mode() & 0o777,
        0o400
    );
}

#[test]
fn operation_audit_holds_one_snapshot_excluding_concurrent_publication() {
    let file = TestFile::new("audit snapshot publication");
    let mut services = event_services(0xa6);
    let store = open(&file, services.authority, 10, 2_000);
    publish(&store, &mut services, b"first", b"one", false).expect("first");
    let mut pages = Vec::new();
    let result = store
        .audit_event_operations(1, |progress| {
            pages.push(progress);
            if progress.scanned == 1 {
                publish(&store, &mut services, b"after-snapshot", b"two", false)
                    .expect("concurrent publication");
            }
        })
        .expect("stable snapshot");
    assert_eq!(
        result,
        EventOperationAuditProgress {
            scanned: 2,
            total: 2
        }
    );
    assert_eq!(
        pages.iter().map(|p| p.scanned).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(pages.iter().all(|p| p.total == 2));
    assert_eq!(
        store
            .audit_event_operations(1, |_| {})
            .expect("next audit")
            .total,
        4
    );
}

#[test]
fn operation_audit_rejects_65_otherwise_valid_aliases() {
    let file = TestFile::new("audit alias overflow");
    let mut services = event_services(0xa8);
    let store = open(&file, services.authority, 100, 20_000);
    publish(&store, &mut services, b"first", b"one", false).unwrap();
    let read = store.database.begin_read().unwrap();
    let ledger = read.open_table(EVENT_OPERATION_LEDGER_V3).unwrap();
    let (_, value) = ledger.first().unwrap().unwrap();
    let value = value.value().to_vec();
    let EventOperationLedgerRecord::Active { transfer_id, .. } =
        decode_event_operation_ledger_record(&value).unwrap()
    else {
        panic!("active fixture")
    };
    let write = store.database.begin_write().unwrap();
    {
        let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).unwrap();
        let mut reverse = write.open_table(ACTIVE_OPERATION_BY_EVENT_V1).unwrap();
        // The existing real publication plus 64 canonical aliases.
        for index in 0..64u8 {
            let fingerprint = [index; 32];
            assert!(
                ledger
                    .insert(fingerprint.as_slice(), value.as_slice())
                    .unwrap()
                    .is_none()
            );
            reverse
                .insert(
                    encode_active_operation_by_event_key(transfer_id, fingerprint).as_slice(),
                    [].as_slice(),
                )
                .unwrap();
        }
        write_event_operation_stats(
            &mut write.open_table(METADATA).unwrap(),
            EventOperationStats {
                records_total: 65,
                records_active: 65,
                records_retired: 0,
                reverse_rows: 65,
                logical_bytes: 65 * 162,
            },
        )
        .unwrap();
    }
    write.commit().unwrap();
    assert!(matches!(
        store.audit_event_operations(1, |_| {}),
        Err(StoreError::SemanticInvariant(
            "Event operation audit exceeds the alias limit"
        ))
    ));
}

#[test]
fn operation_audit_retirement_category_does_not_wrap_backend_or_custody_errors() {
    assert!(matches!(
        classify_retirement_invariant(StoreError::SemanticInvariant("ledger")),
        StoreError::EventOperationRetirementInvariant(_)
    ));
    assert!(matches!(
        classify_retirement_invariant(StoreError::AccountingMismatch {
            field: "ledger",
            durable: 1,
            reconstructed: 0
        }),
        StoreError::EventOperationRetirementInvariant(_)
    ));
    assert!(matches!(
        classify_retirement_invariant(StoreError::Backend(redb::Error::Io(std::io::Error::other(
            "storage failure"
        )))),
        StoreError::Backend(_)
    ));
    assert!(matches!(
        classify_retirement_invariant(StoreError::Custody(CustodyStoreError::Invariant(
            "custody failure"
        ))),
        StoreError::Custody(_)
    ));
    assert!(matches!(
        classify_retirement_invariant(StoreError::ControlPolicyUnsettled { pending: 1 }),
        StoreError::ControlPolicyUnsettled { .. }
    ));
}

#[test]
fn operation_audit_reverse_pass_uses_original_snapshot() {
    let file = TestFile::new("audit snapshot reverse");
    let mut services = event_services(0xa7);
    let store = open(&file, services.authority, 10, 2_000);
    publish(&store, &mut services, b"first", b"one", false).expect("first");
    let event = store
        .event_for_operation(&EventOperationKey::new(b"first".to_vec()).unwrap())
        .unwrap()
        .unwrap();
    let fingerprint = event_operation_fingerprint(
        &services.authority,
        &EventOperationKey::new(b"first".to_vec()).unwrap(),
    );
    let key = encode_active_operation_by_event_key(event.transfer_id, fingerprint);
    store
        .audit_event_operations(1, |progress| {
            if progress.scanned == 1 {
                let write = store.database.begin_write().unwrap();
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .insert(key.as_slice(), b"corrupt".as_slice())
                    .unwrap();
                write.commit().unwrap();
            }
        })
        .expect("reverse pass must see original empty value");
    assert!(store.audit_event_operations(1, |_| {}).is_err());
}

#[test]
fn operation_audit_cancellation_is_not_completion() {
    let file = TestFile::new("audit cancellation");
    let store = open(&file, [0xa8; 32], 100, 20_000);
    retired_rows(&store, 40);
    let scanned = std::cell::Cell::new(0);
    let result = store.audit_event_operations_cancellable(
        3,
        |p| scanned.set(p.scanned),
        || scanned.get() >= 3,
    );
    assert!(matches!(
        result,
        Err(StoreError::EventOperationAuditCancelled)
    ));
    assert_eq!(scanned.get(), 3);
    assert_eq!(store.audit_event_operations(3, |_| {}).unwrap().scanned, 40);
}

#[test]
fn operation_audit_detects_malformed_ledger_reverse_and_event_relations() {
    // Each corruption is committed independently, then restored. Startup has
    // already validated the retained Event; the audit must validate its edges.
    let file = TestFile::new("audit corruption matrix");
    let mut services = event_services(0xa9);
    let store = open(&file, services.authority, 100, 20_000);
    publish(&store, &mut services, b"first", b"one", false).expect("first");
    let event = store
        .event_for_operation(&EventOperationKey::new(b"first".to_vec()).unwrap())
        .unwrap()
        .unwrap();
    let fingerprint = event_operation_fingerprint(
        &services.authority,
        &EventOperationKey::new(b"first".to_vec()).unwrap(),
    );
    let reverse_key = encode_active_operation_by_event_key(event.transfer_id, fingerprint);
    let original = store
        .database
        .begin_read()
        .unwrap()
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .unwrap()
        .get(fingerprint.as_slice())
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    for case in 0..16 {
        let write = store.database.begin_write().unwrap();
        match case {
            0..=3 => {
                let mut bad = original.clone();
                match case {
                    0 => bad[0] = 0xff,
                    1 => bad[1] = 0xff,
                    2 => {
                        bad.pop();
                    }
                    _ => bad.push(0),
                }
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .unwrap()
                    .insert(fingerprint.as_slice(), bad.as_slice())
                    .unwrap();
            }
            4 => {
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .unwrap()
                    .remove(fingerprint.as_slice())
                    .unwrap();
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .unwrap()
                    .insert(b"short".as_slice(), original.as_slice())
                    .unwrap();
            }
            5 => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .remove(reverse_key.as_slice())
                    .unwrap();
            }
            6 => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .insert(reverse_key.as_slice(), b"nonempty".as_slice())
                    .unwrap();
            }
            7..=9 => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .remove(reverse_key.as_slice())
                    .unwrap();
                let key = match case {
                    7 => vec![3; 63],
                    8 => encode_active_operation_by_event_key(
                        EventTransferId::new([3; 32]),
                        fingerprint,
                    )
                    .to_vec(),
                    _ => encode_active_operation_by_event_key(event.transfer_id, [3; 32]).to_vec(),
                };
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .insert(key.as_slice(), [].as_slice())
                    .unwrap();
            }
            10 => {
                let retired =
                    encode_event_operation_ledger_record(EventOperationLedgerRecord::Retired {
                        intent_digest: [1; 32],
                        reason: CustodyRetirementReason::Expired,
                    });
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .unwrap()
                    .insert(fingerprint.as_slice(), retired.as_slice())
                    .unwrap();
            }
            11 => {
                write
                    .open_table(EVENTS)
                    .unwrap()
                    .remove(event.transfer_id.as_bytes().as_slice())
                    .unwrap();
            }
            12 => {
                write
                    .open_table(EVENT_BYTES)
                    .unwrap()
                    .remove(event.transfer_id.as_bytes().as_slice())
                    .unwrap();
            }
            13 => {
                write
                    .open_table(EVENT_ACCEPTANCE_MARKERS)
                    .unwrap()
                    .remove(event.transfer_id.as_bytes().as_slice())
                    .unwrap();
            }
            14 => {
                write
                    .open_table(METADATA)
                    .unwrap()
                    .insert(EVENT_OPERATION_LOGICAL_BYTES, 1)
                    .unwrap();
            }
            _ => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .unwrap()
                    .insert(
                        encode_active_operation_by_event_key(event.transfer_id, [3; 32]).as_slice(),
                        [].as_slice(),
                    )
                    .unwrap();
            }
        }
        // Retain the original snapshot for exact restoration of touched tables.
        let before = store.database.begin_read().unwrap();
        write.commit().unwrap();
        let result = store.audit_event_operations(1, |_| {});
        if case == 14 {
            assert!(
                matches!(
                    result,
                    Err(StoreError::AccountingMismatch {
                        field: EVENT_OPERATION_LOGICAL_BYTES,
                        durable: 1,
                        reconstructed: 162
                    })
                ),
                "committed counter mismatch must be detected"
            );
        } else {
            assert!(result.is_err(), "corruption case {case}");
        }
        let restore = store.database.begin_write().unwrap();
        for definition in [
            EVENT_OPERATION_LEDGER_V3,
            ACTIVE_OPERATION_BY_EVENT_V1,
            EVENTS,
            EVENT_BYTES,
        ] {
            restore.delete_table(definition).unwrap();
            let mut table = restore.open_table(definition).unwrap();
            for row in before.open_table(definition).unwrap().iter().unwrap() {
                let (key, value) = row.unwrap();
                table.insert(key.value(), value.value()).unwrap();
            }
        }
        restore
            .open_table(EVENT_ACCEPTANCE_MARKERS)
            .unwrap()
            .insert(
                event.transfer_id.as_bytes().as_slice(),
                event.acceptance_marker,
            )
            .unwrap();
        restore
            .open_table(METADATA)
            .unwrap()
            .insert(EVENT_OPERATION_LOGICAL_BYTES, 162)
            .unwrap();
        restore.commit().unwrap();
    }
    store
        .audit_event_operations(1, |_| {})
        .expect("restored relations");
}

#[test]
fn operation_audit_startup_defers_malformed_retired_record_to_complete_audit() {
    let file = TestFile::new("audit bounded startup");
    let store = open(&file, [0xab; 32], 100, 20_000);
    retired_rows(&store, 1);
    let write = store.database.begin_write().unwrap();
    write
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .unwrap()
        .insert([0; 32].as_slice(), b"malformed".as_slice())
        .unwrap();
    write.commit().unwrap();
    drop(store);
    let store = open(&file, [0xab; 32], 100, 20_000);
    assert!(store.audit_event_operations(1, |_| {}).is_err());
    drop(store);
    assert!(Store::audit_existing_event_operations(&file.0, 1, |_| {}).is_err());
}
