use super::*;
use crate::event_operation::*;
use redb::TableHandle;

const SAMPLE: aster_mesh::CustodySample = aster_mesh::CustodySample {
    clock_id: [0xa5; 16],
    tick_ms: 1_000,
};
const EXPIRED: aster_mesh::CustodySample = aster_mesh::CustodySample {
    tick_ms: 1_100,
    ..SAMPLE
};

fn fixture(aliases: u8) -> (TestFile, EventServices, Store, StoredEvent) {
    let file = TestFile::new("operation retirement");
    let mut services = event_services(0xa5);
    // Exactly 64 active aliases plus the mandatory one-record reserve.
    let store = Store::open_with_limits_and_operation_limits_for_mission(
        &file.0,
        StoreLimits::default(),
        BlobDepotLimits::DEFAULT,
        EventOperationLimits::new(65, 10_530, 1).expect("limits"),
        services.authority,
    )
    .expect("store");
    let policy = store.control_policy_snapshot().expect("policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let header = reservation
        .header(
            Priority::Routine,
            b"retirement".to_vec(),
            Some(100),
            7,
            false,
            1,
        )
        .expect("header");
    let sealed = services
        .publisher
        .seal_event(&header, b"payload")
        .expect("seal");
    let event = content_event(&mut services.reader, &sealed.bytes);
    let transfer = EventTransferId::new(event.envelope_id());
    // A real unkeyed Event acceptance permits testing the zero-alias boundary.
    let prepared =
        PreparedEvent::from_verified_with_custody(&event, &sealed.bytes, EventOrigin::Local)
            .expect("prepared");
    store
        .commit_prepared_event(
            &prepared,
            Some(&reservation),
            None,
            EventAdmissionGuard::Control(&policy),
            Some(PendingEventCustody {
                expected_policy: store.custody_policy_revision().expect("revision"),
                authenticated_age_ms: 0,
                sample: Some(SAMPLE),
            }),
        )
        .expect("accept unkeyed Event");
    let intent = event_publication_intent(&header, b"payload");
    for alias in 0..aliases {
        let key = EventOperationKey::new(vec![0xa5, alias]).expect("key");
        let request = EventOperationRequest::new(&key, &intent, b"payload", None).expect("request");
        store
            .commit_reserved_event_once_with_custody_policy(
                &policy,
                LocalCustodyCheckpoint::new(
                    store.custody_policy_revision().expect("revision"),
                    SAMPLE,
                ),
                &request,
                &reservation,
                &event,
                &sealed.bytes,
            )
            .expect("alias");
    }
    let stored = store.get_event(transfer).expect("lookup").expect("Event");
    (file, services, store, stored)
}

fn stats(store: &Store) -> EventOperationStats {
    inspect_event_operation_accounting_read(&store.database.begin_read().expect("read"))
        .expect("operation stats")
}

fn retire(store: &Store) -> Result<CustodyGcReport, StoreError> {
    store.collect_custody_garbage(Some(EXPIRED), store.custody_policy_revision()?, 64)
}

type Snapshot = Vec<(String, Vec<(String, String)>)>;

fn snapshot(read: &redb::ReadTransaction) -> Snapshot {
    read.list_tables()
        .expect("tables")
        .map(|table| {
            let name = table.name().to_owned();
            let rows = super::event_operation_migration::snapshot_table(read, &name);
            (name, rows)
        })
        .collect()
}

fn shared_snapshot(store: &Store) -> Snapshot {
    let read = store.database.begin_read().expect("read shared metadata");
    [
        EVENTS.name(),
        SEMANTIC_ITEMS.name(),
        ACCEPTED_DOTS.name(),
        ACCEPTED_EVENTS.name(),
        CAUSAL_FRONTIER.name(),
        PUBLISHER_HIGH_WATER.name(),
        EVENT_HIGH_WATER.name(),
        EVENT_ACCEPTANCE_MARKERS.name(),
        EVENT_ACCEPTANCE_ORDER.name(),
        EVENT_OPERATION_WITNESSES.name(),
        EVENT_OPERATIONS.name(),
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            super::event_operation_migration::snapshot_table(&read, name),
        )
    })
    .collect()
}

#[test]
fn retirement_compacts_zero_one_and_64_aliases_at_full_capacity_and_reopens() {
    // Missing compaction, a wrong delta, quota admission during conversion, or
    // deleting shared metadata breaks these hand-derived expectations.
    for (aliases, before_bytes, after_bytes) in [(0, 0, 0), (1, 162, 67), (64, 10_368, 4_288)] {
        let (file, services, store, stored) = fixture(aliases);
        assert_eq!(
            stats(&store),
            EventOperationStats {
                records_total: u64::from(aliases),
                records_active: u64::from(aliases),
                records_retired: 0,
                reverse_rows: u64::from(aliases),
                logical_bytes: before_bytes,
            }
        );
        let shared = shared_snapshot(&store);
        let report = retire(&store).expect("retire");
        assert_eq!(
            report.retired,
            vec![CustodyObjectKey::event(stored.transfer_id)]
        );
        assert_eq!(shared_snapshot(&store), shared);
        assert_eq!(
            stats(&store),
            EventOperationStats {
                records_total: u64::from(aliases),
                records_active: 0,
                records_retired: u64::from(aliases),
                reverse_rows: 0,
                logical_bytes: after_bytes,
            }
        );
        assert!(
            store
                .get_event(stored.transfer_id)
                .expect("payload lookup")
                .is_none()
        );
        let read = store.database.begin_read().expect("read retired");
        assert_eq!(
            read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                .expect("reverse")
                .len()
                .expect("len"),
            0
        );
        for row in read
            .open_table(EVENT_OPERATION_LEDGER_V3)
            .expect("ledger")
            .iter()
            .expect("rows")
        {
            let (key, value) = row.expect("row");
            assert_eq!((key.value().len(), value.value().len()), (32, 35));
        }
        assert_eq!(
            custody::retired_event_receipt_read(&read, stored.transfer_id).expect("receipt"),
            Some((
                stored.semantic_id,
                stored.acceptance_marker,
                CustodyRetirementReason::Expired
            ))
        );
        drop(read);
        drop(store);
        let reopened =
            Store::open_for_mission(&file.0, services.authority).expect("reopen retired");
        assert_eq!(shared_snapshot(&reopened), shared);
        assert_eq!(stats(&reopened).logical_bytes, after_bytes);
        let intent = event_publication_intent(&stored.header, b"payload");
        let changed = event_publication_intent(&stored.header, b"changed");
        for alias in 0..aliases {
            let key = EventOperationKey::new(vec![0xa5, alias]).expect("key");
            let exact = EventOperationRequest::new(&key, &intent, b"payload", None).expect("exact");
            assert_eq!(
                reopened
                    .event_operation_resolution_for_request(&exact)
                    .expect("exact retry"),
                Some(EventOperationResolution::RetiredOperation {
                    reason: CustodyRetirementReason::Expired
                })
            );
            let changed =
                EventOperationRequest::new(&key, &changed, b"changed", None).expect("changed");
            assert!(matches!(
                reopened.event_operation_resolution_for_request(&changed),
                Err(StoreError::EventOperationConflict)
            ));
        }
    }
}

#[test]
fn retirement_rejects_corrupt_edges_targets_and_counters_without_any_commit() {
    // Each mutation must abort the complete GC transaction, including marks,
    // continuity, custody fences, payload deletion, and all earlier aliases.
    let _reset = FaultReset;
    let mut accepted = Vec::new();
    for corruption in [
        "missing-edge",
        "missing-target",
        "short-edge",
        "long-edge",
        "edge-value",
        "malformed-target",
        "wrong-transfer",
        "retired-target",
        "missing-counter",
        "total-counter",
        "active-counter",
        "retired-counter",
        "reverse-counter",
        "byte-counter",
        "coherent-undercount",
        "65-aliases",
    ] {
        let (file, _services, store, stored) = fixture(2);
        let write = store.database.begin_write().expect("corrupt transaction");
        let (fingerprint, encoded) = {
            let ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
            let (key, value) = ledger
                .iter()
                .expect("rows")
                .next_back()
                .expect("last row")
                .expect("row");
            (key.value().to_vec(), value.value().to_vec())
        };
        let edge = encode_active_operation_by_event_key(
            stored.transfer_id,
            fingerprint.as_slice().try_into().expect("fingerprint"),
        );
        match corruption {
            "missing-edge" => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse")
                    .remove(edge.as_slice())
                    .expect("remove");
            }
            "missing-target" => {
                let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
                ledger.remove(fingerprint.as_slice()).expect("remove");
                ledger
                    .insert([0xff; 32].as_slice(), encoded.as_slice())
                    .expect("unreferenced target");
            }
            "short-edge" | "long-edge" => {
                let mut reverse = write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse");
                reverse.remove(edge.as_slice()).expect("remove");
                let mut malformed = edge.to_vec();
                if corruption == "short-edge" {
                    malformed.truncate(32);
                } else {
                    malformed.push(0);
                }
                reverse
                    .insert(malformed.as_slice(), &[][..])
                    .expect("malformed edge");
            }
            "edge-value" => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse")
                    .insert(edge.as_slice(), &[1][..])
                    .expect("value");
            }
            "malformed-target" | "wrong-transfer" | "retired-target" => {
                let mut target = encoded;
                if corruption == "malformed-target" {
                    target.truncate(4);
                } else if corruption == "wrong-transfer" {
                    target[34..].fill(0xff);
                } else {
                    target[1] = 2;
                    target.truncate(35);
                    target[34] = CustodyRetirementReason::Expired as u8;
                }
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .expect("ledger")
                    .insert(fingerprint.as_slice(), target.as_slice())
                    .expect("target");
            }
            "65-aliases" => {
                // Bypass the publication cap only to emulate a corrupt durable image.
                for n in 0..63u8 {
                    let extra = [n; 32];
                    write
                        .open_table(EVENT_OPERATION_LEDGER_V3)
                        .expect("ledger")
                        .insert(extra.as_slice(), encoded.as_slice())
                        .expect("extra ledger");
                    write
                        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                        .expect("reverse")
                        .insert(
                            encode_active_operation_by_event_key(stored.transfer_id, extra)
                                .as_slice(),
                            &[][..],
                        )
                        .expect("extra edge");
                }
                write_event_operation_stats(
                    &mut write.open_table(METADATA).expect("metadata"),
                    EventOperationStats {
                        records_total: 65,
                        records_active: 65,
                        records_retired: 0,
                        reverse_rows: 65,
                        logical_bytes: 10_530,
                    },
                )
                .expect("65 alias accounting");
            }
            "coherent-undercount" => {
                write_event_operation_stats(
                    &mut write.open_table(METADATA).expect("metadata"),
                    EventOperationStats::default(),
                )
                .expect("undercount");
            }
            name => {
                let field = match name {
                    "missing-counter" | "total-counter" => EVENT_OPERATION_RECORDS_TOTAL,
                    "active-counter" => EVENT_OPERATION_RECORDS_ACTIVE,
                    "retired-counter" => EVENT_OPERATION_RECORDS_RETIRED,
                    "reverse-counter" => EVENT_OPERATION_REVERSE_ROWS,
                    "byte-counter" => EVENT_OPERATION_LOGICAL_BYTES,
                    _ => unreachable!(),
                };
                let mut metadata = write.open_table(METADATA).expect("metadata");
                if name == "missing-counter" {
                    metadata.remove(field).expect("remove counter");
                } else {
                    metadata.insert(field, 99).expect("corrupt counter");
                }
            }
        }
        write.commit().expect("commit corrupt fixture");
        let before = snapshot(&store.database.begin_read().expect("before"));
        // Point 1 is immediately before the first operation mutation. Every
        // invalid edge/target/counter must fail before reaching that point.
        RETIREMENT_TEST_FAULT.set(1);
        let result = retire(&store);
        RETIREMENT_TEST_FAULT.set(0);
        if result.is_ok() {
            accepted.push(corruption);
            continue;
        }
        assert!(
            !matches!(
                result,
                Err(StoreError::SemanticInvariant(
                    "injected Event operation retirement failure"
                ))
            ),
            "{corruption} reached mutation before validation"
        );
        assert_eq!(
            snapshot(&store.database.begin_read().expect("after")),
            before,
            "mutated {corruption}"
        );
        drop(store);
        // Raw reopen is intentional: the fixture was already corrupt before GC.
        let database = Database::open(&file.0).expect("raw reopen");
        assert_eq!(
            snapshot(&database.begin_read().expect("reopened read")),
            before,
            "reopen changed {corruption}"
        );
    }
    assert!(accepted.is_empty(), "accepted corruptions: {accepted:?}");
}

struct FaultReset;

impl Drop for FaultReset {
    fn drop(&mut self) {
        RETIREMENT_TEST_FAULT.set(0);
    }
}

#[test]
fn retirement_faults_before_during_and_after_compaction_reopen_the_complete_before_image() {
    let _reset = FaultReset;
    let mut missed = Vec::new();
    for point in 1..=4 {
        let (file, services, store, stored) = fixture(2);
        let before = snapshot(&store.database.begin_read().expect("before"));
        RETIREMENT_TEST_FAULT.set(point);
        let result = retire(&store);
        RETIREMENT_TEST_FAULT.set(0);
        if result.is_ok() {
            missed.push(point);
            continue;
        }
        assert!(matches!(
            result,
            Err(StoreError::SemanticInvariant(
                "injected Event operation retirement failure"
            ))
        ));
        assert_eq!(
            snapshot(&store.database.begin_read().expect("after error")),
            before
        );
        drop(store);
        {
            let database = Database::open(&file.0).expect("raw reopen");
            assert_eq!(snapshot(&database.begin_read().expect("raw read")), before);
        }
        let reopened =
            Store::open_for_mission(&file.0, services.authority).expect("audited reopen");
        assert_eq!(
            stats(&reopened),
            EventOperationStats {
                records_total: 2,
                records_active: 2,
                records_retired: 0,
                reverse_rows: 2,
                logical_bytes: 324,
            }
        );
        assert!(
            reopened
                .get_event(stored.transfer_id)
                .expect("retained payload")
                .is_some()
        );
        assert_eq!(
            retire(&reopened).expect("retry retirement").retired,
            vec![CustodyObjectKey::event(stored.transfer_id)]
        );
        assert_eq!(
            stats(&reopened),
            EventOperationStats {
                records_total: 2,
                records_active: 0,
                records_retired: 2,
                reverse_rows: 0,
                logical_bytes: 134,
            }
        );
    }
    assert!(
        missed.is_empty(),
        "missed retirement fault points: {missed:?}"
    );
}

#[test]
fn retirement_ranges_only_the_selected_event_and_preserves_other_aliases() {
    let (file, mut services, store, stored) = fixture(2);
    let other = accept_local_finite_event(&store, &mut services, 7, b"other", 10_000, SAMPLE);
    let key = EventOperationKey::new(vec![b'f', 7]).expect("other key");
    let fingerprint = event_operation_fingerprint(&services.authority, &key);
    let edge = encode_active_operation_by_event_key(other, fingerprint);
    let write = store.database.begin_write().expect("write");
    // An unrelated invalid value exposes an accidental full reverse scan.
    // Complete validation of other Events belongs to the ledger audit.
    write
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse")
        .insert(edge.as_slice(), b"unrelated".as_slice())
        .expect("unrelated edge");
    write.commit().expect("commit unrelated fixture");
    assert_eq!(
        retire(&store).expect("retire selected").retired,
        vec![CustodyObjectKey::event(stored.transfer_id)]
    );
    assert_eq!(
        stats(&store),
        EventOperationStats {
            records_total: 3,
            records_active: 1,
            records_retired: 2,
            reverse_rows: 1,
            logical_bytes: 296,
        }
    );
    let read = store.database.begin_read().expect("read");
    let reverse = read
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse");
    assert_eq!(
        reverse
            .get(edge.as_slice())
            .expect("edge")
            .expect("retained edge")
            .value(),
        b"unrelated"
    );
    assert!(store.get_event(other).expect("other payload").is_some());
    drop((reverse, read));
    // Repair only the injected unrelated corruption before a normal reopen.
    let write = store.database.begin_write().expect("repair fixture");
    write
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse")
        .insert(edge.as_slice(), &[][..])
        .expect("repair edge");
    write.commit().expect("commit repair");
    drop(store);
    let reopened =
        Store::open_for_mission(&file.0, services.authority).expect("reopen selected retirement");
    assert!(
        reopened
            .get_event(other)
            .expect("retained other Event")
            .is_some()
    );
    assert_eq!(stats(&reopened).logical_bytes, 296);
}

#[test]
fn retirement_compacts_live_pressure_victims_with_the_pressure_reason() {
    let (file, services, store, stored) = fixture(1);
    let shared = shared_snapshot(&store);
    let revision = store
        .set_custody_quota(CustodyQuota::global(1, 1_000_000).expect("quota"))
        .expect("set quota");
    let report = store
        .collect_custody_pressure(
            None,
            CustodyPressureDemand {
                usage: CustodyUsage { items: 1, bytes: 1 },
                priority: Priority::Immediate,
            },
            Some(SAMPLE),
            revision,
            1,
        )
        .expect("pressure retirement");
    assert_eq!(
        report.retired,
        vec![CustodyObjectKey::event(stored.transfer_id)]
    );
    assert_eq!(shared_snapshot(&store), shared);
    drop(store);
    let reopened =
        Store::open_for_mission(&file.0, services.authority).expect("reopen pressure victim");
    assert_eq!(stats(&reopened).logical_bytes, 67);
    let key = EventOperationKey::new(vec![0xa5, 0]).expect("key");
    assert_eq!(
        reopened
            .event_operation_resolution(&key)
            .expect("resolution"),
        Some(EventOperationResolution::RetiredOperation {
            reason: CustodyRetirementReason::QuotaPressure
        })
    );
}
