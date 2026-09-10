use super::*;
use crate::event_operation::{
    ACTIVE_OPERATION_BY_EVENT_V1, EVENT_OPERATION_LEDGER_V3, MIGRATION_TEST_FAULT,
};
use redb::TableHandle;

const V3_COUNTERS: [&str; 5] = [
    "semantic_event_operation_v3_records_total",
    "semantic_event_operation_v3_records_active",
    "semantic_event_operation_v3_records_retired",
    "semantic_event_operation_v3_reverse_rows",
    "semantic_event_operation_v3_logical_bytes",
];
const SAMPLE: aster_mesh::CustodySample = aster_mesh::CustodySample {
    clock_id: [0x71; 16],
    tick_ms: 1_000,
};

struct FaultReset;

impl Drop for FaultReset {
    fn drop(&mut self) {
        MIGRATION_TEST_FAULT.set(0);
    }
}

fn remove_v3(write: &redb::WriteTransaction) {
    write
        .delete_table(EVENT_OPERATION_LEDGER_V3)
        .expect("remove v3 fixture ledger");
    write
        .delete_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("remove v3 fixture reverse");
    let mut metadata = write.open_table(METADATA).expect("metadata");
    for field in V3_COUNTERS {
        metadata.remove(field).expect("remove v3 fixture counter");
    }
}

fn legacy_fixture(
    name: &str,
    aliases: u8,
    witnessed_v1: bool,
) -> (TestFile, NodeId, EventTransferId) {
    let file = TestFile::new(name);
    let mut services = event_services(0x79);
    let store = Store::open_for_mission(&file.0, services.authority).expect("fixture store");
    let transfer = accept_local_finite_event(&store, &mut services, 1, b"payload", 10_000, SAMPLE);
    let write = store
        .database
        .begin_write()
        .expect("released fixture transaction");
    remove_v3(&write);
    let mut row = write
        .open_table(EVENT_OPERATIONS)
        .expect("operations")
        .get(&[b'f', 1][..])
        .expect("operation")
        .expect("published row")
        .value()
        .to_vec();
    if witnessed_v1 {
        row.truncate(34);
        row[0] = 1;
        // This digest is SHA-256 of the content-verified fixture payload.
        let witness = [
            1, 0x23, 0x9f, 0x59, 0xed, 0x55, 0xe7, 0x37, 0xc7, 0x71, 0x47, 0xcf, 0x55, 0xad, 0x0c,
            0x1b, 0x03, 0x0b, 0x6d, 0x7e, 0xe7, 0x48, 0xa7, 0x42, 0x69, 0x52, 0xf9, 0xb8, 0x52,
            0xd5, 0xa9, 0x35, 0xe5,
        ];
        write
            .open_table(EVENT_OPERATION_WITNESSES)
            .expect("witness table")
            .insert(transfer.as_bytes().as_slice(), witness.as_slice())
            .expect("witness");
    }
    {
        let mut operations = write.open_table(EVENT_OPERATIONS).expect("operations");
        operations
            .remove(&[b'f', 1][..])
            .expect("replace primary key");
        for index in 0..aliases {
            operations
                .insert(&[0x81, index][..], row.as_slice())
                .expect("legacy alias");
        }
    }
    {
        let mut metadata = write.open_table(METADATA).expect("metadata");
        metadata
            .insert(EVENT_OPERATION_COUNT, u64::from(aliases))
            .expect("count");
        metadata
            .insert(
                EVENT_OPERATION_TOTAL_BYTES,
                u64::from(aliases) * (2 + row.len() as u64),
            )
            .expect("bytes");
    }
    write.commit().expect("commit released legacy fixture");
    drop(store);
    (file, services.authority, transfer)
}

type RawRows = Vec<(Vec<u8>, Vec<u8>)>;
type LogicalRows = Vec<(String, String)>;

#[derive(Debug, Eq, PartialEq)]
struct LegacySnapshot {
    tables: Vec<String>,
    metadata: Vec<(String, u64)>,
    domain: Vec<(String, Vec<u8>)>,
    rows: Vec<RawRows>,
    all_tables: Vec<(String, LogicalRows)>,
}

fn snapshot_table(read: &redb::ReadTransaction, name: &str) -> LogicalRows {
    // Capture every logical key/value, including unrelated schema and custody
    // indexes, without relying on physical page placement after rollback.
    macro_rules! try_table {
        ($key:ty, $value:ty) => {
            if let Ok(table) = read.open_table(TableDefinition::<$key, $value>::new(name)) {
                return table
                    .iter()
                    .expect("snapshot rows")
                    .map(|row| {
                        let (key, value) = row.expect("snapshot row");
                        (format!("{:?}", key.value()), format!("{:?}", value.value()))
                    })
                    .collect();
            }
        };
    }
    try_table!(&[u8], &[u8]);
    try_table!(&[u8], u64);
    try_table!(&str, &[u8]);
    try_table!(&str, u64);
    try_table!(u64, &[u8]);
    panic!("unexpected fixture table type: {name}");
}

fn legacy_snapshot(path: &Path) -> LegacySnapshot {
    let database = redb::Database::open(path).expect("raw reopen");
    let read = database.begin_read().expect("read snapshot");
    assert_eq!(
        read.list_multimap_tables().expect("multimap list").count(),
        0
    );
    let tables: Vec<String> = read
        .list_tables()
        .expect("table list")
        .map(|table| table.name().to_owned())
        .collect();
    let all_tables = tables
        .iter()
        .map(|name| (name.clone(), snapshot_table(&read, name)))
        .collect();
    let metadata = read
        .open_table(METADATA)
        .expect("metadata")
        .iter()
        .expect("metadata rows")
        .map(|row| {
            let (key, value) = row.expect("metadata row");
            (key.value().to_owned(), value.value())
        })
        .collect();
    let domain = read
        .open_table(SEMANTIC_DOMAIN)
        .expect("domain")
        .iter()
        .expect("domain rows")
        .map(|row| {
            let (key, value) = row.expect("domain row");
            (key.value().to_owned(), value.value().to_vec())
        })
        .collect();
    let rows = [
        EVENT_OPERATIONS,
        EVENT_OPERATION_WITNESSES,
        EVENTS,
        EVENT_BYTES,
        SEMANTIC_ITEMS,
        ACCEPTED_DOTS,
        ACCEPTED_EVENTS,
        custody::CUSTODY_RETIREMENTS,
        custody::CUSTODY_RETIRED_SEMANTICS,
    ]
    .into_iter()
    .map(|table| {
        read.open_table(table)
            .expect("legacy table")
            .iter()
            .expect("legacy rows")
            .map(|row| {
                let (key, value) = row.expect("legacy row");
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect()
    })
    .collect();
    LegacySnapshot {
        tables,
        metadata,
        domain,
        rows,
        all_tables,
    }
}

fn reject_unchanged(
    file: &TestFile,
    mission: NodeId,
    limits: EventOperationLimits,
    variant: &str,
    display: &str,
) {
    let before = legacy_snapshot(&file.0);
    let error = Store::open_with_limits_and_operation_limits_for_mission(
        &file.0,
        StoreLimits::default(),
        BlobDepotLimits::default(),
        limits,
        mission,
    )
    .err()
    .expect("migration must fail closed");
    assert_eq!(format!("{error:?}"), variant);
    assert_eq!(error.to_string(), display);
    assert_eq!(
        legacy_snapshot(&file.0),
        before,
        "failed migration changed the durable legacy image"
    );
}

fn assert_migrated(file: &TestFile, mission: NodeId, active: u64, retired: u64, bytes: u64) {
    let store = Store::open_for_mission(&file.0, mission).expect("migration open");
    drop(store);
    let store = Store::open_for_mission(&file.0, mission).expect("v3 reopen");
    let read = store.database.begin_read().expect("v3 read");
    assert_eq!(
        read.open_table(EVENT_OPERATIONS)
            .expect("legacy table")
            .len()
            .expect("legacy count"),
        0
    );
    assert_eq!(
        read.open_table(EVENT_OPERATION_WITNESSES)
            .expect("witness table")
            .len()
            .expect("witness count"),
        0
    );
    let metadata = read.open_table(METADATA).expect("metadata");
    for (field, expected) in
        V3_COUNTERS
            .into_iter()
            .zip([active + retired, active, retired, active, bytes])
    {
        assert_eq!(
            metadata
                .get(field)
                .expect("v3 counter")
                .expect("present v3 counter")
                .value(),
            expected
        );
    }
    for field in [
        EVENT_OPERATION_COUNT,
        EVENT_OPERATION_TOTAL_BYTES,
        EVENT_TOMBSTONE_OPERATION_COUNT,
        EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES,
    ] {
        assert_eq!(
            metadata
                .get(field)
                .expect("legacy counter")
                .expect("legacy counter present")
                .value(),
            0
        );
    }
    assert_eq!(
        read.open_table(EVENT_OPERATION_LEDGER_V3)
            .expect("ledger")
            .len()
            .expect("ledger rows"),
        active + retired
    );
    assert_eq!(
        read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)
            .expect("reverse")
            .len()
            .expect("reverse rows"),
        active
    );
    drop((metadata, read));
    assert_eq!(
        store.event_stats().expect("Event stats").operation_stats,
        EventOperationStats {
            records_total: active + retired,
            records_active: active,
            records_retired: retired,
            reverse_rows: active,
            logical_bytes: bytes,
        }
    );
    drop(store);
    Store::inspect_existing(&file.0).expect("read-only v3 audit");
}

#[test]
fn migration_v2_preserves_64_distinct_aliases_and_moves_ordinary_accounting() {
    let (file, mission, transfer) = legacy_fixture("migration v2 aliases", 64, false);
    let before = legacy_snapshot(&file.0);
    let old_intent = before.rows[0][0].1[66..98].to_vec();
    assert_migrated(&file, mission, 64, 0, 10_368);
    let database = redb::Database::open(&file.0).expect("raw reopen");
    let read = database.begin_read().expect("read migrated rows");
    let ledger = read.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
    let reverse = read
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse");
    let expected_fingerprints: std::collections::BTreeSet<[u8; 32]> = (0..64)
        .map(|index| {
            let preimage = [
                b"aster/event-operation-key/v1".as_slice(),
                &mission,
                &[0, 2, 0x81, index],
            ]
            .concat();
            Sha256::digest(preimage).into()
        })
        .collect();
    let mut actual_fingerprints = std::collections::BTreeSet::new();
    for row in ledger.iter().expect("ledger rows") {
        let (key, value) = row.expect("ledger row");
        assert_eq!(key.value().len(), 32);
        actual_fingerprints.insert(<[u8; 32]>::try_from(key.value()).expect("fingerprint"));
        assert_eq!(value.value().len(), 66);
        assert_eq!(&value.value()[..2], &[1, 1]);
        assert_eq!(&value.value()[2..34], old_intent);
        assert_eq!(&value.value()[34..], transfer.as_bytes());
        let reverse_key = [transfer.as_bytes().as_slice(), key.value()].concat();
        assert_eq!(
            reverse
                .get(reverse_key.as_slice())
                .expect("reverse lookup")
                .expect("matching reverse row")
                .value(),
            &[]
        );
    }
    assert_eq!(actual_fingerprints, expected_fingerprints);
}

#[test]
fn migration_witnessed_v1_reconstructs_the_exact_authenticated_intent() {
    let (file, mission, _) = legacy_fixture("migration witnessed v1", 2, true);
    let publisher = decode_event_metadata(&legacy_snapshot(&file.0).rows[2][0].1)
        .expect("accepted metadata")
        .header
        .stamp
        .dot
        .publisher;
    let expected = expected_fixture_intent(publisher, 1, None);
    assert_migrated(&file, mission, 2, 0, 324);
    let database = redb::Database::open(&file.0).expect("raw reopen");
    let read = database.begin_read().expect("read");
    for row in read
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .iter()
        .expect("rows")
    {
        assert_eq!(&row.expect("row").1.value()[2..34], &expected);
    }
}

fn expected_fixture_intent(
    publisher: NodeId,
    suffix: u8,
    predecessor: Option<EventSemanticId>,
) -> [u8; 32] {
    // Independent literal canonical preimage: publisher, topic, scope, Routine,
    // logical key f/1, seven-byte payload digest, non-tombstone, TTL, no predecessor.
    let mut canonical = b"aster/event-publication-intent/v2".to_vec();
    canonical.extend_from_slice(&publisher);
    canonical.extend_from_slice(b"\x00\x0amesh-event\x00\x0emission/events\x00\x00\x00\x00\x02f");
    canonical.push(suffix);
    canonical.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x07");
    canonical.extend_from_slice(&[
        0x23, 0x9f, 0x59, 0xed, 0x55, 0xe7, 0x37, 0xc7, 0x71, 0x47, 0xcf, 0x55, 0xad, 0x0c, 0x1b,
        0x03, 0x0b, 0x6d, 0x7e, 0xe7, 0x48, 0xa7, 0x42, 0x69, 0x52, 0xf9, 0xb8, 0x52, 0xd5, 0xa9,
        0x35, 0xe5,
    ]);
    canonical.extend_from_slice(b"\x00\x01\x00\x00\x00\x00\x00\x00\x27\x10");
    match predecessor {
        Some(id) => {
            canonical.push(1);
            canonical.extend_from_slice(id.as_bytes());
        }
        None => canonical.push(0),
    }
    Sha256::digest(canonical).into()
}

#[test]
fn migration_witnessless_v1_rejects_even_with_retained_sealed_bytes() {
    let (file, mission, _) = legacy_fixture("migration witnessless", 1, true);
    let database = redb::Database::open(&file.0).expect("raw open");
    let write = database.begin_write().expect("write");
    write
        .delete_table(EVENT_OPERATION_WITNESSES)
        .expect("remove witness");
    write
        .open_table(EVENT_OPERATION_WITNESSES)
        .expect("empty witnesses");
    write.commit().expect("commit witnessless fixture");
    drop(database);
    reject_unchanged(
        &file,
        mission,
        EventOperationLimits::DEFAULT,
        "EventOperationMigrationMissingAuthenticatedIntent",
        "Event operation migration lacks authenticated intent",
    );
}

#[test]
fn migration_alias_65_rejects_the_entire_legacy_map() {
    let (file, mission, _) = legacy_fixture("migration 65 aliases", 65, false);
    reject_unchanged(
        &file,
        mission,
        EventOperationLimits::DEFAULT,
        "EventOperationMigrationAliasOverflow",
        "Event operation migration exceeds the alias limit",
    );
}

#[test]
fn migration_destination_count_and_byte_limits_reject_atomically() {
    for limits in [
        EventOperationLimits::new(2, 10_000, 1).expect("count limit"),
        EventOperationLimits::new(10, 485, 1).expect("byte limit"),
    ] {
        let (file, mission, _) = legacy_fixture("migration destination full", 3, false);
        reject_unchanged(
            &file,
            mission,
            limits,
            "EventOperationMigrationDestinationCapacity",
            "Event operation migration exceeds destination capacity",
        );
    }
}

#[test]
fn migration_fingerprint_collision_rejects_distinct_keys_with_identical_intent() {
    let (file, mission, _) = legacy_fixture("migration fingerprint collision", 2, false);
    let _reset = FaultReset;
    MIGRATION_TEST_FAULT.set(1);
    reject_unchanged(
        &file,
        mission,
        EventOperationLimits::DEFAULT,
        "EventOperationMigrationFingerprintCollision",
        "Event operation migration fingerprint collision",
    );
}

#[test]
fn migration_abort_immediately_before_commit_preserves_the_legacy_image() {
    let (file, mission, _) = legacy_fixture("migration precommit abort", 2, true);
    let _reset = FaultReset;
    MIGRATION_TEST_FAULT.set(2);
    reject_unchanged(
        &file,
        mission,
        EventOperationLimits::DEFAULT,
        "SemanticInvariant(\"injected Event operation migration abort\")",
        "durable semantic Event invariant failed: injected Event operation migration abort",
    );
    MIGRATION_TEST_FAULT.set(0);
    assert_migrated(&file, mission, 2, 0, 324);
}

#[test]
fn migration_requires_durable_mission_binding_even_when_the_caller_supplies_one() {
    let (file, mission, _) = legacy_fixture("migration missing mission", 1, false);
    let database = redb::Database::open(&file.0).expect("raw open");
    let write = database.begin_write().expect("write");
    write
        .open_table(SEMANTIC_DOMAIN)
        .expect("domain")
        .remove(MISSION_AUTHORITY_ID)
        .expect("remove binding");
    write.commit().expect("commit unbound fixture");
    drop(database);
    reject_unchanged(
        &file,
        mission,
        EventOperationLimits::DEFAULT,
        "EventOperationMigrationMissingMissionBinding",
        "Event operation migration lacks a mission binding",
    );
}

#[test]
fn migration_partial_v3_and_mixed_complete_v3_never_replace_legacy_rows() {
    for complete in [false, true] {
        let (file, mission, _) = legacy_fixture("migration mixed schema", 1, false);
        let database = redb::Database::open(&file.0).expect("raw open");
        let write = database.begin_write().expect("write");
        write
            .open_table(EVENT_OPERATION_LEDGER_V3)
            .expect("partial ledger");
        if complete {
            write
                .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                .expect("reverse");
            let mut metadata = write.open_table(METADATA).expect("metadata");
            for counter in V3_COUNTERS {
                metadata.insert(counter, 0).expect("zero counter");
            }
        }
        write.commit().expect("commit mixed fixture");
        drop(database);
        let reason = if complete {
            "Event operation ledger coexists with legacy rows"
        } else {
            "Event operation ledger schema group is incomplete"
        };
        reject_unchanged(
            &file,
            mission,
            EventOperationLimits::DEFAULT,
            &format!("SemanticInvariant({reason:?})"),
            &format!("durable semantic Event invariant failed: {reason}"),
        );
    }
}

#[test]
fn migration_distinguishes_lease_withheld_retained_events_from_retirement_receipts() {
    let file = TestFile::new("migration retained and retired");
    let mut services = event_services(0x7a);
    let store = Store::open_for_mission(&file.0, services.authority).expect("fixture store");
    let active = accept_local_finite_event(&store, &mut services, 1, b"active", 10_000, SAMPLE);
    let withheld = accept_local_finite_event(&store, &mut services, 2, b"withheld", 100, SAMPLE);
    let retired = accept_local_finite_event(&store, &mut services, 3, b"retired", 100, SAMPLE);
    store
        .begin_custody_send(
            services.relay.identity(),
            CustodyObjectKey::event(withheld),
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("revision"),
        )
        .expect("hold transfer lease");
    let report = store
        .collect_custody_garbage(
            Some(aster_mesh::CustodySample {
                tick_ms: 1_100,
                ..SAMPLE
            }),
            store.custody_policy_revision().expect("revision"),
            10,
        )
        .expect("retire expired fixture");
    assert_eq!(report.blocked_by_leases, 1);
    assert_eq!(report.retired, vec![CustodyObjectKey::event(retired)]);
    let write = store.database.begin_write().expect("fixture write");
    remove_v3(&write);
    write.commit().expect("released fixture");
    drop(store);
    assert_migrated(&file, services.authority, 2, 1, 391);
    let database = redb::Database::open(&file.0).expect("raw reopen");
    let read = database.begin_read().expect("read");
    let mut active_targets = std::collections::BTreeSet::new();
    let mut retired_rows = 0;
    for row in read
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .iter()
        .expect("rows")
    {
        let (_, value) = row.expect("row");
        match value.value()[1] {
            1 => {
                active_targets.insert(EventTransferId::new(
                    value.value()[34..66].try_into().expect("transfer"),
                ));
            }
            2 => {
                assert_eq!(value.value().len(), 35);
                assert_eq!(value.value()[34], 1);
                retired_rows += 1;
            }
            state => panic!("unexpected state {state}"),
        }
    }
    assert_eq!(active_targets, [active, withheld].into());
    assert_eq!(retired_rows, 1);
}

#[test]
fn migration_witnessed_v1_retains_the_authenticated_predecessor_in_its_digest() {
    let file = TestFile::new("migration witnessed predecessor");
    let mut services = event_services(0x7b);
    let store = Store::open_for_mission(&file.0, services.authority).expect("store");
    let first = accept_local_finite_event(&store, &mut services, 1, b"payload", 10_000, SAMPLE);
    let predecessor = store
        .get_event(first)
        .expect("Event")
        .expect("accepted predecessor")
        .semantic_id;
    let second = accept_local_finite_event(&store, &mut services, 2, b"payload", 10_000, SAMPLE);
    let write = store.database.begin_write().expect("write");
    remove_v3(&write);
    let mut legacy = vec![1];
    legacy.extend_from_slice(second.as_bytes());
    legacy.push(1);
    legacy.extend_from_slice(predecessor.as_bytes());
    write
        .open_table(EVENT_OPERATIONS)
        .expect("operations")
        .insert(&[b'f', 2][..], legacy.as_slice())
        .expect("legacy row");
    write
        .open_table(METADATA)
        .expect("metadata")
        .insert(EVENT_OPERATION_TOTAL_BYTES, 168)
        .expect("100-byte v2 plus 68-byte v1");
    write.commit().expect("v1 fixture");
    // Establish the witness through the released capability-checking API.
    let stored = store
        .get_event(second)
        .expect("Event")
        .expect("retained reaction");
    let event = content_event(&mut services.reader, &stored.sealed);
    let intent = event_publication_intent(event.header(), b"payload");
    let key = EventOperationKey::new(vec![b'f', 2]).expect("key");
    let request =
        EventOperationRequest::new(&key, &intent, b"payload", Some(predecessor)).expect("request");
    store
        .bind_legacy_event_operation_intent_with_policy(
            &store.control_policy_snapshot().expect("policy"),
            &request,
            &event,
            &stored.sealed,
        )
        .expect("bind authenticated witness")
        .expect("bound reaction");
    let expected =
        expected_fixture_intent(event.header().stamp.dot.publisher, 2, Some(predecessor));
    drop(store);
    assert_migrated(&file, services.authority, 2, 0, 324);
    let database = redb::Database::open(&file.0).expect("raw reopen");
    let read = database.begin_read().expect("read");
    let rows = read.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
    let reaction = rows
        .iter()
        .expect("rows")
        .map(|row| row.expect("row").1.value().to_vec())
        .find(|bytes| &bytes[34..] == second.as_bytes())
        .expect("reaction ledger record");
    assert_eq!(&reaction[2..34], &expected);
}

#[test]
fn migration_corrupt_v2_intent_and_missing_v1_metadata_preserve_all_tables() {
    for v1 in [false, true] {
        let (file, mission, transfer) = legacy_fixture("migration invalid source", 1, v1);
        let database = redb::Database::open(&file.0).expect("raw open");
        let write = database.begin_write().expect("write");
        if v1 {
            write
                .open_table(EVENTS)
                .expect("events")
                .remove(transfer.as_bytes().as_slice())
                .expect("remove metadata");
        } else {
            let mut operations = write.open_table(EVENT_OPERATIONS).expect("operations");
            let mut bytes = operations
                .get(&[0x81, 0][..])
                .expect("row")
                .expect("operation")
                .value()
                .to_vec();
            bytes[66] ^= 1;
            operations
                .insert(&[0x81, 0][..], bytes.as_slice())
                .expect("corrupt intent");
        }
        write.commit().expect("commit invalid fixture");
        drop(database);
        let (variant, display) = if v1 {
            (
                "EventOperationMigrationMissingAuthenticatedIntent",
                "Event operation migration lacks authenticated intent",
            )
        } else {
            (
                "SemanticInvariant(\"Event operation intent differs from retained Event metadata\")",
                "durable semantic Event invariant failed: Event operation intent differs from retained Event metadata",
            )
        };
        reject_unchanged(
            &file,
            mission,
            EventOperationLimits::DEFAULT,
            variant,
            display,
        );
    }
}

struct MigrationDepotRoot(PathBuf);

impl MigrationDepotRoot {
    fn new() -> Self {
        let path = TestFile::new("migration physical depot")
            .0
            .with_extension("directory");
        std::fs::create_dir(&path).expect("create isolated fixture directory");
        Self(path)
    }
}

impl Drop for MigrationDepotRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn migration_missing_physical_depot_marker_preserves_the_complete_legacy_image() {
    let root = MigrationDepotRoot::new();
    let file = TestFile(root.0.join("store.redb"));
    let mut services = event_services(0x7c);
    let store = Store::open_for_mission(&file.0, services.authority).expect("store");
    accept_local_finite_event(&store, &mut services, 1, b"payload", 10_000, SAMPLE);
    drop(store.blob_depot().expect("establish physical owner marker"));
    let write = store.database.begin_write().expect("released fixture");
    // Exercise the durable-token fast path that precedes physical validation.
    assert_ne!(
        blob::depot::depot_owner_token_write(&write).expect("durable owner token"),
        [0; 32]
    );
    remove_v3(&write);
    write.commit().expect("commit released legacy image");
    drop(store);
    let marker = root.0.join("blob-depot-v1/.aster-store-owner-v1");
    let saved_marker = root.0.join("owner-marker.saved");
    std::fs::rename(&marker, &saved_marker).expect("withhold exact owner marker");
    let before = legacy_snapshot(&file.0);
    let error = Store::open_for_mission(&file.0, services.authority)
        .err()
        .expect("missing owner marker must reject open");
    assert!(matches!(
        error,
        StoreError::Blob(BlobStoreError::DepotIntegrity(
            "fixed Blob depot root is missing its owner marker"
        ))
    ));
    assert!(
        !marker.exists(),
        "failed open must not repair the owner marker"
    );
    assert!(
        legacy_snapshot(&file.0) == before,
        "physical depot validation failed after committing the legacy operation migration"
    );
    std::fs::rename(&saved_marker, &marker).expect("restore exact fixture marker");
    assert_migrated(&file, services.authority, 1, 0, 162);
}

#[test]
fn migration_clears_nonzero_legacy_tombstone_operation_counters() {
    let file = TestFile::new("migration tombstone operation");
    let mut services = event_services(0x7d);
    let store = Store::open_for_mission(&file.0, services.authority).expect("store");
    let policy = store.control_policy_snapshot().expect("policy");
    let operation = EventOperationKey::new(vec![0x82, 1]).expect("operation key");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let header = reservation
        .header(Priority::Routine, b"deleted".to_vec(), None, 0, true, 1)
        .expect("tombstone header");
    let intent = event_publication_intent(&header, b"");
    let request = EventOperationRequest::new(&operation, &intent, b"", None).expect("request");
    let sealed = services
        .publisher
        .seal_event(&header, b"")
        .expect("seal tombstone");
    let event = content_event(&mut services.reader, &sealed.bytes);
    let transfer = match store
        .commit_reserved_event_once_with_policy(
            &policy,
            &request,
            &reservation,
            &event,
            &sealed.bytes,
        )
        .expect("publish tombstone")
    {
        EventOnceOutcome::Inserted { transfer_id, .. } => transfer_id,
        outcome => panic!("unexpected publication outcome: {outcome:?}"),
    };
    let write = store
        .database
        .begin_write()
        .expect("released tombstone fixture");
    remove_v3(&write);
    {
        let metadata = write.open_table(METADATA).expect("metadata");
        assert_eq!(
            metadata
                .get(EVENT_TOMBSTONE_OPERATION_COUNT)
                .expect("count")
                .expect("counter")
                .value(),
            1
        );
        // Two raw key bytes plus the 98-byte v2 record, without a predecessor.
        assert_eq!(
            metadata
                .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)
                .expect("bytes")
                .expect("counter")
                .value(),
            100
        );
    }
    let expected_intent = write
        .open_table(EVENT_OPERATIONS)
        .expect("operations")
        .get(operation.as_bytes())
        .expect("row")
        .expect("tombstone operation")
        .value()[66..98]
        .to_vec();
    write.commit().expect("commit released tombstone fixture");
    drop(store);
    assert_migrated(&file, services.authority, 1, 0, 162);
    let reopened = Store::open_for_mission(&file.0, services.authority).expect("reopen tombstone");
    assert!(
        reopened
            .get_event(transfer)
            .expect("Event")
            .expect("retained tombstone")
            .header
            .tombstone
    );
    let read = reopened.database.begin_read().expect("read v3");
    let row = read
        .open_table(EVENT_OPERATION_LEDGER_V3)
        .expect("ledger")
        .iter()
        .expect("rows")
        .next()
        .expect("tombstone record")
        .expect("row")
        .1
        .value()
        .to_vec();
    assert_eq!(&row[..2], &[1, 1]);
    assert_eq!(&row[2..34], &expected_intent);
    assert_eq!(&row[34..], transfer.as_bytes());
}
