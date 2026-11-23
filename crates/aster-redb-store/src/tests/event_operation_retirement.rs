use super::*;

const SAMPLE: aster_mesh::CustodySample = aster_mesh::CustodySample {
    clock_id: [0xa5; 16],
    tick_ms: 1_000,
};
const EXPIRED: aster_mesh::CustodySample = aster_mesh::CustodySample {
    tick_ms: 1_100,
    ..SAMPLE
};

fn retire(store: &Store) -> Result<CustodyGcReport, StoreError> {
    store.collect_custody_garbage(Some(EXPIRED), store.custody_policy_revision()?, 64)
}

struct NumberedReplay {
    reservation: EventReservation,
    intent: EventPublicationIntent,
    sealed: Vec<u8>,
}

fn numbered_finite_fixture(
    priority: Priority,
) -> (
    TestFile,
    EventServices,
    Store,
    EventClientId,
    EventRecoverySnapshot,
    NumberedEventResult,
    NumberedReplay,
) {
    let file = TestFile::new("numbered finite retirement");
    let mut services = event_services(0xa6);
    let store = Store::open_for_mission(&file.0, services.authority).expect("store");
    let client = EventClientId::new(b"numbered-retirement".to_vec()).expect("client");
    let claimed = store
        .begin_event_publication_session(&client, 0, b"initial-claim")
        .expect("claim client");
    store
        .complete_event_publication_recovery(&client, claimed.session, claimed.snapshot_revision)
        .expect("complete initial recovery");
    let policy = store.control_policy_snapshot().expect("control policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let payload = b"numbered";
    let header = reservation
        .header(
            priority,
            b"numbered-retirement".to_vec(),
            Some(100),
            payload.len() as u64,
            false,
            1,
        )
        .expect("header");
    let intent = event_publication_intent(&header, payload);
    let request = NumberedEventOperationRequest::new(
        &client,
        claimed.session,
        EventOperationSequence::new(1).expect("sequence"),
        None,
        &intent,
        payload,
    )
    .expect("numbered request");
    let sealed = services
        .publisher
        .seal_event(&header, payload)
        .expect("seal");
    let event = content_event(&mut services.reader, &sealed.bytes);
    let published = store
        .commit_reserved_numbered_event_with_custody_policy(
            &policy,
            LocalCustodyCheckpoint::new(
                store.custody_policy_revision().expect("custody revision"),
                SAMPLE,
            ),
            &request,
            &reservation,
            &event,
            &sealed.bytes,
        )
        .expect("numbered finite commit");
    assert!(published.inserted);
    assert_eq!(published.result.content, CommittedEventContent::Available);
    let before = store
        .begin_event_publication_session(&client, claimed.session.get(), b"before-retirement")
        .expect("recover committed result");
    assert_eq!(before.outstanding, vec![published.result]);
    (
        file,
        services,
        store,
        client,
        before,
        published.result,
        NumberedReplay {
            reservation,
            intent,
            sealed: sealed.bytes,
        },
    )
}

#[test]
fn numbered_result_retires_at_expiry_mark_while_lease_holds_payload() {
    let (_file, services, store, client, before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("lease revision"),
        )
        .expect("active transfer lease");

    let marked = retire(&store).expect("mark expired Event");
    assert_eq!(marked.marked, vec![key]);
    assert!(marked.retired.is_empty());
    assert_eq!(marked.blocked_by_leases, 1);
    assert_eq!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("logical lookup"),
        None
    );
    assert_eq!(store.event_stats().expect("retained bytes").events, 1);
    assert!(matches!(
        store.complete_event_publication_recovery(
            &client,
            before.session,
            before.snapshot_revision,
        ),
        Err(StoreError::NumberedEventOperation(
            NumberedEventOperationError::RecoveryRevisionChanged
        ))
    ));
    assert_eq!(
        crate::numbered_event_operation::client_snapshot_revision_for_test(&store, &client)
            .expect("durable normalized revision"),
        before.snapshot_revision + 1
    );
    let first = store
        .begin_event_publication_session(&client, before.session.get(), b"after-mark")
        .expect("recover after logical mark");
    assert_eq!(first.outstanding.len(), 1);
    assert_eq!(first.outstanding[0].receipt, published.receipt);
    assert_eq!(
        first.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    );
    assert_eq!(first.snapshot_revision, before.snapshot_revision + 1);

    let repeated = retire(&store).expect("repeat mark while leased");
    assert!(repeated.marked.is_empty());
    assert!(repeated.retired.is_empty());
    assert_eq!(repeated.blocked_by_leases, 1);
    let replay = store
        .begin_event_publication_session(&client, first.session.get(), b"after-repeat")
        .expect("recover after repeat");
    assert_eq!(replay.snapshot_revision, first.snapshot_revision);
    assert_eq!(replay.outstanding, first.outstanding);

    store
        .release_transfer_lease(lease.id)
        .expect("release lease");
    let finalized = retire(&store).expect("finalize expiry");
    assert_eq!(finalized.retired, vec![key]);
    assert_eq!(store.event_stats().expect("after cleanup").events, 0);
    let after = store
        .begin_event_publication_session(&client, replay.session.get(), b"after-finalize")
        .expect("recover after physical cleanup");
    assert_eq!(after.snapshot_revision, first.snapshot_revision);
    assert_eq!(after.outstanding, first.outstanding);
}

#[test]
fn numbered_result_keeps_quota_pressure_reason_after_later_expiry() {
    let (_file, services, store, client, before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let quota_revision = store
        .set_custody_quota(CustodyQuota::global(1, 1_000_000).expect("quota"))
        .expect("set quota");
    let lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            quota_revision,
        )
        .expect("active transfer lease");
    assert!(
        store
            .collect_custody_pressure(
                None,
                CustodyPressureDemand {
                    usage: CustodyUsage { items: 1, bytes: 1 },
                    priority: Priority::Immediate,
                },
                Some(SAMPLE),
                quota_revision,
                1,
            )
            .is_err(),
        "held bytes cannot satisfy the requested quota"
    );
    assert_eq!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("logical lookup"),
        None
    );
    assert_eq!(store.event_stats().expect("retained bytes").events, 1);
    let marked = store
        .begin_event_publication_session(&client, before.session.get(), b"pressure-mark")
        .expect("recover pressure mark");
    assert_eq!(marked.outstanding.len(), 1);
    assert_eq!(marked.outstanding[0].receipt, published.receipt);
    assert_eq!(
        marked.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::QuotaPressure)
    );
    assert_eq!(marked.snapshot_revision, before.snapshot_revision + 1);

    store
        .release_transfer_lease(lease.id)
        .expect("release lease");
    let finalized = retire(&store).expect("finish after TTL elapsed");
    assert_eq!(finalized.retired, vec![key]);
    let after = store
        .begin_event_publication_session(&client, marked.session.get(), b"pressure-final")
        .expect("recover after finalization");
    assert_eq!(after.snapshot_revision, marked.snapshot_revision);
    assert_eq!(after.outstanding, marked.outstanding);
}

#[test]
fn numbered_cleanup_rejects_receipt_identity_corruption_without_retirement_progress() {
    const RESULTS: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-results.v1");

    let (_file, _services, store, client, _before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let revision_before =
        crate::numbered_event_operation::client_snapshot_revision_for_test(&store, &client)
            .expect("client revision before corruption");
    let write = store
        .database
        .begin_write()
        .expect("corrupt result receipt");
    let (key, mut value) = write
        .open_table(RESULTS)
        .expect("result table")
        .iter()
        .expect("result rows")
        .next()
        .expect("one result")
        .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
        .expect("read result");
    value[65] ^= 1;
    write
        .open_table(RESULTS)
        .expect("result table")
        .insert(key.as_slice(), value.as_slice())
        .expect("write corrupt semantic identity");
    write.commit().expect("commit result corruption");

    assert!(matches!(
        retire(&store),
        Err(StoreError::NumberedEventOperation(
            NumberedEventOperationError::Invariant(
                "numbered Event result differs from custody authority"
            )
        ))
    ));
    assert!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("retirement rollback keeps payload")
            .is_some()
    );
    assert_eq!(
        store.event_stats().expect("rollback stats").retiring_events,
        0
    );
    assert_eq!(
        crate::numbered_event_operation::client_snapshot_revision_for_test(&store, &client)
            .expect("client revision after rollback"),
        revision_before
    );
}

fn mutate_first_numbered_result(store: &Store, mutate: impl FnOnce(&mut [u8])) {
    const RESULTS: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-results.v1");

    let write = store
        .database
        .begin_write()
        .expect("corrupt numbered result");
    let (key, mut value) = write
        .open_table(RESULTS)
        .expect("result table")
        .iter()
        .expect("result rows")
        .next()
        .expect("one result")
        .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
        .expect("read result");
    mutate(&mut value);
    write
        .open_table(RESULTS)
        .expect("result table")
        .insert(key.as_slice(), value.as_slice())
        .expect("write corrupt result");
    write.commit().expect("commit result corruption");
}

#[test]
fn numbered_result_audits_reject_custody_authority_corruption_without_mutation() {
    enum Corruption {
        RetiredWithLiveCustody,
        WrongSemantic,
        WrongAcceptanceMarker,
        WrongRetirementReason,
        AvailableAtCleanFence,
    }

    for (index, corruption) in [
        Corruption::RetiredWithLiveCustody,
        Corruption::WrongSemantic,
        Corruption::WrongAcceptanceMarker,
        Corruption::WrongRetirementReason,
        Corruption::AvailableAtCleanFence,
    ]
    .into_iter()
    .enumerate()
    {
        let (file, services, store, _client, _before, published, _replay) =
            numbered_finite_fixture(Priority::Routine);
        if matches!(
            corruption,
            Corruption::WrongRetirementReason | Corruption::AvailableAtCleanFence
        ) {
            assert_eq!(
                retire(&store)
                    .expect("complete clean-fence retirement")
                    .retired,
                vec![CustodyObjectKey::event(published.receipt.transfer_id)]
            );
        }
        mutate_first_numbered_result(&store, |encoded| match corruption {
            Corruption::RetiredWithLiveCustody => {
                encoded[105] = 2;
                encoded[106] = CustodyRetirementReason::Expired as u8;
            }
            Corruption::WrongSemantic => encoded[65] ^= 1,
            Corruption::WrongAcceptanceMarker => {
                let marker = u64::from_be_bytes(encoded[97..105].try_into().expect("marker bytes"));
                encoded[97..105].copy_from_slice(&(marker + 1).to_be_bytes());
            }
            Corruption::WrongRetirementReason => {
                encoded[105] = 2;
                encoded[106] = CustodyRetirementReason::QuotaPressure as u8;
            }
            Corruption::AvailableAtCleanFence => {
                encoded[105] = 1;
                encoded[106] = 0;
            }
        });
        drop(store);

        for result in [
            Store::inspect_existing(&file.0).map(|_| ()),
            Store::open_for_mission(&file.0, services.authority).map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(StoreError::NumberedEventOperation(_))),
                "numbered authority corruption {index} was accepted: {result:?}"
            );
        }
    }
}

#[test]
fn numbered_result_audits_accept_raw_available_only_while_cleanup_is_pending() {
    let (marked_file, marked_services, marked_store, _client, _before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let _lease = marked_store
        .begin_custody_send(
            marked_services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            marked_store
                .custody_policy_revision()
                .expect("marked policy revision"),
        )
        .expect("hold marked payload");
    assert_eq!(
        retire(&marked_store).expect("mark with lease").marked,
        vec![key]
    );
    drop(marked_store);
    Store::inspect_existing(&marked_file.0).expect("inspect raw Marked result");
    drop(
        Store::open_for_mission(&marked_file.0, marked_services.authority)
            .expect("reopen raw Marked result"),
    );

    let (fenced_file, fenced_services, fenced_store, _client, _before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    seed_peer_receipt_fanout(&fenced_store, key, MAX_CUSTODY_PAGE);
    let fenced = retire(&fenced_store).expect("fence with pending cleanup");
    assert!(fenced.retired.is_empty());
    assert_eq!(fenced.examined_dependencies, MAX_CUSTODY_PAGE as u64);
    drop(fenced_store);
    Store::inspect_existing(&fenced_file.0).expect("inspect raw FencedCleaning result");
    drop(
        Store::open_for_mission(&fenced_file.0, fenced_services.authority)
            .expect("reopen raw FencedCleaning result"),
    );
}

#[test]
fn numbered_cleanup_rewrites_raw_pages_and_persists_client_revision() {
    let (file, services, store, client, _before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let write = store
        .database
        .begin_write()
        .expect("seed raw numbered fan-out");
    crate::numbered_event_operation::seed_numbered_result_fanout_write(
        &write,
        &client,
        published.receipt,
        1_024,
    )
    .expect("seed 1,025 raw results");
    write.commit().expect("commit raw numbered fan-out");
    let revision_before =
        crate::numbered_event_operation::client_snapshot_revision_for_test(&store, &client)
            .expect("revision before cleanup");

    let first = retire(&store).expect("rewrite first raw page");
    assert_eq!(first.marked, vec![key]);
    assert!(first.retired.is_empty());
    assert_eq!(first.examined_dependencies, MAX_CUSTODY_PAGE as u64);
    assert_eq!(first.examined_numbered_results, MAX_CUSTODY_PAGE as u64);
    assert_eq!(first.rewritten_numbered_results, MAX_CUSTODY_PAGE as u64);
    assert_eq!(
        crate::numbered_event_operation::client_snapshot_revision_for_test(&store, &client)
            .expect("revision after first raw page"),
        revision_before + MAX_CUSTODY_PAGE as u64
    );
    drop(store);

    let reopened =
        Store::open_for_mission(&file.0, services.authority).expect("reopen partial raw cleanup");
    let second = retire(&reopened).expect("rewrite final raw result");
    assert_eq!(second.retired, vec![key]);
    assert_eq!(second.examined_numbered_results, 1);
    assert_eq!(second.rewritten_numbered_results, 1);
    assert_eq!(
        crate::numbered_event_operation::client_snapshot_revision_for_test(&reopened, &client)
            .expect("revision after final raw result"),
        revision_before + 1_025
    );
    assert_eq!(
        reopened
            .numbered_event_operation_stats()
            .expect("numbered reverse-edge stats")
            .reverse_edges,
        1_025
    );
}

#[test]
fn malformed_durable_numbered_cursor_cannot_control_cleanup_after_reopen() {
    for foreign_prefix in [false, true] {
        let (file, services, store, client, _before, published, _replay) =
            numbered_finite_fixture(Priority::Routine);
        let write = store.database.begin_write().expect("seed cursor fan-out");
        crate::numbered_event_operation::seed_numbered_result_fanout_write(
            &write,
            &client,
            published.receipt,
            1_024,
        )
        .expect("seed cursor results");
        write.commit().expect("commit cursor fan-out");
        let first = retire(&store).expect("create durable cursor");
        assert!(first.retired.is_empty());

        let write = store
            .database
            .begin_write()
            .expect("corrupt cleanup cursor");
        let (cleanup_key, mut cleanup) = write
            .open_table(custody::CUSTODY_RETIRING)
            .expect("cleanup table")
            .iter()
            .expect("cleanup rows")
            .next()
            .expect("one cleanup row")
            .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
            .expect("read cleanup row");
        assert_eq!(cleanup[43], 1, "cursor must be present before corruption");
        if foreign_prefix {
            cleanup[48] ^= 1;
        } else {
            cleanup[44..48].copy_from_slice(&32u32.to_be_bytes());
            cleanup.truncate(80);
        }
        write
            .open_table(custody::CUSTODY_RETIRING)
            .expect("cleanup table")
            .insert(cleanup_key.as_slice(), cleanup.as_slice())
            .expect("write malformed cursor");
        write.commit().expect("commit malformed cursor");
        drop(store);

        for result in [
            Store::inspect_existing(&file.0).map(|_| ()),
            Store::open_for_mission(&file.0, services.authority).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(StoreError::NumberedEventOperation(
                    NumberedEventOperationError::Invariant(
                        "numbered Event cleanup cursor key is invalid"
                    )
                ))
            ));
        }
        let database = redb::Builder::new()
            .open_read_only(&file.0)
            .expect("read rejected image");
        let read = database.begin_read().expect("read transaction");
        assert_eq!(
            read.open_table(custody::CUSTODY_RETIRING)
                .expect("cleanup table")
                .get(cleanup_key.as_slice())
                .expect("read cleanup row")
                .expect("cleanup row retained")
                .value(),
            cleanup.as_slice(),
            "audit rejection must retain malformed cleanup control state"
        );
    }
}

#[test]
fn fenced_cleanup_audits_reject_wrong_queue_order() {
    let (file, services, store, _client, _before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let object = CustodyObjectKey::event(published.receipt.transfer_id);
    seed_peer_receipt_fanout(&store, object, MAX_CUSTODY_PAGE);
    let fenced = retire(&store).expect("fence with pending cleanup");
    assert!(fenced.retired.is_empty());

    let write = store.database.begin_write().expect("corrupt cleanup order");
    let (mut cleanup_key, cleanup_value) = write
        .open_table(custody::CUSTODY_RETIRING)
        .expect("cleanup table")
        .iter()
        .expect("cleanup rows")
        .next()
        .expect("one cleanup row")
        .map(|(key, value)| (key.value().to_vec(), value.value().to_vec()))
        .expect("read cleanup row");
    write
        .open_table(custody::CUSTODY_RETIRING)
        .expect("cleanup table")
        .remove(cleanup_key.as_slice())
        .expect("remove exact cleanup")
        .expect("cleanup existed");
    let order = u64::from_be_bytes(cleanup_key[..8].try_into().expect("order bytes"));
    cleanup_key[..8].copy_from_slice(&(order + 1).to_be_bytes());
    write
        .open_table(custody::CUSTODY_RETIRING)
        .expect("cleanup table")
        .insert(cleanup_key.as_slice(), cleanup_value.as_slice())
        .expect("insert wrong-order cleanup");
    write.commit().expect("commit wrong cleanup order");
    drop(store);

    for result in [
        Store::inspect_existing(&file.0).map(|_| ()),
        Store::open_for_mission(&file.0, services.authority).map(|_| ()),
    ] {
        assert!(
            matches!(
                result,
                Err(StoreError::Custody(CustodyStoreError::Invariant(
                    "custody retirement cleanup order differs from its authority"
                )))
            ),
            "wrong fenced cleanup order did not preserve its structural diagnostic: {result:?}"
        );
    }
}

#[test]
fn numbered_cleanup_cursor_bounds_canonical_prefix_and_preserves_reverse_edges() {
    let (file, mut services, store, client, before, published, replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let write = store.database.begin_write().expect("seed numbered fan-out");
    crate::numbered_event_operation::seed_numbered_result_fanout_write(
        &write,
        &client,
        published.receipt,
        1_024,
    )
    .expect("seed 1,025 total results");
    write.commit().expect("commit numbered fan-out");

    let lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("lease revision"),
        )
        .expect("hold marked payload");
    let marked = retire(&store).expect("mark while leased");
    assert_eq!(marked.blocked_by_leases, 1);

    let canonical = store
        .begin_event_publication_session(&client, before.session.get(), b"canonical-prefix")
        .expect("canonicalize marked results");
    assert_eq!(canonical.outstanding.len(), 1_025);
    assert!(canonical.outstanding.iter().all(|result| {
        result.content == CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    }));
    assert_eq!(
        store
            .numbered_event_operation_stats()
            .expect("canonical stats")
            .reverse_edges,
        1_025
    );

    store
        .release_transfer_lease(lease.id)
        .expect("release payload lease");
    let first = retire(&store).expect("first cursor page");
    assert!(first.retired.is_empty());
    assert_eq!(first.examined_dependencies, 1_024);
    assert_eq!(first.removed_pairs, 1);
    assert_eq!(first.examined_numbered_results, 1_023);
    assert_eq!(first.rewritten_numbered_results, 0);

    let behind = EventClientId::new(b"a".to_vec()).expect("behind-cursor client");
    let claim = store
        .begin_event_publication_session(&behind, 0, b"behind-cursor")
        .expect("claim behind client");
    store
        .complete_event_publication_recovery(&behind, claim.session, claim.snapshot_revision)
        .expect("complete behind recovery");
    let payload = b"numbered";
    let request = NumberedEventOperationRequest::new(
        &behind,
        claim.session,
        EventOperationSequence::new(1).expect("behind sequence"),
        None,
        &replay.intent,
        payload,
    )
    .expect("behind-cursor exact request");
    let event = content_event(&mut services.reader, &replay.sealed);
    let behind_result = store
        .commit_reserved_numbered_event_with_custody_policy(
            replay.reservation.control_policy(),
            LocalCustodyCheckpoint::new(
                store.custody_policy_revision().expect("custody revision"),
                EXPIRED,
            ),
            &request,
            &replay.reservation,
            &event,
            &replay.sealed,
        )
        .expect("retired exact replay behind cursor")
        .result;
    assert_eq!(
        behind_result.content,
        CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    );
    drop(store);
    let store = Store::open_for_mission(&file.0, services.authority).expect("reopen cursor state");

    let second = retire(&store).expect("finish cursor cleanup");
    assert_eq!(second.retired, vec![key]);
    assert_eq!(second.examined_numbered_results, 2);
    assert_eq!(second.rewritten_numbered_results, 0);
    assert_eq!(
        store
            .numbered_event_operation_stats()
            .expect("retained reverse stats")
            .reverse_edges,
        1_026
    );
    assert_eq!(
        store
            .acknowledge_event_publication_result(
                &behind,
                claim.session,
                EventOperationSequence::new(1).expect("behind sequence"),
            )
            .expect("ack behind result"),
        EventResultAcknowledgement::Acknowledged
    );
    assert_eq!(
        store
            .numbered_event_operation_stats()
            .expect("acknowledged reverse stats")
            .reverse_edges,
        1_025
    );
}

#[test]
fn numbered_retirement_invariant_is_reported_without_unbounded_mark_scan() {
    let (_file, services, store, client, before, published, _replay) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let _lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("lease revision"),
        )
        .expect("active transfer lease");
    const REVERSE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-result-by-event.v1");
    let edge = {
        let write = store.database.begin_write().expect("corrupt reverse edge");
        let mut reverse = write.open_table(REVERSE).expect("reverse table");
        let edge = reverse
            .iter()
            .expect("reverse rows")
            .next()
            .expect("one reverse row")
            .expect("reverse row")
            .0
            .value()
            .to_vec();
        reverse
            .insert(edge.as_slice(), b"invalid".as_slice())
            .expect("insert malformed reverse value");
        drop(reverse);
        write.commit().expect("commit malformed edge");
        edge
    };

    let marked = retire(&store).expect("constant-work mark does not scan result fan-out");
    assert_eq!(marked.marked, vec![key]);
    assert_eq!(marked.blocked_by_leases, 1);
    assert_eq!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("withheld Event"),
        None
    );
    assert_eq!(
        store.event_stats().expect("marked stats").retiring_events,
        1
    );
    store
        .begin_event_publication_session(&client, before.session.get(), b"after-failure")
        .expect_err("logical overlay validates the malformed reverse row");

    let write = store.database.begin_write().expect("repair reverse edge");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .insert(edge.as_slice(), &[][..])
        .expect("restore empty reverse value");
    write.commit().expect("commit reverse repair");
    let recovered = store
        .begin_event_publication_session(&client, before.session.get(), b"after-repair")
        .expect("recover after repaired mark");
    assert_eq!(recovered.snapshot_revision, before.snapshot_revision + 1);
    assert_eq!(
        recovered.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    );
}

#[test]
fn route_only_pressure_retirement_does_not_scan_numbered_result_edges() {
    let (_file, mut services, store, client, before, published, _replay) =
        numbered_finite_fixture(Priority::Flash);
    let payload = b"route-only";
    let mut header = event_header(
        services.publisher.identity(),
        2,
        2,
        VersionVector::default(),
        b"route-only",
        payload,
        None,
    );
    header.priority = Priority::Routine;
    let sealed = services
        .publisher
        .seal_event(&header, payload)
        .expect("seal route-only Event");
    let route = services
        .relay
        .verify_event(&sealed.bytes)
        .expect("verify route-only Event");
    let route_id = EventTransferId::new(route.envelope_id());
    store
        .cache_route_verified_event(&route, &sealed.bytes)
        .expect("cache route-only Event");
    let route_key = CustodyObjectKey::route_event(route_id);
    const REVERSE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-result-by-event.v1");
    let mut unrelated_edge = route_id.as_bytes().to_vec();
    unrelated_edge.push(0);
    let write = store
        .database
        .begin_write()
        .expect("inject unrelated reverse row");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .insert(unrelated_edge.as_slice(), b"invalid".as_slice())
        .expect("insert unrelated malformed edge");
    write.commit().expect("commit unrelated row");

    let revision = store
        .set_custody_quota(CustodyQuota::global(2, 1_000_000).expect("quota"))
        .expect("set quota");
    let retired = store
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
        .expect("route pressure retirement");
    assert_eq!(retired.retired, vec![route_key]);
    let recovered = store
        .begin_event_publication_session(&client, before.session.get(), b"after-route")
        .expect("recover numbered result");
    assert_eq!(recovered.snapshot_revision, before.snapshot_revision);
    assert_eq!(recovered.outstanding, vec![published]);

    let write = store.database.begin_write().expect("remove injected row");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .remove(unrelated_edge.as_slice())
        .expect("remove injected reverse edge");
    write.commit().expect("commit reverse cleanup");
}
