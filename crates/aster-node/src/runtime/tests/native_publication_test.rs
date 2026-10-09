use super::*;

#[test]
fn native_publication_recovers_committed_unapplied_intent_without_republishing() {
    let state = root("native-numbered-lost-reply");
    fs::create_dir_all(&state).unwrap();
    let mission = demo_member_mission();
    let mut sealer = open_test_sealer(&mission);
    let path = state.join(STORE_FILE);
    let store = Store::open_for_mission(&path, mission.mission_authority_id()).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let client = aster_redb_store::EventClientId::new(b"aster.native.ping.v1".to_vec()).unwrap();
    let mut journal = crate::demo_publication::Journal::open(&store, client.clone()).unwrap();
    journal
        .retain(
            &store,
            crate::demo_publication::Intent {
                sequence: 0,
                input_marker: 0,
                predecessor: None,
                logical_key: DEMO_PING_LOGICAL_KEY.to_vec(),
                payload: DEMO_PING_PAYLOAD.to_vec(),
                applied: false,
            },
        )
        .unwrap();
    let session = journal.session().unwrap();
    let committed = publish_selected_numbered_event_once(
        &store,
        &policy,
        &mut sealer,
        NumberedEventPublishRequest {
            client_id: client,
            session,
            sequence: aster_redb_store::EventOperationSequence::new(1).unwrap(),
            predecessor: None,
            topic: demo_event_topic().unwrap(),
            scope: demo_scope().unwrap(),
            priority: Priority::Immediate,
            logical_key: DEMO_PING_LOGICAL_KEY.to_vec(),
            payload: DEMO_PING_PAYLOAD.to_vec(),
            tombstone: false,
        },
        EventPublishOptions::durable(),
        None,
    )
    .unwrap();
    assert!(committed.inserted);
    drop(journal); // Crash after commit, before receipt application/acknowledgement.
    drop(store);
    let store = Store::open_for_mission(&path, mission.mission_authority_id()).unwrap();
    let clock = NodeCustodyClock::injected([0xe1; 16], 0, 0);
    let cache = AuthenticatedEventRouteCache::empty(&sealer);
    let mut tracker = SelectedEventStatusTracker::new(BTreeSet::new(), false);
    for _ in 0..2 {
        let mut journal = None;
        drive_sample_application(
            NodeApplication::PingEmitter,
            SampleApplicationContext {
                store: &store,
                policy: &policy,
                sealer: &mut sealer,
                custody_clock: &clock,
                event_route_cache: &cache,
            },
            &mut journal,
            &mut false,
            &mut tracker,
        )
        .unwrap();
        let journal = journal.unwrap();
        assert!(journal.session().unwrap().get() > session.get());
        assert!(journal.ping_completed());
        assert!(journal.pending().is_none());
        assert_eq!(
            journal.last_event(),
            Some(*committed.result.receipt.semantic_id.as_bytes())
        );
        assert_eq!(
            store
                .numbered_event_operation_stats()
                .unwrap()
                .outstanding_results,
            0
        );
        assert_eq!(
            store.committed_numbered_event_publication_count().unwrap(),
            1
        );
        assert_eq!(store.event_operation_stats().unwrap().records_total, 0);
    }
    assert_eq!(
        tracker
            .operation_rate
            .snapshot(tokio::time::Instant::now(), 1)
            .0,
        0.0
    );
    drop(store);
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn native_publication_refuses_missing_or_corrupt_registered_client_checkpoint() {
    let state = root("native-numbered-missing-checkpoint");
    fs::create_dir_all(&state).unwrap();
    let mission = demo_member_mission();
    let store =
        Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id()).unwrap();
    let client = aster_redb_store::EventClientId::new(b"aster.native.ping.v1".to_vec()).unwrap();
    let mut claim = [0; 32];
    getrandom::fill(&mut claim).expect("random publication claim");
    let snapshot = store
        .begin_event_publication_session(&client, 0, &claim)
        .unwrap();
    assert!(crate::demo_publication::Journal::open(&store, client.clone()).is_err());
    store
        .save_event_publication_checkpoint(&client, b"{}")
        .unwrap();
    assert!(crate::demo_publication::Journal::open(&store, client.clone()).is_err());
    // Both failures happened before a new claim could fence the original owner.
    assert_eq!(
        store
            .begin_event_publication_session(&client, 0, &claim)
            .unwrap()
            .session,
        snapshot.session
    );
    drop(store);
    fs::remove_dir_all(state).unwrap();
}
