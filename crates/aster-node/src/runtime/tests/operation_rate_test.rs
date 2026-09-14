use super::*;

#[test]
fn operation_rate_sample_ping_pong_counts_new_records_and_excludes_replay() {
    let state = root("operation-rate-sample");
    fs::create_dir_all(&state).unwrap();
    let mission = demo_member_mission();
    let mut sealer = open_test_sealer(&mission);
    let store =
        Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id()).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let clock = NodeCustodyClock::injected([0xdf; 16], 0, 0);
    let cache = AuthenticatedEventRouteCache::empty(&sealer);
    let mut tracker = SelectedEventStatusTracker::new(BTreeSet::new(), false);
    for (role, expected_rate) in [
        (NodeApplication::PingEmitter, 1.0 / 60.0),
        (NodeApplication::PingEmitter, 1.0 / 60.0),
        (NodeApplication::PongResponder, 2.0 / 60.0),
        (NodeApplication::PongResponder, 2.0 / 60.0),
        (NodeApplication::Relay, 2.0 / 60.0),
    ] {
        // Reset cursors to force durable retry paths, as after restart.
        drive_sample_application(
            role,
            SampleApplicationContext {
                store: &store,
                policy: &policy,
                sealer: &mut sealer,
                custody_clock: &clock,
                event_route_cache: &cache,
            },
            &mut 0,
            &mut false,
            &mut tracker,
        )
        .unwrap();
        assert_eq!(
            tracker
                .operation_rate
                .snapshot(tokio::time::Instant::now(), 1)
                .0,
            expected_rate
        );
    }
    assert_eq!(store.event_operation_stats().unwrap().records_total, 2);
    drop(store);
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn operation_rate_window_expires_at_exact_monotonic_boundary_and_rounds_up() {
    let now = tokio::time::Instant::now();
    let mut rate = EventOperationAcceptRate::default();
    assert_eq!(rate.snapshot(now, 100), (0.0, 0));
    rate.record(now, 7);
    assert_eq!(rate.snapshot(now, 2), (7.0 / 60.0, 18));
    assert_eq!(rate.snapshot(now, u64::MAX).1, u64::MAX);
    rate.record(now + Duration::from_secs(30), 3);
    assert_eq!(
        rate.snapshot(now + Duration::from_secs(59), 2),
        (10.0 / 60.0, 12)
    );
    assert_eq!(
        rate.snapshot(now + Duration::from_secs(60), 2),
        (3.0 / 60.0, 40)
    );
    assert_eq!(rate.snapshot(now + Duration::from_secs(90), 2), (0.0, 0));
    rate.record(now + Duration::from_secs(90), 1);
    assert_eq!(
        rate.snapshot(now + Duration::from_secs(90), 0),
        (1.0 / 60.0, 0)
    );
}

#[test]
fn operation_rate_counts_committed_active_alias_and_direct_retired_fences_once() {
    let state = root("operation-rate-commit");
    fs::create_dir_all(&state).unwrap();
    let services = control_test_services([0xd8; 32]);
    let store = Store::open_with_limits_and_operation_limits_for_mission(
        state.join(STORE_FILE),
        StoreLimits::default(),
        BlobDepotLimits::DEFAULT,
        EventOperationLimits::new(5, 5 * 162, 1).unwrap(),
        services.other.mission_authority_id(),
    )
    .unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let mut sealer = open_test_sealer(&services.other);
    let reservation = store
        .reserve_event_with_policy(&policy, sealer.identity(), &services.topic, &services.scope)
        .unwrap();
    let header = reservation
        .header(Priority::Routine, b"rate".to_vec(), Some(100), 4, false, 1)
        .unwrap();
    let sealed = sealer.seal_event(&header, b"rate").unwrap();
    let route = sealer.verify_event(&sealed.bytes).unwrap();
    let EventContentVerification::ContentVerified { event, .. } =
        sealer.verify_event_content(route, &sealed.bytes).unwrap()
    else {
        panic!("content authority")
    };
    let intent = EventPublicationIntent::new(
        EventPublicationSpec::new(
            sealer.identity(),
            services.topic.clone(),
            services.scope.clone(),
            Priority::Routine,
            b"rate".to_vec(),
            false,
            Some(100),
        )
        .unwrap(),
        b"rate",
    )
    .unwrap();
    let mut tracker = SelectedEventStatusTracker::new(BTreeSet::new(), false);
    let clock_id = [0xd9; 16];
    let commit = |tracker: &mut SelectedEventStatusTracker, key: &[u8]| {
        let operation = EventOperationKey::new(key.to_vec()).unwrap();
        let request = EventOperationRequest::new(&operation, &intent, b"rate", None).unwrap();
        tracker.observe_operation_commit(&store, || {
            store.commit_reserved_event_once_with_custody_policy(
                &policy,
                LocalCustodyCheckpoint::new(
                    store.custody_policy_revision().unwrap(),
                    CustodySample {
                        clock_id,
                        tick_ms: 0,
                    },
                ),
                &request,
                &reservation,
                &event,
                &sealed.bytes,
            )
        })
    };
    assert!(matches!(
        commit(&mut tracker, b"first").unwrap(),
        EventOnceOutcome::Inserted { .. }
    ));
    assert!(matches!(
        commit(&mut tracker, b"first").unwrap(),
        EventOnceOutcome::Existing { .. }
    ));
    assert!(matches!(
        commit(&mut tracker, b"alias").unwrap(),
        EventOnceOutcome::BoundExisting { .. }
    ));
    assert_eq!(
        tracker
            .operation_rate
            .snapshot(tokio::time::Instant::now(), 2),
        (2.0 / 60.0, 60)
    );
    let changed = EventPublicationIntent::new(
        EventPublicationSpec::new(
            sealer.identity(),
            services.topic.clone(),
            services.scope.clone(),
            Priority::Routine,
            b"rate".to_vec(),
            false,
            Some(100),
        )
        .unwrap(),
        b"evil",
    )
    .unwrap();
    let key = EventOperationKey::new(b"first".to_vec()).unwrap();
    let request = EventOperationRequest::new(&key, &changed, b"evil", None).unwrap();
    let changed_sealed = sealer.seal_event(&header, b"evil").unwrap();
    let changed_route = sealer.verify_event(&changed_sealed.bytes).unwrap();
    let EventContentVerification::ContentVerified {
        event: changed_event,
        ..
    } = sealer
        .verify_event_content(changed_route, &changed_sealed.bytes)
        .unwrap()
    else {
        panic!("content authority")
    };
    assert!(matches!(
        tracker.observe_operation_commit(&store, || store
            .commit_reserved_event_once_with_custody_policy(
                &policy,
                LocalCustodyCheckpoint::new(
                    store.custody_policy_revision().unwrap(),
                    CustodySample {
                        clock_id,
                        tick_ms: 0
                    }
                ),
                &request,
                &reservation,
                &changed_event,
                &changed_sealed.bytes,
            )),
        Err(StoreError::EventOperationConflict)
    ));
    store
        .collect_custody_garbage(
            Some(CustodySample {
                clock_id,
                tick_ms: 100,
            }),
            store.custody_policy_revision().unwrap(),
            10,
        )
        .unwrap();
    assert!(matches!(
        commit(&mut tracker, b"direct-retired").unwrap(),
        EventOnceOutcome::RetiredOperation { .. }
    ));
    assert!(matches!(
        commit(&mut tracker, b"direct-retired").unwrap(),
        EventOnceOutcome::RetiredOperation { .. }
    ));
    assert!(matches!(
        commit(&mut tracker, b"first").unwrap(),
        EventOnceOutcome::RetiredOperation { .. }
    ));
    assert_eq!(
        tracker
            .operation_rate
            .snapshot(tokio::time::Instant::now(), 1),
        (3.0 / 60.0, 20)
    );
    commit(&mut tracker, b"last-ordinary").unwrap();
    assert!(matches!(
        commit(&mut tracker, b"over-capacity"),
        Err(StoreError::EventOperationLimitExceeded {
            current: 4,
            limit: 4
        })
    ));
    assert_eq!(
        tracker
            .operation_rate
            .snapshot(tokio::time::Instant::now(), 1),
        (4.0 / 60.0, 15)
    );
    assert_eq!(store.event_operation_stats().unwrap().records_total, 4);
    drop(store);
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn operation_rate_snapshot_removes_expired_samples_during_quiet_period() {
    let now = tokio::time::Instant::now();
    let mut rate = EventOperationAcceptRate::default();
    rate.record(now, 7);
    rate.record(now + Duration::from_secs(30), 3);
    assert_eq!(
        rate.snapshot(now + Duration::from_secs(60), 2),
        (3.0 / 60.0, 40)
    );
    assert_eq!(
        rate.commits.len(),
        1,
        "snapshot must remove the exact 60-second-old sample"
    );
    assert_eq!(rate.snapshot(now + Duration::from_secs(91), 2), (0.0, 0));
    assert!(
        rate.commits.is_empty(),
        "quiet status must not retain expired entries to scan again"
    );
    rate.record(now + Duration::from_secs(92), 4);
    assert_eq!(
        rate.snapshot(now + Duration::from_secs(93), 1),
        (4.0 / 60.0, 15)
    );
}
