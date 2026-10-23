#[tokio::test]
async fn blob_ranges_stream_saturated_six_mutable_directions() {
    let mut missions = issue_missions(2);
    let a = missions.pop().unwrap();
    let b = missions.pop().unwrap();
    let authority = a.credentials.mission_authority_id();
    let topic = Topic::new("opaque").unwrap();
    let scope = Scope::new("test/runtime-contact").unwrap();
    let roots = [
        root("stream-six-a"),
        root("stream-six-b"),
    ];
    for path in &roots {
        fs::create_dir_all(path).unwrap();
    }
    let stores: Vec<_> = roots
        .iter()
        .map(|path| Arc::new(Store::open_for_mission(path.join(STORE_FILE), authority).unwrap()))
        .collect();
    let interests = || {
        let selector = || SourceInterestSelector::new(topic.clone(), scope.clone(), false);
        MutableSourceInterests::new(vec![selector()], vec![selector()]).with_blob(vec![selector()])
    };
    let mut states = Vec::new();
    let mut records = Vec::new();
    let mut blobs = Vec::new();
    for (index, (store, mission)) in stores
        .iter()
        .zip([&a.credentials, &b.credentials])
        .enumerate()
    {
        let mut sealer = open_test_sealer(mission);
        seed_test_event_subscription(
            store,
            EventSubscriptionMode::Consume,
            &topic,
            &scope,
            b"stream-six",
        );
        for index in 0..2 {
            publish_test_epoch_one_event(
                store,
                &mut sealer,
                &topic,
                &scope,
                format!("event-{index}").as_bytes(),
            );
        }
        states.push(publish_test_state(
            store,
            &mut sealer,
            &topic,
            &scope,
            b"state",
            b"state",
        ));
        records.push(publish_test_record(
            store,
            &mut sealer,
            &topic,
            &scope,
            b"record",
            b"record",
        ));
        blobs.push(publish_test_blob(
            store,
            &mut sealer,
            &topic,
            &scope,
            1,
            &vec![0x51 + index as u8; 96 * 1024],
        ));
    }
    let a_cache = test_event_route_cache(&stores[0], &a.credentials);
    let b_cache = test_event_route_cache(&stores[1], &b.credentials);
    let production_event_capacity =
        event_transfer_capacity(&PeerReceipt::default(), Some(SEMANTIC_PROTOCOL_V7)).unwrap();
    assert_eq!(production_event_capacity, MAX_CONTACT_ITEMS - 9);
    let preaccounted = production_event_capacity - 2;
    let contact = with_test_semantic_version(
        SEMANTIC_PROTOCOL_V7,
        blob_contact_test_pair_with_caches(
            stores[0].clone(),
            a.credentials,
            interests(),
            a_cache,
            stores[1].clone(),
            b.credentials,
            interests(),
            b_cache,
            None,
            None,
            None,
            None,
            preaccounted,
        ),
    );
    let (left, right) = contact.await;
    for receipt in [&left, &right] {
        assert_eq!(receipt.event_page_entries_sent, 1, "{receipt:?}");
        assert_eq!(receipt.event_page_unscheduled, 1, "{receipt:?}");
        assert!(receipt.blob_ranges_fetched > 0, "{receipt:?}");
        assert!(
            receipt.offered + receipt.fetched <= MAX_CONTACT_ITEMS,
            "{receipt:?}"
        );
        assert!(receipt.handshake_frames + receipt.protected_frames <= MAX_CONTACT_FRAMES);
        assert!(receipt.handshake_bytes + receipt.protected_bytes <= MAX_CONTACT_BYTES);
        assert_eq!(receipt.negotiated_transfer_profiles.unwrap()[3], 4);
    }
    for index in 0..2 {
        assert!(
            stores[index]
                .get_state(states[1 - index])
                .unwrap()
                .is_some()
        );
        assert!(
            stores[index]
                .get_record(records[1 - index])
                .unwrap()
                .is_some()
        );
        assert!(
            stores[index].get_blob(blobs[1 - index]).unwrap().is_some()
                || stores[index]
                    .pending_blob_source(blobs[1 - index])
                    .unwrap()
                    .is_some()
        );
    }
    drop(stores);
    for path in roots {
        fs::remove_dir_all(path).unwrap();
    }
}
