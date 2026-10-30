#[tokio::test]
async fn blob_ranges_stream_prefix_conflict_cleanup_failure_is_actor_fatal() {
    stream_prefix_conflict_cleanup(true).await;
}

#[tokio::test]
async fn blob_ranges_stream_prefix_conflict_cleanup_success_is_recoverable() {
    stream_prefix_conflict_cleanup(false).await;
}

async fn stream_prefix_conflict_cleanup(corrupt_source: bool) {
    let services = control_test_services([0x72; 32]);
    let a = services.member;
    let b = services.other;
    let ar = root(&format!("prefix-conflict-source-{corrupt_source}"));
    let br = root(&format!("prefix-conflict-receiver-{corrupt_source}"));
    fs::create_dir_all(&ar).unwrap();
    fs::create_dir_all(&br).unwrap();
    let a_store =
        Arc::new(Store::open_for_mission(ar.join(STORE_FILE), a.mission_authority_id()).unwrap());
    let b_store =
        Arc::new(Store::open_for_mission(br.join(STORE_FILE), b.mission_authority_id()).unwrap());
    let source = publish_test_blob(
        &a_store,
        &mut open_test_sealer(&a),
        &services.topic,
        &services.scope,
        1,
        &[0x36; 96 * 1024],
    );
    let plan = completed_test_blob_plan(&a_store, &mut open_test_sealer(&a), source);
    let interests = MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
        services.topic,
        services.scope,
        false,
    )]);
    let fault = blob_ranges_stream_test::install_boundary(
        &a_store,
        &b_store,
        true,
        StreamBoundary::PrefixConflict,
    );
    let transfer = tokio::spawn(with_test_semantic_version(
        SEMANTIC_PROTOCOL_V8,
        stream_prefix_conflict_contact(
            a_store.clone(),
            a,
            b_store.clone(),
            b.clone(),
            interests,
        ),
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        fault.sender_paused.notified().await;
        fault.receiver_paused.notified().await;
    })
    .await
    .expect("authenticated first range reached production append boundary");
    let policy = b_store.control_policy_snapshot().unwrap();
    // The schedule is already authenticated and fixed. Seed conflicting durable
    // bytes for each candidate so the actual next Store append detects conflict.
    for id in plan.carrier_ids() {
        let object = BlobCarrierObjectId::new(id.wire_bytes()).unwrap();
        let total = plan.carrier_total_len(&id.wire_bytes()).unwrap();
        let bytes = vec![
            0;
            usize::try_from(total)
                .unwrap()
                .min(MAX_BLOB_NETWORK_RANGE_BYTES)
        ];
        b_store
            .append_blob_carrier_prefix_with_policy(&policy, source, object, total, 0, &bytes)
            .unwrap();
    }
    if corrupt_source {
        // Seed every legitimate prefix before corrupting any one of them: the
        // pressure invariant correctly prevents subsequent setup writes after
        // it observes the first malformed row.
        for id in plan.carrier_ids() {
            let object = BlobCarrierObjectId::new(id.wire_bytes()).unwrap();
            // One corrupt binding causes real append AND real abort failures.
            // No synthetic error or fatal-wrapper helper substitutes for either.
            b_store
                .test_corrupt_blob_carrier_prefix_source(source, object)
                .unwrap();
        }
    }
    let prefixes = u64::try_from(plan.carrier_ids().count()).unwrap();
    fault.release_sender.notify_one();
    fault.release_receiver.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(15), transfer)
        .await
        .unwrap()
        .unwrap();
    blob_ranges_stream_test::remove(&a_store);
    blob_ranges_stream_test::remove(&b_store);
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("conflicting prefix must reject contact"),
    };
    assert!(b_store.get_blob(source).unwrap().is_none());
    if corrupt_source {
        assert!(
            matches!(&error, NodeError::FatalBlobCoherence(message) if message.contains("conflicting Blob carrier prefix cleanup") || message.contains("Blob pressure carrier prefix contradicts its pending source")),
            "cleanup error lost fatal classification: {error:?}"
        );
        assert!(actor_fatal_contact_error(&error, b.identity()));
        for id in plan.carrier_ids() {
            assert!(matches!(
                b_store.blob_carrier_prefix_status(
                    source,
                    BlobCarrierObjectId::new(id.wire_bytes()).unwrap()
                ),
                Err(StoreError::Blob(BlobStoreError::CarrierPrefixConflict))
            ));
        }
    } else {
        assert!(
            matches!(
                &error,
                NodeError::Store(StoreError::Blob(BlobStoreError::CarrierPrefixConflict))
            ),
            "original append conflict must survive successful cleanup: {error:?}"
        );
        assert!(!actor_fatal_contact_error(&error, b.identity()));
        assert_eq!(b_store.blob_stats().unwrap().carrier_prefixes, prefixes - 1);
    }
    drop(a_store);
    drop(b_store);
    fs::remove_dir_all(ar).unwrap();
    fs::remove_dir_all(br).unwrap();
}

// Return the typed production contact error rather than the panic-based success
// helper: both cleanup branches must reach the actor's real error classifier.
async fn stream_prefix_conflict_contact(
    server_store: Arc<Store>,
    server_mission: UnprotectedReferenceMission,
    client_store: Arc<Store>,
    client_mission: UnprotectedReferenceMission,
    interests: MutableSourceInterests,
) -> Result<CompletedPeerContact, NodeError> {
    let server_cache = test_event_route_cache(&server_store, &server_mission);
    let client_cache = test_event_route_cache(&client_store, &client_mission);
    let server = Endpoint::bind(
        aster_iroh::SecretKey::generate(),
        EndpointConfig::direct("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .unwrap();
    let client = Endpoint::bind(
        aster_iroh::SecretKey::generate(),
        EndpointConfig::direct("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .unwrap();
    let peer = MissionPeerBinding::new(client.id(), client_mission.identity());
    let allowed = BTreeSet::from([client.id()]);
    let server_identity = server_mission.identity();
    let server_task = tokio::spawn({
        let server = server.clone();
        let interests = interests.clone();
        async move {
            let connection = server.accept(&allowed).await.unwrap();
            serve_connection_with_forwarding(InboundContact {
                store: server_store,
                connection,
                mission: server_mission,
                expected_peer: Some(peer),
                #[cfg(feature = "nearby-discovery")]
                automatic_admission: None,
                policy_lock: Arc::new(RwLock::new(())),
                emission_policy: Arc::new(LiveEmissionPolicy::new(EventEmissionPolicy::Normal)),
                custody_clock: NodeCustodyClock::injected([0xb1; 16], 0, 0),
                event_route_cache: server_cache,
                event_bridge: None,
                mutable_interests: interests,
            })
            .await
        }
    });
    let policy = Arc::new(LiveEmissionPolicy::new(EventEmissionPolicy::Normal));
    let result = sync_once_with_forwarding(
        &client,
        OutboundContact {
            store: client_store,
            mission: client_mission,
            peer: MissionExpectedPeer {
                carrier: ExpectedPeer {
                    id: server.id(),
                    address: loopback(&server),
                },
                mission: server_identity,
            }
            .into(),
            #[cfg(feature = "nearby-discovery")]
            automatic_admission: None,
            policy_lock: Arc::new(RwLock::new(())),
            emission_snapshot: policy.snapshot().unwrap(),
            emission_policy: policy,
            custody_clock: NodeCustodyClock::injected([0xb2; 16], 0, 0),
            event_route_cache: client_cache,
            event_bridge: None,
            mutable_interests: interests,
            controlled_relay: None,
        },
    )
    .await;
    client.close().await;
    server.close().await;
    let _ = server_task.await.unwrap();
    result
}

#[tokio::test]
async fn blob_ranges_stream_publication_capacity_rotates_two_installed_sources() {
    let mut missions = issue_missions(2);
    let a = missions.pop().unwrap();
    let b = missions.pop().unwrap();
    let authority = a.credentials.mission_authority_id();
    let topic = Topic::new("opaque").unwrap();
    let scope = Scope::new("test/runtime-contact").unwrap();
    let interests = || {
        MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
            topic.clone(),
            scope.clone(),
            false,
        )])
    };
    let ar = root("stream-publication-fair-source");
    let br = root("stream-publication-fair-receiver");
    fs::create_dir_all(&ar).unwrap();
    fs::create_dir_all(&br).unwrap();
    let a_store = Arc::new(Store::open_for_mission(ar.join(STORE_FILE), authority).unwrap());
    let limits = StoreLimits::new(
        MAX_CONTROL_ITEMS + CUSTODY_EMERGENCY_ITEM_RESERVE + 1,
        DEFAULT_MAX_TOTAL_PAYLOAD_BYTES,
    )
    .unwrap();
    let b_store = Arc::new(
        Store::open_with_limits_for_mission(br.join(STORE_FILE), limits, authority).unwrap(),
    );
    publish_test_state(
        &b_store,
        &mut open_test_sealer(&b.credentials),
        &topic,
        &scope,
        b"occupied",
        b"occupied",
    );
    let sources: Vec<_> = (0..2)
        .map(|n| {
            publish_test_blob(
                &a_store,
                &mut open_test_sealer(&a.credentials),
                &topic,
                &scope,
                1,
                &[n + 5],
            )
        })
        .collect();
    let receiver_cache = test_event_route_cache(&b_store, &b.credentials);
    for source in &sources {
        let sealed = a_store
            .get_blob(*source)
            .unwrap()
            .expect("installed rotation source")
            .sealed;
        stage_test_pending_blob(
            &b_store,
            &receiver_cache,
            &b.credentials,
            *source,
            &sealed,
        );
        let mut source_verifier = open_test_sealer(&a.credentials);
        let route = source_verifier.verify_blob(&sealed).unwrap();
        let BlobContentVerification::ContentVerified {
            blob,
            manifest_bytes,
        } = source_verifier
            .verify_blob_content(route, &sealed)
            .unwrap()
        else {
            panic!("installed rotation source lost content access")
        };
        let plan = blob.transfer_plan(&manifest_bytes).unwrap();
        let completion = a_store
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
            .unwrap();
        let lineage = source_verifier.verify_current_blob_lineage(&blob).unwrap();
        let source_policy = a_store.control_policy_snapshot().unwrap();
        let receiver_policy = b_store.control_policy_snapshot().unwrap();
        for carrier in plan.carrier_ids() {
            let object = BlobCarrierObjectId::new(carrier.wire_bytes()).unwrap();
            let total = plan.carrier_total_len(object.as_bytes()).unwrap();
            let mut offset = 0;
            while offset < total {
                let range_len = usize::try_from(
                    (total - offset).min(u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES).unwrap()),
                )
                .unwrap();
                let (stable_total, bytes) = a_store
                    .read_completed_blob_carrier_range_with_policy(
                        &source_policy,
                        &completion,
                        &lineage,
                        *source,
                        object,
                        offset,
                        range_len,
                        &plan,
                    )
                    .unwrap()
                    .expect("installed rotation carrier range");
                assert_eq!(stable_total, total);
                b_store
                    .append_blob_carrier_prefix_with_policy(
                        &receiver_policy,
                        *source,
                        object,
                        total,
                        offset,
                        &bytes,
                    )
                    .unwrap();
                offset += u64::try_from(bytes.len()).unwrap();
            }
        }
    }
    assert_eq!(b_store.blob_stats().unwrap().pending_sources, 2);
    let peer = a.credentials.identity();
    let mut turns = Vec::new();
    for _ in 0..3 {
        let (receipt, _, _, _) = blob_contact_test_pair(
            a_store.clone(),
            a.credentials.clone(),
            interests(),
            b_store.clone(),
            b.credentials.clone(),
            interests(),
        )
        .await;
        assert!(receipt.blob_deferred > 0);
        assert_eq!(receipt.blob_bytes_fetched, 0);
        turns.push(
            b_store
                .blob_carrier_fetch_cursor(peer)
                .unwrap()
                .expect("capacity deferral advances the installed-source cursor")
                .source(),
        );
        for source in &sources {
            assert!(b_store.get_blob(*source).unwrap().is_none());
            assert!(b_store.pending_blob_source(*source).unwrap().is_some());
        }
    }
    assert_ne!(
        turns[0], turns[1],
        "capacity-deferred installed source must yield its scheduling turn"
    );
    assert_eq!(
        turns[0], turns[2],
        "two installed sources must rotate without skipping either source"
    );
    drop(a_store);
    drop(b_store);
    fs::remove_dir_all(ar).unwrap();
    fs::remove_dir_all(br).unwrap();
}
