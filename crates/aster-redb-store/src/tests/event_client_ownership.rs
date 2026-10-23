use super::*;

fn claim(
    store: &Store,
    name: &[u8],
    expected: u64,
    complete: bool,
) -> (EventClientContext, EventRecoverySnapshot) {
    let client_id = EventClientId::new(name.to_vec()).unwrap();
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).unwrap();
    let snapshot = store
        .begin_event_publication_session(&client_id, expected, &nonce)
        .unwrap();
    if complete {
        store
            .complete_event_publication_recovery(
                &client_id,
                snapshot.session,
                snapshot.snapshot_revision,
            )
            .unwrap();
    }
    (
        EventClientContext {
            client_id,
            session: snapshot.session,
        },
        snapshot,
    )
}

fn assert_fenced<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    assert!(
        matches!(
            result,
            Err(StoreError::NumberedEventOperation(
                NumberedEventOperationError::SessionFenced
            ))
        ),
        "{result:?}"
    );
}

#[test]
fn takeover_preserves_owned_delivery_state_and_fences_every_old_mutation() {
    let file = TestFile::new("client-owned-takeover");
    let mut services = event_services(0xb1);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let (old, _) = claim(&store, b"application-a", 0, true);
    let (other, _) = claim(&store, b"application-b", 0, true);
    let key = EventSubscriptionKey::new(b"same-key".to_vec()).unwrap();
    let spec = subscription_spec(EventSubscriptionMode::Consume);
    let subscription = store
        .create_event_subscription_with_policy(&old, &policy, &key, spec.clone())
        .unwrap();
    let independent = store
        .create_event_subscription_with_policy(&other, &policy, &key, spec.clone())
        .unwrap();
    assert_ne!(subscription.id, independent.id);
    let publisher = services.publisher.identity();
    let event = accept_event(
        &store,
        &mut services,
        event_header(
            publisher,
            1,
            1,
            VersionVector::default(),
            b"takeover",
            b"survive takeover",
            None,
        ),
        b"survive takeover",
    );
    let plan = store
        .prepare_event_subscription_poll_with_policy(&old, &policy, subscription.id, 8, 8)
        .unwrap();
    let selection = EventSubscriptionPollSelection {
        deliveries: vec![event.semantic_id],
        inactive_pending: vec![],
    };
    let first = store
        .commit_event_subscription_poll_with_policy(&policy, &plan, &selection)
        .unwrap();
    assert_eq!(first.deliveries[0].attempt, 1);
    let before = store.event_subscription_stats().unwrap();
    let publication_before = store.numbered_event_operation_stats().unwrap();
    let (current, snapshot) = claim(&store, b"application-a", old.session.get(), false);
    assert_fenced(store.create_event_subscription_with_policy(&old, &policy, &key, spec.clone()));
    assert_fenced(store.prepare_event_subscription_poll_with_policy(
        &old,
        &policy,
        subscription.id,
        8,
        8,
    ));
    assert_fenced(store.acknowledge_event_delivery_with_policy(
        &old,
        &policy,
        subscription.id,
        event.semantic_id,
    ));
    assert_fenced(store.remove_event_subscription_with_policy(&old, &policy, subscription.id));
    assert_fenced(store.commit_event_subscription_poll_with_policy(&policy, &plan, &selection));
    assert!(matches!(
        store.prepare_event_subscription_poll_with_policy(&current, &policy, subscription.id, 8, 8),
        Err(StoreError::NumberedEventOperation(
            NumberedEventOperationError::RecoveryRequired
        ))
    ));
    for result in [
        store
            .prepare_event_subscription_poll_with_policy(&other, &policy, subscription.id, 8, 8)
            .map(|_| ()),
        store
            .acknowledge_event_delivery_with_policy(
                &other,
                &policy,
                subscription.id,
                event.semantic_id,
            )
            .map(|_| ()),
        store
            .remove_event_subscription_with_policy(&other, &policy, subscription.id)
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(StoreError::NumberedEventOperation(
                NumberedEventOperationError::SubscriptionOwnerMismatch
            ))
        ));
    }
    assert_eq!(store.event_subscription_stats().unwrap(), before);
    assert_eq!(
        store.numbered_event_operation_stats().unwrap(),
        publication_before
    );
    let status = store
        .event_client_status(&old.client_id, Some(old.session))
        .unwrap();
    assert_eq!(status.current_session, Some(current.session));
    assert_eq!(status.disposition, EventClientDisposition::Fenced);
    assert_eq!(
        (
            status.subscriptions,
            status.pending_deliveries,
            status.acknowledged_deliveries
        ),
        (1, 1, 0)
    );
    assert_eq!(
        status.ownership_metadata_bytes,
        1 + old.client_id.as_bytes().len() as u64
    );
    assert_eq!(
        store
            .event_client_status(&current.client_id, Some(current.session))
            .unwrap()
            .disposition,
        EventClientDisposition::RecoveryRequired
    );
    store
        .complete_event_publication_recovery(
            &current.client_id,
            current.session,
            snapshot.snapshot_revision,
        )
        .unwrap();
    let replay = store
        .create_event_subscription_with_policy(&current, &policy, &key, spec)
        .unwrap();
    assert!(!replay.inserted);
    assert_eq!(replay.id, subscription.id);
    drop(store);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    assert_eq!(
        store
            .event_client_status(&current.client_id, Some(current.session))
            .unwrap()
            .disposition,
        EventClientDisposition::Current
    );
    let plan = store
        .prepare_event_subscription_poll_with_policy(&current, &policy, subscription.id, 8, 8)
        .unwrap();
    let repeated = store
        .commit_event_subscription_poll_with_policy(&policy, &plan, &selection)
        .unwrap();
    assert_eq!(repeated.deliveries[0].attempt, 2);
    assert_eq!(
        store
            .acknowledge_event_delivery_with_policy(
                &current,
                &policy,
                subscription.id,
                event.semantic_id
            )
            .unwrap(),
        EventDeliveryAck::Acknowledged
    );
    assert_eq!(
        store
            .acknowledge_event_delivery_with_policy(
                &current,
                &policy,
                subscription.id,
                event.semantic_id
            )
            .unwrap(),
        EventDeliveryAck::AlreadyAcknowledged
    );
    assert_fenced(store.acknowledge_event_delivery_with_policy(
        &old,
        &policy,
        subscription.id,
        event.semantic_id,
    ));
    assert!(
        store
            .remove_event_subscription_with_policy(&current, &policy, subscription.id)
            .unwrap()
            .removed
    );
    assert!(
        !store
            .remove_event_subscription_with_policy(&current, &policy, subscription.id)
            .unwrap()
            .removed
    );
    assert_fenced(store.remove_event_subscription_with_policy(&old, &policy, subscription.id));
    let status = store
        .event_client_status(&current.client_id, Some(current.session))
        .unwrap();
    assert_eq!(
        (
            status.subscriptions,
            status.pending_deliveries,
            status.acknowledged_deliveries,
            status.ownership_metadata_bytes
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        store.numbered_event_operation_stats().unwrap(),
        publication_before
    );
}

#[test]
fn poll_prepared_before_takeover_cannot_move_cursor_or_record_attempts() {
    let file = TestFile::new("owned-poll-linearization");
    let mut services = event_services(0xb2);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let policy = store.control_policy_snapshot().unwrap();
    let (old, _) = claim(&store, b"client", 0, true);
    let subscription = store
        .create_event_subscription_with_policy(
            &old,
            &policy,
            &EventSubscriptionKey::new(b"feed".to_vec()).unwrap(),
            subscription_spec(EventSubscriptionMode::Consume),
        )
        .unwrap();
    let publisher = services.publisher.identity();
    let event = accept_event(
        &store,
        &mut services,
        event_header(
            publisher,
            1,
            1,
            VersionVector::default(),
            b"prepared",
            b"prepared only",
            None,
        ),
        b"prepared only",
    );
    let plan = store
        .prepare_event_subscription_poll_with_policy(&old, &policy, subscription.id, 1, 8)
        .unwrap();
    let before = store.event_subscription_stats().unwrap();
    let (current, _) = claim(&store, b"client", old.session.get(), true);
    let selection = EventSubscriptionPollSelection {
        deliveries: vec![event.semantic_id],
        inactive_pending: vec![],
    };
    assert_fenced(store.commit_event_subscription_poll_with_policy(&policy, &plan, &selection));
    assert_eq!(store.event_subscription_stats().unwrap(), before);
    let fresh = store
        .prepare_event_subscription_poll_with_policy(&current, &policy, subscription.id, 1, 8)
        .unwrap();
    assert_eq!(fresh.discovered_through(), 0);
    assert!(fresh.pending_candidates().is_empty());
    assert_eq!(
        store
            .commit_event_subscription_poll_with_policy(&policy, &fresh, &selection)
            .unwrap()
            .deliveries[0]
            .attempt,
        1
    );
}

#[test]
fn incompatible_or_orphaned_subscription_state_is_refused_without_changing_bytes() {
    for corruption in 0..3 {
        let file = TestFile::new("owned-subscription-preflight");
        let services = event_services(0xb3);
        let store = Store::open_for_mission(&file.0, services.authority).unwrap();
        let policy = store.control_policy_snapshot().unwrap();
        let (client, _) = claim(&store, b"client", 0, true);
        let subscription = store
            .create_event_subscription_with_policy(
                &client,
                &policy,
                &EventSubscriptionKey::new(b"feed".to_vec()).unwrap(),
                subscription_spec(EventSubscriptionMode::Consume),
            )
            .unwrap();
        let write = store.database.begin_write().unwrap();
        {
            let mut table = write.open_table(EVENT_SUBSCRIPTIONS).unwrap();
            let bytes = table
                .get(subscription.id.as_bytes().as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let mut record = decode_event_subscription_record(&bytes).unwrap();
            let corrupt = match corruption {
                0 => {
                    let mut bytes = bytes;
                    bytes[0] = 1;
                    bytes
                }
                1 => {
                    record.owner = EventClientId::new(b"unregistered".to_vec()).unwrap();
                    encode_event_subscription_record(&record).unwrap()
                }
                _ => {
                    let mut bytes = bytes;
                    bytes[1] = 0;
                    bytes
                }
            };
            table
                .insert(subscription.id.as_bytes().as_slice(), corrupt.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        drop(store);
        let before = std::fs::read(&file.0).unwrap();
        assert!(Store::require_numbered_publication_compatible(&file.0).is_err());
        assert_eq!(std::fs::read(&file.0).unwrap(), before);
        assert!(Store::open_for_mission(&file.0, services.authority).is_err());
        assert_eq!(std::fs::read(&file.0).unwrap(), before);
    }
}

#[test]
fn unclean_unowned_subscription_refusal_preserves_original_bytes() {
    const CHILD_PATH: &str = "ASTER_UNOWNED_SUBSCRIPTION_CHILD_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let store = Store::open_for_mission(PathBuf::from(path), [0x91; 32]).unwrap();
        let (client, _) = claim(&store, b"unclean-client", 0, true);
        let policy = store.control_policy_snapshot().unwrap();
        let subscription = store
            .create_event_subscription_with_policy(
                &client,
                &policy,
                &EventSubscriptionKey::new(b"feed".to_vec()).unwrap(),
                subscription_spec(EventSubscriptionMode::Consume),
            )
            .unwrap();
        let write = store.database.begin_write().unwrap();
        {
            let mut table = write.open_table(EVENT_SUBSCRIPTIONS).unwrap();
            let mut bytes = table
                .get(subscription.id.as_bytes().as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            bytes[0] = 1;
            table
                .insert(subscription.id.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        std::process::exit(0); // leave redb's clean-close allocator receipt unwritten
    }
    let file = TestFile::new("unclean-unowned-subscription");
    assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "tests::event_client_ownership::unclean_unowned_subscription_refusal_preserves_original_bytes", "--nocapture"]).env(CHILD_PATH, &file.0).status().unwrap().success());
    let before = std::fs::read(&file.0).unwrap();
    assert!(matches!(
        redb::Builder::new().open_read_only(&file.0),
        Err(redb::DatabaseError::RepairAborted)
    ));
    assert!(Store::require_numbered_publication_compatible(&file.0).is_err());
    assert_eq!(std::fs::read(&file.0).unwrap(), before);
    assert!(Store::open_for_mission(&file.0, [0x91; 32]).is_err());
    assert_eq!(std::fs::read(&file.0).unwrap(), before);
}

#[test]
fn status_observes_unregistered_and_unobserved_clients_without_mutation() {
    let file = TestFile::new("client-status-before-registration");
    let services = event_services(0xb2);
    let store = Store::open_for_mission(&file.0, services.authority).unwrap();
    let client = EventClientId::new(b"fresh-client".to_vec()).unwrap();
    let before = store.numbered_event_operation_stats().unwrap();
    let subscriptions_before = store.event_subscription_stats().unwrap();
    for observed in [None, Some(EventPublicationSession::new(1).unwrap())] {
        let status = store.event_client_status(&client, observed).unwrap();
        assert_eq!(
            status,
            EventClientStatus {
                current_session: None,
                disposition: EventClientDisposition::Unregistered,
                subscriptions: 0,
                pending_deliveries: 0,
                acknowledged_deliveries: 0,
                ownership_metadata_bytes: 0,
            }
        );
    }
    assert!(!store.has_event_publication_client(&client).unwrap());
    assert_eq!(store.numbered_event_operation_stats().unwrap(), before);
    assert_eq!(
        store.event_subscription_stats().unwrap(),
        subscriptions_before
    );

    let (context, snapshot) = claim(&store, client.as_bytes(), 0, false);
    let claimed = store.numbered_event_operation_stats().unwrap();
    for observed in [None, Some(context.session)] {
        let status = store.event_client_status(&client, observed).unwrap();
        assert_eq!(status.current_session, Some(context.session));
        assert_eq!(status.disposition, EventClientDisposition::RecoveryRequired);
    }
    assert_eq!(store.numbered_event_operation_stats().unwrap(), claimed);
    store
        .complete_event_publication_recovery(&client, context.session, snapshot.snapshot_revision)
        .unwrap();
    let recovered = store.numbered_event_operation_stats().unwrap();
    assert_eq!(
        store
            .event_client_status(&client, None)
            .unwrap()
            .disposition,
        EventClientDisposition::RecoveryRequired
    );
    assert_eq!(
        store
            .event_client_status(&client, Some(context.session))
            .unwrap()
            .disposition,
        EventClientDisposition::Current
    );
    assert_eq!(store.numbered_event_operation_stats().unwrap(), recovered);
}
