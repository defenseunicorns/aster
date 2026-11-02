use super::*;
use crate::api::{
    ApplicationNodeRef, BatchPublishRequest, FinishedBlobBatchItem, FinishedBlobBatchRequest, Query,
};
use crate::blob::MIN_BLOB_CHUNK_SIZE;
use crate::inventory::NibblePrefix;
use crate::wire::ObjectKind;
use std::collections::BTreeSet;

#[test]
fn retained_batch_inventory_selects_exact_representation_by_semantic_version() {
    let root = runtime_directory("batch-inventory");
    let topic = Topic::new("alpha").unwrap();
    let scope = Scope::new("mission/team").unwrap();
    let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
    let mut provisioner = ReferenceProvisioner::from_seed([0x7a; 32]).unwrap();
    let node = open_reference_node(
        root.join("inventory.sqlite"),
        provisioner.issue_node(1, &[access]).unwrap(),
        NodeConfig::default(),
    )
    .unwrap();
    let mut backend = ReferenceSemanticRuntimeBackend::new(
        node,
        BlobTransferStore::open_with_config(root.join("blobs"), BlobStoreConfig::default())
            .unwrap(),
    )
    .unwrap();
    let item = |key: &[u8]| PublishRequest {
        class: DataClass::State,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Routine,
        ttl_ms: None,
        logical_key: key.to_vec(),
        payload: key.to_vec(),
        tombstone: false,
    };
    let dual = ApplicationNodeRef::new(backend.node_mut())
        .publish_batch(BatchPublishRequest::new(vec![item(b"one"), item(b"two")]))
        .unwrap();
    let batch_only = ApplicationNodeRef::new(backend.node_mut())
        .publish_batch(BatchPublishRequest::batch_only(vec![
            item(b"three"),
            item(b"four"),
        ]))
        .unwrap();
    // Build exact expected identities from the retained representations, not
    // from the inventory selector under test.
    let mut expected_v1 = BTreeSet::new();
    let mut expected_v2 = BTreeSet::new();
    for publication in dual.items.iter().chain(&batch_only.items) {
        let material = backend
            .node()
            .store()
            .stored_batch_material(&publication.id)
            .unwrap()
            .unwrap();
        if let Some(singleton) = material.singleton_envelope_id {
            expected_v1.insert(ObjectId::new(ObjectKind::SourceEnvelope, singleton));
        }
        expected_v2.insert(ObjectId::new(
            ObjectKind::SourceEnvelope,
            material.compact_envelope_id,
        ));
        expected_v2.insert(ObjectId::new(
            ObjectKind::SourceBatchProof,
            material.proof.proof_envelope_id,
        ));
    }
    assert_eq!(expected_v1.len(), 2);
    assert_eq!(expected_v2.len(), 6);
    let filter = InterestFilter {
        topics: vec![topic.as_str().to_owned()],
        scopes: vec![scope.as_str().to_owned()],
        min_priority: Priority::Routine as u8,
    };
    let mut select = |version| {
        backend
            .select_authorized_inventory_for_semantic_version(
                [0xa5; 32],
                &[],
                &filter,
                InventoryPurpose::ReceiveBaseline,
                version,
            )
            .unwrap()
            .ids_under(&NibblePrefix::root(), 16)
            .into_iter()
            .collect::<BTreeSet<_>>()
    };
    let v1 = select(1);
    let v2 = select(2);
    assert_eq!(v1, expected_v1);
    assert_eq!(v2, expected_v2);
    assert!(v1.iter().all(|id| id.kind() == ObjectKind::SourceEnvelope));
    assert_eq!(
        v2.iter()
            .filter(|id| id.kind() == ObjectKind::SourceEnvelope)
            .count(),
        4
    );
    assert_eq!(
        v2.iter()
            .filter(|id| id.kind() == ObjectKind::SourceBatchProof)
            .count(),
        2
    );
    assert!(v1.is_disjoint(&v2));
    drop(backend);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn batch_only_state_receive_reauthenticates_exact_items_after_restart() {
    let root = runtime_directory("batch-state-receive");
    let topic = Topic::new("alpha").unwrap();
    let scope = Scope::new("mission/team").unwrap();
    let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
    let mut provisioner = ReferenceProvisioner::from_seed([0x7b; 32]).unwrap();
    let source_bundle = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .unwrap()
        .to_bytes()
        .unwrap();
    let receiver_bundle = provisioner
        .issue_node(2, &[access])
        .unwrap()
        .to_bytes()
        .unwrap();
    let open = |name: &str, bundle: &[u8]| {
        ReferenceSemanticRuntimeBackend::new(
            open_reference_node(
                root.join(format!("{name}.sqlite")),
                restored_bundle(bundle),
                NodeConfig::default(),
            )
            .unwrap(),
            BlobTransferStore::open_with_config(
                root.join(format!("{name}-blobs")),
                BlobStoreConfig::default(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut source = open("source", &source_bundle);
    let receiver = open("receiver", &receiver_bundle);
    let source_id = source.node().identity();
    let receiver_id = receiver.node().identity();
    let item = |key: &[u8], payload: &[u8]| PublishRequest {
        class: DataClass::State,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        ttl_ms: None,
        logical_key: key.to_vec(),
        payload: payload.to_vec(),
        tombstone: false,
    };
    let published = ApplicationNodeRef::new(source.node_mut())
        .publish_batch(BatchPublishRequest::batch_only(vec![
            item(b"alpha", b"ready"),
            item(b"bravo", b"moving"),
        ]))
        .unwrap();
    assert_eq!(published.items.len(), 2);
    assert_eq!(published.items[0].publisher_counter, 1);
    assert_eq!(published.items[1].publisher_counter, 2);
    let expected = BTreeMap::from([
        (
            published.items[0].id,
            (b"alpha".to_vec(), b"ready".to_vec()),
        ),
        (
            published.items[1].id,
            (b"bravo".to_vec(), b"moving".to_vec()),
        ),
    ]);
    let query = Query {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        class: Some(DataClass::State),
        ..Query::default()
    };
    let read = |backend: &mut ReferenceSemanticRuntimeBackend| {
        let items = ApplicationNodeRef::new(backend.node_mut())
            .query(query.clone())
            .unwrap();
        let count = items.len();
        let exact = items
            .into_iter()
            .map(|item| (item.id, (item.logical_key, item.payload)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(exact.len(), count, "query returned duplicate item IDs");
        exact
    };
    assert_eq!(read(&mut source), expected);
    drop(source);
    let mut source = open("source", &source_bundle);
    assert_eq!(read(&mut source), expected);
    let mut sender = RuntimeDriver::initiator(
        restored_bundle(&source_bundle),
        SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
        source,
        blob_start(301),
        None,
    )
    .unwrap();
    let mut recipient = RuntimeDriver::responder_with_start(
        restored_bundle(&receiver_bundle),
        SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
        receiver,
        blob_start(303),
        None,
    )
    .unwrap();
    assert!(read(recipient.backend_mut()).is_empty());
    let (left, right) = MemoryLink::pair(768);
    let now = Instant::now();
    for tick in 0..5_000 {
        let now = now + Duration::from_millis(tick);
        sender.pump_at(&left, now).unwrap();
        recipient.pump_at(&right, now).unwrap();
        if read(recipient.backend_mut()) == expected {
            break;
        }
    }
    assert_eq!(sender.authenticated_peer(), Some(receiver_id));
    assert_eq!(recipient.authenticated_peer(), Some(source_id));
    assert_eq!(read(recipient.backend_mut()), expected);
    drop(sender);
    drop(recipient);
    let mut reopened = open("receiver", &receiver_bundle);
    assert_eq!(reopened.node().identity(), receiver_id);
    assert_eq!(read(&mut reopened), expected);
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn finalized_batch_blobs_transfer_and_read_back_exact_plaintexts() {
    let root = runtime_directory("batch-blob-receive");
    let topic = Topic::new("alpha").unwrap();
    let scope = Scope::new("mission/team").unwrap();
    let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
    let mut provisioner = ReferenceProvisioner::from_seed([0x7c; 32]).unwrap();
    let source_bundle = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .unwrap()
        .to_bytes()
        .unwrap();
    let receiver_bundle = provisioner
        .issue_node(2, &[access])
        .unwrap()
        .to_bytes()
        .unwrap();
    let source_blobs = root.join("source-blobs");
    let receiver_blobs = root.join("receiver-blobs");
    let config = BlobStoreConfig::default();
    let mut source = open_reference_node(
        root.join("source.sqlite"),
        restored_bundle(&source_bundle),
        NodeConfig::default(),
    )
    .unwrap();
    let receiver = open_reference_node(
        root.join("receiver.sqlite"),
        restored_bundle(&receiver_bundle),
        NodeConfig::default(),
    )
    .unwrap();
    let source_id = source.identity();
    let receiver_id = receiver.identity();
    let first_plaintext = vec![0x31; MIN_BLOB_CHUNK_SIZE as usize + 137];
    let second_plaintext = vec![0x52; MIN_BLOB_CHUNK_SIZE as usize * 2 + 19];
    let mut service = source
        .current_blob_service(&scope, &topic, &source_blobs, config)
        .unwrap();
    let mut finish = |plaintext: &[u8], schema: &[u8]| {
        let mut input = Cursor::new(plaintext.to_vec());
        let mut scratch = Cursor::new(Vec::new());
        let manifest = service
            .prepare(
                &mut input,
                &mut scratch,
                MIN_BLOB_CHUNK_SIZE,
                BlobMetadata::new(Some("application/octet-stream".into()), schema.to_vec())
                    .unwrap(),
            )
            .unwrap();
        assert!(
            service
                .encrypt_some(&mut input, &manifest, u64::MAX)
                .unwrap()
                .complete
        );
        service.finish(manifest.id()).unwrap()
    };
    let first = finish(&first_plaintext, b"first");
    let second = finish(&second_plaintext, b"second");
    drop(service);
    let published = ApplicationNodeRef::new(&mut source)
        .publish_finished_blob_batch(FinishedBlobBatchRequest::batch_only(vec![
            FinishedBlobBatchItem {
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                ttl_ms: None,
                finished: first.clone(),
            },
            FinishedBlobBatchItem {
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Routine,
                ttl_ms: None,
                finished: second.clone(),
            },
        ]))
        .unwrap();
    let source = ReferenceSemanticRuntimeBackend::new(
        source,
        BlobTransferStore::open_with_config(&source_blobs, config).unwrap(),
    )
    .unwrap();
    let receiver = ReferenceSemanticRuntimeBackend::new(
        receiver,
        BlobTransferStore::open_with_config(&receiver_blobs, config).unwrap(),
    )
    .unwrap();
    let mut sender = RuntimeDriver::initiator_with_semantic_ceiling(
        restored_bundle(&source_bundle),
        SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
        source,
        blob_start(302),
        None,
        8,
    )
    .unwrap();
    let mut recipient = RuntimeDriver::responder_with_start_and_semantic_ceiling(
        restored_bundle(&receiver_bundle),
        SyncState::new(Default::default(), SparseInventory::new()).unwrap(),
        receiver,
        blob_start(303),
        None,
        8,
    )
    .unwrap();
    let ready = |backend: &mut ReferenceSemanticRuntimeBackend| {
        let mut app = ApplicationNodeRef::new(backend.node_mut());
        app.open_blob_reader(&scope, &topic, &receiver_blobs, config, first.id())
            .is_ok()
            && app
                .open_blob_reader(&scope, &topic, &receiver_blobs, config, second.id())
                .is_ok()
    };
    assert!(!ready(recipient.backend_mut()));
    let (left, right) = MemoryLink::pair(1024);
    let now = Instant::now();
    for tick in 0..30_000 {
        let now = now + Duration::from_millis(tick);
        sender.pump_at(&left, now).unwrap();
        recipient.pump_at(&right, now).unwrap();
        if ready(recipient.backend_mut()) {
            break;
        }
    }
    assert_eq!(sender.authenticated_peer(), Some(receiver_id));
    assert_eq!(recipient.authenticated_peer(), Some(source_id));
    assert_eq!(sender.authenticated_semantic_version(), Some(8));
    assert_eq!(recipient.authenticated_semantic_version(), Some(8));
    let mut app = ApplicationNodeRef::new(recipient.backend_mut().node_mut());
    let received = app
        .query(Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Blob),
            ..Query::default()
        })
        .unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(
        received.iter().map(|item| item.id).collect::<BTreeSet<_>>(),
        published.items.iter().map(|item| item.id).collect()
    );
    for (id, plaintext) in [
        (first.id(), first_plaintext),
        (second.id(), second_plaintext),
    ] {
        let mut reader = app
            .open_blob_reader(&scope, &topic, &receiver_blobs, config, id)
            .unwrap();
        let mut output = Vec::new();
        reader.stream_into(&mut output).unwrap();
        assert_eq!(output, plaintext);
    }
    drop(sender);
    drop(recipient);
    fs::remove_dir_all(root).unwrap();
}
