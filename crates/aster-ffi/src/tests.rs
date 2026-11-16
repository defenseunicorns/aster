use super::operations::*;
use super::*;

fn bytes(b: &[u8]) -> AsterBytes {
    AsterBytes {
        data: b.as_ptr(),
        len: b.len(),
    }
}
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "aster-ffi-v2-{}-{}",
            std::process::id(),
            new_handle().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let mission = root.join("mission.bundle");
        UnprotectedReferenceMission::persist(
            &mission,
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                .to_vec(),
        )
        .unwrap();
        Self { root }
    }
    fn state(&self) -> PathBuf {
        self.root.join("state")
    }
    fn mission(&self) -> PathBuf {
        self.root.join("mission.bundle")
    }
    fn open(&self) -> u64 {
        let state = self.state();
        let mission = self.mission();
        let mut o = AsterNodeOptions::default();
        assert_eq!(aster_node_options_init(&raw mut o), 0);
        o.state_path = bytes(state.to_str().unwrap().as_bytes());
        o.provisioning_path = bytes(mission.to_str().unwrap().as_bytes());
        let mut node = 0;
        ok(aster_node_open(&raw const o, &raw mut node));
        node
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn ok(status: u32) {
    assert_eq!(status, 0, "{}", LAST_ERROR.with(|e| e.borrow().clone()));
}
#[path = "../tests/support/mod.rs"]
mod support;
fn publish(node: u64, operation: &[u8], payload: &[u8]) -> AsterPublishReceipt {
    let r = AsterPublishRequest {
        data_class: 0,
        priority: 2,
        operation_key: bytes(operation),
        topic: bytes(b"position.current"),
        scope: bytes(b"mission/team/alpha"),
        logical_key: bytes(b"unit-7"),
        payload: bytes(payload),
        ..Default::default()
    };
    let mut receipt = AsterPublishReceipt::default();
    ok(aster_node_publish(node, &raw const r, &raw mut receipt));
    receipt
}
fn query(node: u64, class: u32) -> u64 {
    let r = AsterQueryRequest {
        data_class: class,
        topic: bytes(b"position.current"),
        scope: bytes(b"mission/team/alpha"),
        logical_key: bytes(b"unit-7"),
        ..Default::default()
    };
    let mut result = 0;
    ok(aster_node_query(node, &raw const r, &raw mut result));
    result
}
#[test]
fn node_children_are_owned_closed_and_never_reused() {
    let f = Fixture::new();
    let g = Fixture::new();
    let mut n = f.open();
    let mut other = g.open();
    publish(n, b"one", b"payload");
    let mut result = query(n, 0);
    let stale = result;
    let mut info = AsterResultInfo::default();
    assert_eq!(
        aster_result_info(other, result, &raw mut info),
        STATUS_CLOSED
    );
    let mut item = AsterItem::default();
    ok(aster_result_item(n, result, 0, 0, &raw mut item));
    ok(aster_node_close(&raw mut n));
    assert_eq!(n, 0);
    assert_eq!(aster_result_info(n, result, &raw mut info), STATUS_CLOSED);
    assert_eq!(aster_result_close(n, &raw mut result), STATUS_CLOSED);
    assert_eq!(result, 0);
    // Caller-owned copies survive closure and can be freed once, independently.
    assert_eq!(
        input_bytes(
            AsterBytes {
                data: item.payload.data,
                len: item.payload.len
            },
            "payload"
        )
        .unwrap(),
        b"payload"
    );
    ok(aster_item_free(&raw mut item));
    ok(aster_item_free(&raw mut item));
    let mut reopened = f.open();
    let mut new_result = query(reopened, 0);
    assert_ne!(stale, new_result);
    ok(aster_result_close(reopened, &raw mut new_result));
    ok(aster_node_close(&raw mut reopened));
    ok(aster_node_close(&raw mut other));
}
#[test]
fn abi_and_output_validation_precedes_durable_mutation() {
    let f = Fixture::new();
    let mut n = f.open();
    let r = AsterPublishRequest {
        data_class: 0,
        operation_key: bytes(b"op"),
        topic: bytes(b"position.current"),
        scope: bytes(b"mission/team/alpha"),
        logical_key: bytes(b"unit-7"),
        payload: bytes(b"not committed"),
        ..Default::default()
    };
    let mut out = AsterPublishReceipt {
        abi_version: 1,
        ..Default::default()
    };
    assert_eq!(
        aster_node_publish(n, &raw const r, &raw mut out),
        STATUS_ABI_MISMATCH
    );
    assert_eq!(
        aster_node_publish(n, &raw const r, std::ptr::null_mut()),
        STATUS_INVALID_ARGUMENT
    );
    let mut result = query(n, 0);
    let mut entry = AsterEntry::default();
    ok(aster_result_entry(n, result, 0, &raw mut entry));
    assert_eq!(entry.item_count, 0);
    ok(aster_entry_free(&raw mut entry));
    ok(aster_result_close(n, &raw mut result));
    ok(aster_node_close(&raw mut n));
}
#[test]
fn copied_or_modified_output_buffer_cannot_free_other_allocations() {
    let mut first = owned_buffer(b"first").unwrap();
    let mut stale = first;
    let mut modified = first;
    modified.len += 1;
    assert!(release_buffer(&mut modified).is_err());
    assert!(
        lock(allocations(), "test")
            .unwrap()
            .contains_key(&first.allocation)
    );
    release_buffer(&mut first).unwrap();
    let mut next = owned_buffer(b"next").unwrap();
    assert!(release_buffer(&mut stale).is_err());
    assert!(
        lock(allocations(), "test")
            .unwrap()
            .contains_key(&next.allocation)
    );
    release_buffer(&mut next).unwrap();
}
#[test]
fn ffi_is_callable_inside_an_existing_tokio_runtime() {
    let f = Fixture::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut node = f.open();
        publish(node, b"nested", b"value");
        ok(aster_node_close(&raw mut node));
    });
}
#[test]
fn close_serializes_with_in_flight_operations() {
    let f = Fixture::new();
    let n = f.open();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b = barrier.clone();
    let worker = std::thread::spawn(move || {
        b.wait();
        for _ in 0..20 {
            let mut threshold = 0;
            let status = aster_node_get_emission(n, &raw mut threshold);
            assert!(status == 0 || status == STATUS_CLOSED);
        }
    });
    barrier.wait();
    let mut close = n;
    ok(aster_node_close(&raw mut close));
    worker.join().unwrap();
    let mut threshold = 0;
    assert_eq!(
        aster_node_get_emission(n, &raw mut threshold),
        STATUS_CLOSED
    );
}
#[test]
fn record_conflict_guard_is_exact_node_owned_and_retryable() {
    let root = std::env::temp_dir().join(format!(
        "aster-ffi-conflict-{}-{}",
        std::process::id(),
        new_handle().unwrap()
    ));
    support::prepare(&root).unwrap();
    let f = Fixture { root };
    let mut n = f.open();
    let mut guard = query(n, 2);
    let mut e = AsterEntry::default();
    ok(aster_result_entry(n, guard, 0, &raw mut e));
    assert_eq!(e.item_count, 3);
    assert_eq!(e.sibling_ids.len, 96);
    assert_eq!(e.has_guard, 1);
    ok(aster_entry_free(&raw mut e));
    let sub_request = AsterSubscribeRequest {
        data_class: 2,
        operation_key: bytes(b"sub"),
        topic: bytes(b"position.current"),
        scope: bytes(b"mission/team/alpha"),
        ..Default::default()
    };
    let mut sub = AsterSubscription::default();
    ok(aster_node_subscribe(
        n,
        &raw const sub_request,
        &raw mut sub,
    ));
    let poll = AsterPollRequest {
        subscription: sub,
        delivery_limit: 1,
        scan_limit: 100,
        ..Default::default()
    };
    let mut delivered = 0;
    ok(aster_node_poll(n, &raw const poll, &raw mut delivered));
    ok(aster_result_entry(n, delivered, 0, &raw mut e));
    assert_eq!(e.item_count, 3);
    assert_eq!(e.has_guard, 0);
    assert_eq!(e.sibling_ids.len, 96);
    ok(aster_entry_free(&raw mut e));
    let request = AsterResolveRequest {
        guard,
        operation_key: bytes(b"resolve"),
        payload: bytes(b"joined"),
        priority: 2,
        ..Default::default()
    };
    let mut receipt = AsterPublishReceipt::default();
    let g = Fixture::new();
    let mut other = g.open();
    assert_eq!(
        aster_node_resolve(other, &raw const request, &raw mut receipt),
        STATUS_STALE_CONFLICT
    );
    ok(aster_node_close(&raw mut other));
    let delivered_request = AsterResolveRequest {
        guard: delivered,
        ..request
    };
    assert_eq!(
        aster_node_resolve(n, &raw const delivered_request, &raw mut receipt),
        STATUS_STALE_CONFLICT
    );
    ok(aster_node_resolve(n, &raw const request, &raw mut receipt));
    let original = receipt.item_id;
    assert_eq!(receipt.inserted, 1);
    ok(aster_node_resolve(n, &raw const request, &raw mut receipt));
    assert_eq!(receipt.item_id, original);
    assert_eq!(receipt.inserted, 0);
    let stale = AsterResolveRequest {
        operation_key: bytes(b"different-resolution"),
        ..request
    };
    assert_eq!(
        aster_node_resolve(n, &raw const stale, &raw mut receipt),
        STATUS_STALE_CONFLICT
    );
    ok(aster_result_close(n, &raw mut guard));
    assert_eq!(
        aster_node_resolve(n, &raw const request, &raw mut receipt),
        STATUS_STALE_CONFLICT
    );
    ok(aster_result_close(n, &raw mut delivered));
    ok(aster_node_close(&raw mut n));
}
#[test]
fn failure_to_zeroize_replaced_mission_artifact_does_not_erase_state() {
    let f = Fixture::new();
    let mut n = f.open();
    publish(n, b"kept", b"kept");
    let retained = f.root.join("retained.bundle");
    std::fs::rename(f.mission(), &retained).unwrap();
    UnprotectedReferenceMission::persist(
        f.mission(),
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .unwrap();
    assert_ne!(aster_node_zeroize(&raw mut n), 0);
    assert_eq!(n, 0);
    std::fs::remove_file(f.mission()).unwrap();
    std::fs::rename(retained, f.mission()).unwrap();
    let mut reopened = f.open();
    let mut result = query(reopened, 0);
    let mut e = AsterEntry::default();
    ok(aster_result_entry(reopened, result, 0, &raw mut e));
    assert_eq!(e.item_count, 1);
    ok(aster_entry_free(&raw mut e));
    ok(aster_result_close(reopened, &raw mut result));
    ok(aster_node_close(&raw mut reopened));
}
#[test]
fn native_handle_budget_is_reclaimed_after_close() {
    let f = Fixture::new();
    let mut n = f.open();
    let mut handles = Vec::new();
    for _ in 0..MAX_CHILD_HANDLES {
        handles.push(query(n, 0));
    }
    let request = AsterQueryRequest {
        data_class: 0,
        topic: bytes(b"position.current"),
        scope: bytes(b"mission/team/alpha"),
        logical_key: bytes(b"unit-7"),
        ..Default::default()
    };
    let mut out = 0;
    assert_eq!(
        aster_node_query(n, &raw const request, &raw mut out),
        STATUS_QUOTA_EXCEEDED
    );
    assert_eq!(out, 0);
    ok(aster_result_close(n, &raw mut handles[0]));
    out = query(n, 0);
    ok(aster_result_close(n, &raw mut out));
    ok(aster_node_close(&raw mut n));
}
