use aster_redb_store::{EventClientId, EventPublicationSession, Store};
use std::process::Command;

fn random_claim_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("test claim randomness");
    nonce
}

#[test]
fn offline_operator_limits_retirement_and_capacity_preserve_permanent_slots() {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!(
        "aster-client-lifecycle-{}-{:x?}",
        std::process::id(),
        nonce
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("mesh.redb");
    let client = EventClientId::new(b"operator-client".to_vec()).unwrap();
    let store = Store::open_for_mission(&path, [0xb8; 32]).unwrap();
    store
        .begin_event_publication_session(&client, 0, &random_claim_nonce())
        .unwrap();
    drop(store);
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_aster"))
            .args(args)
            .arg("--state")
            .arg(&root)
            .output()
            .unwrap()
    };
    let before = std::fs::read(&path).unwrap();
    assert!(run(&["event-client-capacity"]).status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        !run(&[
            "event-client-retire",
            "--client-id",
            "operator-client",
            "--expected-session",
            "1"
        ])
        .status
        .success()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        run(&[
            "event-client-limits",
            "--max-clients",
            "1",
            "--max-outstanding",
            "1",
            "--max-records",
            "10",
            "--max-bytes",
            "10000"
        ])
        .status
        .success()
    );
    let retirement = run(&[
        "event-client-retire",
        "--client-id-hex",
        "6f70657261746f722d636c69656e74",
        "--expected-session",
        "1",
        "--irreversible",
    ]);
    assert!(
        retirement.status.success(),
        "{}",
        String::from_utf8_lossy(&retirement.stderr)
    );
    let report = run(&["event-client-capacity"]);
    assert!(report.status.success());
    let text = String::from_utf8(report.stdout).unwrap();
    assert!(text.contains("clients=1 retired=1"), "{text}");
    assert!(
        text.contains("max_clients=1 max_outstanding=1 max_records=10 max_bytes=10000"),
        "{text}"
    );
    let store = Store::open_for_mission(&path, [0xb8; 32]).unwrap();
    assert!(
        store
            .begin_event_publication_session(&client, 1, &random_claim_nonce())
            .is_err()
    );
    assert!(
        !store
            .retire_event_client(&client, EventPublicationSession::new(1).unwrap())
            .unwrap()
    );
    // Offline mutation must fail while the node's store writer is held.
    assert!(
        !run(&[
            "event-client-limits",
            "--max-clients",
            "2",
            "--max-outstanding",
            "2",
            "--max-records",
            "20",
            "--max-bytes",
            "20000"
        ])
        .status
        .success()
    );
    assert_eq!(store.event_client_capacity().unwrap().limits.max_clients, 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
