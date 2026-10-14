use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use aster_iroh::PinnedRelay;
use aster_mesh::{ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic};
#[cfg(unix)]
use aster_node::{
    MissionExpectedPeer, NodeApplication, NodeConfig, NodeIdentity, SelectedForwardingConfig,
    application::{
        EventAcknowledgement, EventPollRequest, EventSubscriptionRequest, EventSyncStatus,
        PeerAuthorization, Priority,
    },
    mission::UnprotectedReferenceMission,
    start_node, start_node_with_forwarding,
};
#[cfg(unix)]
use aster_redb_store::{Store, ZeroizationIntent};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Auto-selected UDP blocks are intentionally released before the real child
// binds them. Serialize this binary's process tests so parallel harness workers
// cannot select overlapping blocks and authenticate the wrong test mission.
static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());
#[cfg(unix)]
const PROCESS_READY_TIMEOUT: Duration = Duration::from_secs(40);
#[cfg(unix)]
const LIVE_EVENT_PROCESS_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(unix)]
const LIVE_EVENT_PROCESS_COMPLETION_TIMEOUT: Duration = Duration::from_secs(150);
#[cfg(unix)]
const LIVE_EVENT_CONTACT_TIMEOUT: Duration = Duration::from_secs(120);

fn serialize_process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn fresh_root(test: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "aster-selected-mesh-smoke-{test}-{}-{nonce}-{sequence}",
        std::process::id(),
    ))
}

fn receipt_counter(line: &str, field: &str) -> Option<usize> {
    let prefix = format!("{field}=");
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))?
        .parse()
        .ok()
}

fn assert_exact_event_edge(root: &std::path::Path, phase: &str, source: usize, destination: usize) {
    let source_log = std::fs::read_to_string(root.join(format!("logs/{phase}-node-{source}.log")))
        .expect("exact Event source log");
    let destination_log =
        std::fs::read_to_string(root.join(format!("logs/{phase}-node-{destination}.log")))
            .expect("exact Event destination log");
    let controls_are_zero = |line: &str| {
        [
            "control_offered",
            "control_fetched",
            "control_retained",
            "control_duplicates",
            "control_activated",
            "control_remaining",
        ]
        .into_iter()
        .all(|field| receipt_counter(line, field) == Some(0))
    };
    assert!(source_log.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(1)
            && receipt_counter(line, "fetched") == Some(0)
            && receipt_counter(line, "inserted") == Some(0)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    }));
    assert!(destination_log.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(0)
            && receipt_counter(line, "fetched") == Some(1)
            && receipt_counter(line, "inserted") == Some(1)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    }));
    assert!(
        !source_log
            .lines()
            .chain(destination_log.lines())
            .any(|line| line.starts_with("APPLICATION "))
    );
}

fn assert_peerless_application(
    root: &std::path::Path,
    phase: &str,
    node: usize,
    application: &str,
    kind: &str,
) {
    let log = std::fs::read_to_string(root.join(format!("logs/{phase}-node-{node}.log")))
        .expect("peerless application log");
    assert!(log.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(&format!(" application={application} "))
    }));
    assert!(log.contains(&format!("APPLICATION status=emitted kind={kind} ")));
    assert!(log.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(!log.lines().any(|line| line.starts_with("CONTACT ")));
}

fn assert_default_noop_node(root: &std::path::Path, node: usize, endpoint: bool) {
    let noop = std::fs::read_to_string(root.join(format!("logs/noop-node-{node}.log")))
        .expect("equal-inventory no-op log");
    let passing_contacts = noop
        .lines()
        .filter(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
        .collect::<Vec<_>>();
    assert!(!passing_contacts.is_empty());
    assert!(passing_contacts.iter().all(|line| {
        [
            " control_offered=0 ",
            " control_fetched=0 ",
            " control_retained=0 ",
            " control_duplicates=0 ",
            " control_activated=0 ",
            " control_remaining=0 ",
            " offered=0 ",
            " fetched=0 ",
            " inserted=0 ",
            " duplicates=0 ",
            " remaining=0 ",
        ]
        .into_iter()
        .all(|field| line.contains(field))
    }));
    let stop = noop
        .lines()
        .find(|line| line.starts_with("STOP "))
        .expect("equal-inventory no-op STOP receipt");
    assert!(stop.contains(" controls=0 "));
    assert!(stop.contains(" applied_controls=0 "));
    assert!(stop.contains(" pending_controls=0 "));
    assert!(stop.contains(" control_highwater=0 "));
    if endpoint {
        assert!(stop.contains(" events=2 "));
        assert!(stop.contains(" route_cached_events=0 "));
    } else {
        assert!(stop.contains(" events=0 "));
        assert!(stop.contains(" route_cached_events=2 "));
    }
}

fn persist_zeroization_bundle(path: &std::path::Path, seed: u8) -> Vec<u8> {
    let scope = Scope::new("test/process-zeroization").expect("scope");
    let topic = Topic::new("zeroization-event").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([seed; 32]).expect("zeroization provisioner");
    let bytes = provisioner
        .issue_node(1, &[access])
        .expect("zeroization bundle")
        .to_bytes()
        .expect("encode zeroization bundle");
    std::fs::write(path, &bytes).expect("write zeroization bundle");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only mission permissions");
    }
    bytes
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn wait_for_ready(child: &mut std::process::Child, lines: &mpsc::Receiver<String>) {
    let deadline = Instant::now() + PROCESS_READY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(line) = lines.recv_timeout(Duration::from_millis(100))
            && line.starts_with("READY selected=true ")
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll live node") {
            panic!("node exited before READY with {status}");
        }
    }
    panic!("live node did not emit READY before deadline");
}

#[cfg(unix)]
fn has_selected_ready_marker(line: &str) -> bool {
    line.starts_with("READY selected=true ") || line.contains(" READY selected=true ")
}

fn wait_for_protected_contact(
    child: &mut std::process::Child,
    lines: &mpsc::Receiver<String>,
    expected_prefix: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(line) = lines.recv_timeout(Duration::from_millis(100))
            && line.starts_with(expected_prefix)
            && line.ends_with("status=pass")
            && line.contains(" mission_auth=hybrid-pq ")
            && receipt_counter(&line, "handshake_frames") == Some(4)
            && receipt_counter(&line, "handshake_bytes").is_some_and(|bytes| bytes > 0)
            && receipt_counter(&line, "protected_frames").is_some_and(|frames| frames > 0)
            && receipt_counter(&line, "protected_bytes").is_some_and(|bytes| bytes > 0)
        {
            return line;
        }
        if let Some(status) = child.try_wait().expect("poll contact node") {
            panic!("node exited before protected contact with {status}");
        }
    }
    panic!("node did not emit a completed hybrid/protected contact before deadline");
}

#[cfg(unix)]
fn live_event_worker_command(
    role: &str,
    state: &std::path::Path,
    mission: &std::path::Path,
    bind: &str,
    peer: Option<&str>,
) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current integration test"));
    for name in [
        "ASTER_LIVE_EVENT_PEER",
        "ASTER_LIVE_EVENT_RELAY_URL",
        "ASTER_LIVE_EVENT_RELAY_CA_DER",
        "ASTER_LIVE_EVENT_RELAY_ONLY",
        "ASTER_LIVE_EVENT_MIN_CONTACTS",
        "ASTER_LIVE_EVENT_READY",
    ] {
        command.env_remove(name);
    }
    command
        .args(["--exact", "live_event_process_worker", "--nocapture"])
        .env("ASTER_LIVE_EVENT_WORKER", role)
        .env("ASTER_LIVE_EVENT_STATE", state)
        .env("ASTER_LIVE_EVENT_MISSION", mission)
        .env("ASTER_LIVE_EVENT_BIND", bind)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(peer) = peer {
        command.env("ASTER_LIVE_EVENT_PEER", peer);
    }
    command
}

#[cfg(unix)]
fn configure_live_event_controlled_relay(
    command: &mut Command,
    relay_url: &str,
    ca_paths: &[PathBuf],
    minimum_contacts: u64,
) {
    command
        .env("ASTER_LIVE_EVENT_RELAY_URL", relay_url)
        .env(
            "ASTER_LIVE_EVENT_RELAY_CA_DER",
            std::env::join_paths(ca_paths).expect("join relay CA paths"),
        )
        .env(
            "ASTER_LIVE_EVENT_MIN_CONTACTS",
            minimum_contacts.to_string(),
        );
}

#[cfg(unix)]
fn assert_live_event_worker(output: std::process::Output, marker: &str) {
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 worker stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 worker stderr");
    assert!(
        output.status.success(),
        "live Event worker failed: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "worker omitted {marker:?}: stdout={stdout} stderr={stderr}"
    );
}

#[cfg(unix)]
fn live_event_worker_bind_collision(output: &std::process::Output) -> bool {
    if output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    [stdout.as_ref(), stderr.as_ref()]
        .iter()
        .any(|stream| live_event_bind_collision_text(stream))
}

#[cfg(unix)]
fn live_event_bind_collision_text(stream: &str) -> bool {
    stream.contains("AddrInUse")
        || stream.contains("Address already in use")
        || stream.contains("EADDRINUSE")
        || stream.contains("Failed to bind sockets")
        || stream.contains("Failed%20to%20bind%20sockets")
}

#[cfg(unix)]
#[test]
fn bind_collision_detector_accepts_top_level_raw_and_encoded_iroh_errors() {
    assert!(live_event_bind_collision_text(
        "transport error: Failed to bind sockets"
    ));
    assert!(live_event_bind_collision_text(
        "ERROR error=transport%20error%3A%20Failed%20to%20bind%20sockets"
    ));
    assert!(live_event_bind_collision_text("error=EADDRINUSE"));
    assert!(!live_event_bind_collision_text(
        "transport error: relay unavailable"
    ));
}

#[cfg(unix)]
#[test]
fn selected_ready_marker_accepts_a_libtest_prefix_at_a_record_boundary() {
    assert!(has_selected_ready_marker(
        "READY selected=true carrier_route=direct"
    ));
    assert!(has_selected_ready_marker(
        "test live_event_process_worker ... READY selected=true carrier_route=direct"
    ));
    assert!(!has_selected_ready_marker(
        "NOTREADY selected=true carrier_route=direct"
    ));
    assert!(!has_selected_ready_marker(
        "READY selected=false carrier_route=direct"
    ));
}

#[cfg(unix)]
fn wait_for_live_event_workers(
    mut receiver: std::process::Child,
    mut publisher: std::process::Child,
) -> (std::process::Output, std::process::Output) {
    let deadline = Instant::now() + LIVE_EVENT_PROCESS_COMPLETION_TIMEOUT;
    let mut receiver_status = None;
    let mut publisher_status = None;
    let mut timed_out = false;
    loop {
        if receiver_status.is_none() {
            receiver_status = receiver
                .try_wait()
                .expect("poll live Event receiver")
                .map(|status| status.success());
        }
        if publisher_status.is_none() {
            publisher_status = publisher
                .try_wait()
                .expect("poll live Event publisher")
                .map(|status| status.success());
        }
        if receiver_status == Some(false) || publisher_status == Some(false) {
            if receiver_status.is_none() {
                let _ = receiver.kill();
            }
            if publisher_status.is_none() {
                let _ = publisher.kill();
            }
            break;
        }
        if receiver_status.is_some() && publisher_status.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            if receiver_status.is_none() {
                let _ = receiver.kill();
            }
            if publisher_status.is_none() {
                let _ = publisher.kill();
            }
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let receiver = receiver
        .wait_with_output()
        .expect("collect live Event receiver");
    let publisher = publisher
        .wait_with_output()
        .expect("collect live Event publisher");
    if timed_out {
        panic!(
            "live Event workers exceeded their runtime-valid deadline: receiver_stdout={} receiver_stderr={} publisher_stdout={} publisher_stderr={}",
            String::from_utf8_lossy(&receiver.stdout),
            String::from_utf8_lossy(&receiver.stderr),
            String::from_utf8_lossy(&publisher.stdout),
            String::from_utf8_lossy(&publisher.stderr),
        );
    }
    (receiver, publisher)
}

#[cfg(unix)]
#[test]
fn live_event_process_worker() {
    let Ok(role) = std::env::var("ASTER_LIVE_EVENT_WORKER") else {
        return;
    };
    let state = PathBuf::from(
        std::env::var_os("ASTER_LIVE_EVENT_STATE").expect("worker state environment"),
    );
    let mission_path = PathBuf::from(
        std::env::var_os("ASTER_LIVE_EVENT_MISSION").expect("worker mission environment"),
    );
    let bind = std::env::var("ASTER_LIVE_EVENT_BIND")
        .expect("worker bind environment")
        .parse()
        .expect("worker bind address");
    let peers = std::env::var("ASTER_LIVE_EVENT_PEER")
        .ok()
        .map(|peer| peer.parse::<MissionExpectedPeer>().expect("worker peer"))
        .into_iter()
        .collect::<Vec<_>>();
    let expected_peer = peers.first().map(|peer| peer.mission);
    let controlled_relay = std::env::var("ASTER_LIVE_EVENT_RELAY_URL").ok().map(|url| {
        let roots = std::env::var_os("ASTER_LIVE_EVENT_RELAY_CA_DER")
            .map(|paths| {
                std::env::split_paths(&paths)
                    .map(|path| std::fs::read(path).expect("worker relay CA root"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let url = url.parse().expect("worker relay URL");
        if roots.is_empty() {
            PinnedRelay::new(url).expect("worker WebPKI relay")
        } else {
            PinnedRelay::with_ca_roots(url, roots).expect("worker pinned relay roots")
        }
    });
    let relay_only = std::env::var_os("ASTER_LIVE_EVENT_RELAY_ONLY").is_some();
    let minimum_contacts = std::env::var("ASTER_LIVE_EVENT_MIN_CONTACTS")
        .ok()
        .map(|value| value.parse::<u64>().expect("minimum contact count"))
        .unwrap_or(1);
    let relay_enabled = controlled_relay.is_some();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("worker Tokio runtime");
    runtime.block_on(async move {
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("worker mission");
        let config = NodeConfig {
            state: state.clone(),
            bind,
            mission,
            peers,
            mutable_interests: Default::default(),
            sync_interval: Duration::from_millis(500),
            run_for: None,
            application: NodeApplication::Relay,
        };
        let running = match controlled_relay {
            Some(relay) if relay_only => {
                start_node_with_forwarding(
                    config,
                    SelectedForwardingConfig::default().with_controlled_relay_only(relay),
                )
                .await
            }
            Some(relay) => {
                start_node_with_forwarding(
                    config,
                    SelectedForwardingConfig::default().with_controlled_relay(relay),
                )
                .await
            }
            None => start_node(config).await,
        }
        .expect("start worker node");
        let events = running.selected_events();
        let scope = Scope::new("test/process-live-event").expect("worker scope");
        let topic = Topic::new("offline-later-sync").expect("worker topic");

        match role.as_str() {
            "offline-publisher" => {
                use aster_node::publication_journal::{Backend, Intent, Journal};
                let journal_path = state.join("source-publication.redb");
                Journal::initialize(&journal_path, b"process-offline-source").unwrap();
                let mut journal = Journal::open(&journal_path, b"process-offline-source").unwrap();
                let mut backend = Backend::Live(&events);
                journal.recover(&mut backend).await.unwrap();
                let published = journal.publish_metadata(&mut backend, Intent {
                    predecessor: None, topic: topic.as_str().to_owned(), scope: scope.as_str().to_owned(), priority: Priority::Priority as u8,
                    logical_key: b"process-offline-key".to_vec(), payload: b"published before either peer was online".to_vec(), tombstone: false, ttl_ms: None,
                }).await.unwrap();
                journal.acknowledge(&mut backend).await.unwrap();
                let status = events.status().await.expect("offline status");
                assert_eq!(status.sync, EventSyncStatus::Offline);
                assert_eq!(status.authenticated_contacts, 0);
                let receipt = running.shutdown().await.expect("offline shutdown");
                assert!(!relay_enabled || receipt.contacts == receipt.relay_contacts);
                println!("WORKER_OFFLINE_PUBLISHED id={}", published.id);
            }
            "sync-publisher" => {
                let mut observed = None;
                let contact_deadline = Instant::now() + LIVE_EVENT_CONTACT_TIMEOUT;
                while Instant::now() < contact_deadline {
                    let status = events.status().await.expect("publisher live status");
                    if status.authenticated_contacts >= minimum_contacts {
                        observed = Some(status);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let status = observed.expect("publisher authenticated later contact");
                assert_eq!(status.peers.len(), 1);
                assert_eq!(
                    status.peers[0].peer,
                    expected_peer.expect("configured peer")
                );
                assert_eq!(status.peers[0].authorization, PeerAuthorization::Active);
                assert_eq!(status.sync, EventSyncStatus::LastContactComplete);
                let receipt = running.shutdown().await.expect("publisher shutdown");
                if relay_enabled {
                    assert_eq!(receipt.direct_contacts, 0);
                    assert_eq!(receipt.unknown_path_contacts, 0);
                    assert_eq!(receipt.relay_contacts, receipt.contacts);
                }
                println!(
                    "WORKER_PUBLISHER_SYNC contacts={} sync={:?} direct_contacts={} relay_contacts={}",
                    status.authenticated_contacts,
                    status.sync,
                    receipt.direct_contacts,
                    receipt.relay_contacts
                );
            }
            "sync-receiver" => {
                let subscription = events
                    .subscribe(EventSubscriptionRequest {
                        operation_key: b"process-later-sync-subscription".to_vec(),
                        topic,
                        scope,
                        include_descendant_scopes: false,
                    })
                    .await
                    .expect("receiver subscription");
                if let Some(ready) = std::env::var_os("ASTER_LIVE_EVENT_READY") {
                    std::fs::write(ready, b"subscription-durable")
                        .expect("publish receiver readiness");
                }
                let receiver_deadline = Instant::now() + LIVE_EVENT_CONTACT_TIMEOUT;
                let mut delivery = None;
                while Instant::now() < receiver_deadline {
                    let page = events
                        .poll(EventPollRequest {
                            subscription: subscription.id,
                            delivery_limit: 8,
                            scan_limit: 8,
                        })
                        .await
                        .expect("receiver poll");
                    if let Some(found) = page.deliveries.into_iter().next() {
                        delivery = Some(found);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let delivery = delivery.expect("later sync delivered offline Event");
                assert_eq!(
                    delivery.event.payload,
                    b"published before either peer was online"
                );
                assert_eq!(
                    events
                        .acknowledge(subscription.id, delivery.event.id)
                        .await
                        .expect("receiver acknowledge"),
                    EventAcknowledgement::Acknowledged
                );
                assert!(
                    events
                        .poll(EventPollRequest {
                            subscription: subscription.id,
                            delivery_limit: 8,
                            scan_limit: 8,
                        })
                        .await
                        .expect("poll after acknowledgement")
                        .deliveries
                        .is_empty()
                );
                let mut observed = None;
                let status_deadline = Instant::now() + LIVE_EVENT_CONTACT_TIMEOUT;
                while Instant::now() < status_deadline {
                    let status = events.status().await.expect("receiver live status");
                    if status.authenticated_contacts >= minimum_contacts {
                        observed = Some(status);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let status = observed.expect("receiver authenticated later contact");
                assert_eq!(status.peers.len(), 1);
                assert_eq!(
                    status.peers[0].peer,
                    expected_peer.expect("configured peer")
                );
                assert_eq!(status.peers[0].authorization, PeerAuthorization::Active);
                let receipt = running.shutdown().await.expect("receiver shutdown");
                if relay_enabled {
                    assert_eq!(receipt.direct_contacts, 0);
                    assert_eq!(receipt.unknown_path_contacts, 0);
                    assert_eq!(receipt.relay_contacts, receipt.contacts);
                }
                println!(
                    "WORKER_RECEIVED id={} attempt={} contacts={} sync={:?} direct_contacts={} relay_contacts={}",
                    delivery.event.id,
                    delivery.attempt,
                    status.authenticated_contacts,
                    status.sync,
                    receipt.direct_contacts,
                    receipt.relay_contacts
                );
            }
            "restart-receiver" => {
                let subscription = events
                    .subscribe(EventSubscriptionRequest {
                        operation_key: b"process-later-sync-subscription".to_vec(),
                        topic,
                        scope,
                        include_descendant_scopes: false,
                    })
                    .await
                    .expect("restart subscription");
                assert!(!subscription.inserted);
                assert!(
                    events
                        .poll(EventPollRequest {
                            subscription: subscription.id,
                            delivery_limit: 8,
                            scan_limit: 8,
                        })
                        .await
                        .expect("restart poll")
                        .deliveries
                        .is_empty()
                );
                assert_eq!(
                    events.status().await.expect("restart status").sync,
                    EventSyncStatus::Offline
                );
                let receipt = running.shutdown().await.expect("restart shutdown");
                assert!(!relay_enabled || receipt.contacts == receipt.relay_contacts);
                println!("WORKER_RESTART_ACK_DURABLE");
            }
            _ => panic!("unknown live Event worker role {role:?}"),
        }
    });
}

#[cfg(unix)]
#[test]
fn offline_publish_later_real_process_sync_poll_ack_and_restart() {
    use std::{net::UdpSocket, os::unix::fs::PermissionsExt as _};

    let _process_test = serialize_process_test();
    let root = fresh_root("offline-later-live-event");
    let publisher_state = root.join("publisher-state");
    let receiver_state = root.join("receiver-state");
    let publisher_mission_path = root.join("publisher.bundle");
    let receiver_mission_path = root.join("receiver.bundle");
    std::fs::create_dir_all(&root).expect("process root");
    let scope = Scope::new("test/process-live-event").expect("scope");
    let topic = Topic::new("offline-later-sync").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner = ReferenceProvisioner::from_seed([0xe2; 32]).expect("process provisioner");
    let publisher_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .expect("publisher mission")
        .to_bytes()
        .expect("publisher bytes");
    let receiver_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&access))
        .expect("receiver mission")
        .to_bytes()
        .expect("receiver bytes");
    let publisher_mission =
        UnprotectedReferenceMission::persist(&publisher_mission_path, publisher_bytes)
            .expect("persist publisher mission");
    let publisher_mission_id = publisher_mission.identity();
    drop(publisher_mission);
    let receiver_mission =
        UnprotectedReferenceMission::persist(&receiver_mission_path, receiver_bytes)
            .expect("persist receiver mission");
    let receiver_mission_id = receiver_mission.identity();
    drop(receiver_mission);
    std::fs::set_permissions(
        &publisher_mission_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("publisher mission permissions");
    std::fs::set_permissions(
        &receiver_mission_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("receiver mission permissions");

    let publisher_identity =
        NodeIdentity::load_or_create(&publisher_state).expect("publisher identity");
    let publisher_carrier = publisher_identity.id();
    drop(publisher_identity);
    let receiver_identity =
        NodeIdentity::load_or_create(&receiver_state).expect("receiver identity");
    let receiver_carrier = receiver_identity.id();
    drop(receiver_identity);

    let offline = live_event_worker_command(
        "offline-publisher",
        &publisher_state,
        &publisher_mission_path,
        "127.0.0.1:0",
        None,
    )
    .output()
    .expect("offline publisher process");
    assert_live_event_worker(offline, "WORKER_OFFLINE_PUBLISHED");

    let receiver_ready = root.join("receiver-subscription-ready");
    // One absolute budget covers cold store initialization and every bounded
    // bind-collision retry. Do not reset it per attempt and multiply a hang.
    let readiness_deadline = Instant::now() + LIVE_EVENT_PROCESS_STARTUP_TIMEOUT;
    let mut bind_attempt = 0usize;
    let mut last_bind_collision = None;
    let (receiver_output, publisher_output) = loop {
        bind_attempt += 1;
        if bind_attempt > 4 {
            panic!(
                "live Event workers exhausted bind-collision retries: {}",
                last_bind_collision.unwrap_or_else(|| "no collision details".into())
            );
        }
        match std::fs::remove_file(&receiver_ready) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("clear receiver readiness sentinel: {error}"),
        }

        let publisher_socket = UdpSocket::bind("127.0.0.1:0").expect("publisher port");
        let publisher_address = publisher_socket.local_addr().expect("publisher address");
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").expect("receiver port");
        let receiver_address = receiver_socket.local_addr().expect("receiver address");
        let publisher_peer = format!(
            "{receiver_carrier}@{receiver_address}={}",
            aster_node::format_node_id(receiver_mission_id)
        );
        let receiver_peer = format!(
            "{publisher_carrier}@{publisher_address}={}",
            aster_node::format_node_id(publisher_mission_id)
        );
        drop(receiver_socket);

        let mut receiver_command = live_event_worker_command(
            "sync-receiver",
            &receiver_state,
            &receiver_mission_path,
            &receiver_address.to_string(),
            Some(&receiver_peer),
        );
        receiver_command.env("ASTER_LIVE_EVENT_READY", &receiver_ready);
        let mut receiver = Some(receiver_command.spawn().expect("spawn later receiver"));
        let receiver_start_failure = loop {
            if receiver_ready.exists() {
                break None;
            }
            if receiver
                .as_mut()
                .expect("receiver remains owned before readiness")
                .try_wait()
                .expect("poll receiver readiness")
                .is_some()
            {
                break Some(
                    receiver
                        .take()
                        .expect("take failed receiver")
                        .wait_with_output()
                        .expect("collect failed receiver startup"),
                );
            }
            if Instant::now() >= readiness_deadline {
                let mut receiver = receiver.take().expect("take timed-out receiver");
                let _ = receiver.kill();
                let output = receiver
                    .wait_with_output()
                    .expect("collect timed-out receiver startup");
                panic!(
                    "receiver did not durably subscribe within the shared {}s startup deadline: stdout={} stderr={}",
                    LIVE_EVENT_PROCESS_STARTUP_TIMEOUT.as_secs(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            thread::sleep(Duration::from_millis(20));
        };
        if let Some(output) = receiver_start_failure {
            if live_event_worker_bind_collision(&output) {
                last_bind_collision = Some(format!(
                    "attempt {bind_attempt} receiver: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
                continue;
            }
            assert_live_event_worker(output, "WORKER_RECEIVED");
            unreachable!("failed receiver assertion returns only by panicking");
        }
        let receiver = receiver.expect("ready receiver remains owned");

        // Keep the publisher port reserved until the receiver has durably
        // subscribed, then narrow the unavoidable release-to-child-bind gap.
        drop(publisher_socket);
        let publisher = match live_event_worker_command(
            "sync-publisher",
            &publisher_state,
            &publisher_mission_path,
            &publisher_address.to_string(),
            Some(&publisher_peer),
        )
        .spawn()
        {
            Ok(publisher) => publisher,
            Err(error) => {
                let mut receiver = receiver;
                let _ = receiver.kill();
                let output = receiver
                    .wait_with_output()
                    .expect("collect receiver after publisher spawn failure");
                panic!(
                    "spawn restarted publisher: {error}; receiver_stdout={} receiver_stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        };
        let (receiver_output, publisher_output) = wait_for_live_event_workers(receiver, publisher);
        if live_event_worker_bind_collision(&receiver_output)
            || live_event_worker_bind_collision(&publisher_output)
        {
            last_bind_collision = Some(format!(
                "attempt {bind_attempt}: receiver={} publisher={}",
                String::from_utf8_lossy(&receiver_output.stderr),
                String::from_utf8_lossy(&publisher_output.stderr),
            ));
            continue;
        }
        break (receiver_output, publisher_output);
    };
    assert_live_event_worker(receiver_output, "WORKER_RECEIVED");
    assert_live_event_worker(publisher_output, "WORKER_PUBLISHER_SYNC");

    let restart = live_event_worker_command(
        "restart-receiver",
        &receiver_state,
        &receiver_mission_path,
        "127.0.0.1:0",
        None,
    )
    .output()
    .expect("restart receiver process");
    assert_live_event_worker(restart, "WORKER_RESTART_ACK_DURABLE");
    std::fs::remove_dir_all(root).expect("cleanup process evidence");
}

#[cfg(unix)]
#[test]
fn controlled_relay_selected_when_direct_candidate_unusable_then_noops() {
    use std::os::unix::fs::PermissionsExt as _;

    let _process_test = serialize_process_test();
    let relay_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("controlled relay runtime");
    let fixture = relay_runtime
        .block_on(aster_iroh::test_utils::RelayFixture::spawn())
        .expect("self-hosted controlled relay");

    let root = fresh_root("controlled-relay-live-event");
    let publisher_state = root.join("publisher-state");
    let receiver_state = root.join("receiver-state");
    let publisher_mission_path = root.join("publisher.bundle");
    let receiver_mission_path = root.join("receiver.bundle");
    std::fs::create_dir_all(&root).expect("relay process root");
    let scope = Scope::new("test/process-live-event").expect("relay scope");
    let topic = Topic::new("offline-later-sync").expect("relay topic");
    let access =
        ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("relay mission access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xe3; 32]).expect("relay process provisioner");
    let publisher_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .expect("relay publisher mission")
        .to_bytes()
        .expect("relay publisher bytes");
    let receiver_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&access))
        .expect("relay receiver mission")
        .to_bytes()
        .expect("relay receiver bytes");
    let publisher_mission =
        UnprotectedReferenceMission::persist(&publisher_mission_path, publisher_bytes)
            .expect("persist relay publisher mission");
    let publisher_mission_id = publisher_mission.identity();
    drop(publisher_mission);
    let receiver_mission =
        UnprotectedReferenceMission::persist(&receiver_mission_path, receiver_bytes)
            .expect("persist relay receiver mission");
    let receiver_mission_id = receiver_mission.identity();
    drop(receiver_mission);
    for path in [&publisher_mission_path, &receiver_mission_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only relay mission permissions");
    }

    let publisher_identity =
        NodeIdentity::load_or_create(&publisher_state).expect("relay publisher identity");
    let publisher_carrier = publisher_identity.id();
    drop(publisher_identity);
    let receiver_identity =
        NodeIdentity::load_or_create(&receiver_state).expect("relay receiver identity");
    let receiver_carrier = receiver_identity.id();
    drop(receiver_identity);
    let publisher_initiates = publisher_carrier < receiver_carrier;

    let relay_ca_paths = fixture
        .ca_roots_der()
        .iter()
        .enumerate()
        .map(|(index, root_der)| {
            let path = root.join(format!("relay-ca-{index}.der"));
            std::fs::write(&path, root_der).expect("write exact relay CA root");
            path
        })
        .collect::<Vec<_>>();
    assert!(!relay_ca_paths.is_empty());
    let relay_url = fixture.relay_url().to_string();

    let offline = live_event_worker_command(
        "offline-publisher",
        &publisher_state,
        &publisher_mission_path,
        "127.0.0.1:0",
        None,
    )
    .output()
    .expect("offline relay publisher process");
    assert_live_event_worker(offline, "WORKER_OFFLINE_PUBLISHED");

    // These exact direct candidates are intentionally unreachable. The
    // lower-carrier-ID initiator offers that candidate alongside the pinned
    // relay while the responder's IP transport is disabled below. Its
    // successful Relay witness therefore proves the controlled relay was
    // selected when the exact direct candidate could not reach the responder.
    let publisher_peer = format!(
        "{receiver_carrier}@127.0.0.1:9={}",
        aster_node::format_node_id(receiver_mission_id)
    );
    let receiver_peer = format!(
        "{publisher_carrier}@127.0.0.1:9={}",
        aster_node::format_node_id(publisher_mission_id)
    );
    let receiver_ready = root.join("relay-receiver-subscription-ready");
    let mut receiver_command = live_event_worker_command(
        "sync-receiver",
        &receiver_state,
        &receiver_mission_path,
        "127.0.0.1:0",
        Some(&receiver_peer),
    );
    receiver_command.env("ASTER_LIVE_EVENT_READY", &receiver_ready);
    configure_live_event_controlled_relay(&mut receiver_command, &relay_url, &relay_ca_paths, 2);
    if publisher_initiates {
        // Disable the responder's IP transport. The lower-ID publisher still
        // offers the unreachable exact direct candidate alongside the relay,
        // so a successful Relay witness is deterministic selection evidence.
        receiver_command.env("ASTER_LIVE_EVENT_RELAY_ONLY", "1");
    }
    let mut receiver = receiver_command
        .spawn()
        .expect("spawn controlled-relay receiver");
    let ready_deadline = Instant::now() + LIVE_EVENT_PROCESS_STARTUP_TIMEOUT;
    while !receiver_ready.exists() {
        if let Some(status) = receiver
            .try_wait()
            .expect("poll controlled-relay receiver readiness")
        {
            let output = receiver
                .wait_with_output()
                .expect("collect failed controlled-relay receiver");
            panic!(
                "controlled-relay receiver exited before subscription readiness with {status}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = receiver.kill();
            let output = receiver
                .wait_with_output()
                .expect("reap timed-out controlled-relay receiver");
            panic!(
                "controlled-relay receiver did not publish subscription readiness: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        thread::sleep(Duration::from_millis(20));
    }

    let mut publisher_command = live_event_worker_command(
        "sync-publisher",
        &publisher_state,
        &publisher_mission_path,
        "127.0.0.1:0",
        Some(&publisher_peer),
    );
    configure_live_event_controlled_relay(&mut publisher_command, &relay_url, &relay_ca_paths, 2);
    if !publisher_initiates {
        publisher_command.env("ASTER_LIVE_EVENT_RELAY_ONLY", "1");
    }
    let publisher = match publisher_command.spawn() {
        Ok(publisher) => publisher,
        Err(error) => {
            let _ = receiver.kill();
            let receiver_output = receiver
                .wait_with_output()
                .expect("reap receiver after publisher spawn failure");
            panic!(
                "spawn controlled-relay publisher: {error}; receiver_stdout={} receiver_stderr={}",
                String::from_utf8_lossy(&receiver_output.stdout),
                String::from_utf8_lossy(&receiver_output.stderr),
            );
        }
    };
    let (receiver_output, publisher_output) = wait_for_live_event_workers(receiver, publisher);
    let receiver_stdout =
        String::from_utf8(receiver_output.stdout).expect("UTF-8 relay receiver stdout");
    let receiver_stderr =
        String::from_utf8(receiver_output.stderr).expect("UTF-8 relay receiver stderr");
    let publisher_stdout =
        String::from_utf8(publisher_output.stdout).expect("UTF-8 relay publisher stdout");
    let publisher_stderr =
        String::from_utf8(publisher_output.stderr).expect("UTF-8 relay publisher stderr");
    assert!(
        receiver_output.status.success() && publisher_output.status.success(),
        "controlled-relay Event workers failed: receiver_stdout={receiver_stdout} receiver_stderr={receiver_stderr} publisher_stdout={publisher_stdout} publisher_stderr={publisher_stderr}"
    );
    assert!(receiver_stdout.contains("WORKER_RECEIVED "));
    assert!(publisher_stdout.contains("WORKER_PUBLISHER_SYNC "));
    let relay_log = format!("{receiver_stdout}\n{publisher_stdout}");
    assert!(
        relay_log.lines().any(|line| {
            has_selected_ready_marker(line)
                && line.contains(" carrier_route=direct-plus-controlled-relay ")
                && line.contains(" controlled_relay_readiness=deferred ")
                && line.contains(" controlled_relay_trust=explicit-der-roots ")
                && line.contains(" public_relay_fallback=false ")
                && line.contains(" hosted_discovery=false ")
        }),
        "direct-plus-controlled-relay READY receipt missing: {relay_log}"
    );
    assert!(
        relay_log.lines().any(|line| {
            has_selected_ready_marker(line)
                && line.contains(" carrier_route=controlled-relay-only ")
                && line.contains(" controlled_relay_readiness=required-ready ")
        }),
        "controlled-relay-only READY receipt missing: {relay_log}"
    );
    let successful_contacts = relay_log
        .lines()
        .filter(|line| {
            line.starts_with("CONTACT ")
                && line.ends_with("status=pass")
                && line.contains(" carrier_path=relay ")
                && line.contains(" path_observation=not-authorization ")
                && line.contains(" mission_auth=hybrid-pq ")
        })
        .collect::<Vec<_>>();
    assert!(
        successful_contacts.len() >= 4,
        "two authenticated relay contacts must complete at both endpoints: {relay_log}"
    );
    assert!(
        successful_contacts
            .iter()
            .all(|line| { line.contains(" carrier_path_transitions_saturated=false ") })
    );
    assert!(
        successful_contacts.iter().any(|line| {
            receipt_counter(line, "offered") == Some(0)
                && receipt_counter(line, "fetched") == Some(0)
                && receipt_counter(line, "inserted") == Some(0)
                && receipt_counter(line, "duplicates") == Some(0)
                && receipt_counter(line, "remaining") == Some(0)
        }),
        "second equal-inventory relay contact transferred work: {relay_log}"
    );
    assert!(!relay_log.contains(" carrier_path=direct "));
    let relay_stops = relay_log
        .lines()
        .filter(|line| line.starts_with("STOP "))
        .collect::<Vec<_>>();
    assert_eq!(relay_stops.len(), 2);
    assert!(relay_stops.iter().all(|line| {
        receipt_counter(line, "direct_contacts") == Some(0)
            && receipt_counter(line, "unknown_path_contacts") == Some(0)
            && receipt_counter(line, "relay_contacts") == receipt_counter(line, "contacts")
    }));
    assert!(relay_stops.iter().all(|line| {
        receipt_counter(line, "relay_contacts").is_some_and(|contacts| contacts >= 2)
    }));

    let dead_relay_state = root.join("dead-relay-direct-state");
    let dead_relay = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&dead_relay_state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&receiver_mission_path)
        .args([
            "--controlled-relay-url",
            "https://127.0.0.1:1/",
            "--controlled-relay-trust",
            "webpki",
            "--run-for",
            "1",
        ])
        .output()
        .expect("run direct-capable node with unavailable controlled relay");
    let dead_relay_stdout = String::from_utf8(dead_relay.stdout).expect("UTF-8 dead-relay stdout");
    let dead_relay_stderr = String::from_utf8(dead_relay.stderr).expect("UTF-8 dead-relay stderr");
    assert!(
        dead_relay.status.success(),
        "unavailable optional relay blocked direct-capable startup: stdout={dead_relay_stdout} stderr={dead_relay_stderr}"
    );
    assert!(dead_relay_stdout.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" carrier_route=direct-plus-controlled-relay ")
            && line.contains(" controlled_relay_readiness=deferred ")
    }));

    let cli_state = root.join("relay-cli-state");
    let mut cli = Command::new(env!("CARGO_BIN_EXE_aster"));
    cli.args(["node", "--state"])
        .arg(&cli_state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&receiver_mission_path)
        .args([
            "--controlled-relay-url",
            &relay_url,
            "--controlled-relay-trust",
            "der-roots",
            "--controlled-relay-only",
            "--run-for",
            "1",
        ]);
    for ca_path in &relay_ca_paths {
        cli.arg("--controlled-relay-ca-der").arg(ca_path);
    }
    let cli_output = cli.output().expect("run valid controlled-relay CLI");
    let cli_stdout =
        String::from_utf8(cli_output.stdout).expect("UTF-8 controlled-relay CLI stdout");
    let cli_stderr =
        String::from_utf8(cli_output.stderr).expect("UTF-8 controlled-relay CLI stderr");
    assert!(
        cli_output.status.success(),
        "valid controlled-relay CLI failed: stdout={cli_stdout} stderr={cli_stderr}"
    );
    assert!(cli_stdout.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" carrier_route=controlled-relay-only ")
            && line.contains(" controlled_relay_trust=explicit-der-roots ")
            && line.contains(" public_relay_fallback=false ")
    }));
    assert!(cli_stdout.lines().any(|line| {
        line.starts_with("STOP ")
            && receipt_counter(line, "contacts") == Some(0)
            && receipt_counter(line, "relay_contacts") == Some(0)
    }));

    relay_runtime
        .block_on(fixture.shutdown())
        .expect("stop controlled relay fixture");
    std::fs::remove_dir_all(root).expect("cleanup controlled relay evidence");
}

#[cfg(unix)]
#[test]
fn unavailable_controlled_relay_does_not_block_exact_direct_sync() {
    use std::{net::UdpSocket, os::unix::fs::PermissionsExt as _};

    let _process_test = serialize_process_test();
    let root = fresh_root("dead-relay-exact-direct");
    let first_state = root.join("first-state");
    let second_state = root.join("second-state");
    let first_mission_path = root.join("first.bundle");
    let second_mission_path = root.join("second.bundle");
    std::fs::create_dir_all(&root).expect("dead relay direct root");
    let scope = Scope::new("test/dead-relay-direct").expect("dead relay direct scope");
    let topic = Topic::new("exact-direct").expect("dead relay direct topic");
    let access =
        ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("dead relay direct access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xe4; 32]).expect("dead relay provisioner");
    let first_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .expect("first dead relay mission")
        .to_bytes()
        .expect("first dead relay mission bytes");
    let second_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&access))
        .expect("second dead relay mission")
        .to_bytes()
        .expect("second dead relay mission bytes");
    let first_mission = UnprotectedReferenceMission::persist(&first_mission_path, first_bytes)
        .expect("persist first dead relay mission");
    let first_mission_id = first_mission.identity();
    drop(first_mission);
    let second_mission = UnprotectedReferenceMission::persist(&second_mission_path, second_bytes)
        .expect("persist second dead relay mission");
    let second_mission_id = second_mission.identity();
    drop(second_mission);
    for path in [&first_mission_path, &second_mission_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only dead relay mission permissions");
    }
    let first_carrier = NodeIdentity::load_or_create(&first_state)
        .expect("first dead relay identity")
        .id();
    let second_carrier = NodeIdentity::load_or_create(&second_state)
        .expect("second dead relay identity")
        .id();

    let mut bind_attempt = 0usize;
    let mut collision = None;
    let (first_output, second_output) = loop {
        bind_attempt += 1;
        let first_socket = UdpSocket::bind("127.0.0.1:0").expect("reserve first direct socket");
        let first_address = first_socket.local_addr().expect("first direct address");
        let second_socket = UdpSocket::bind("127.0.0.1:0").expect("reserve second direct socket");
        let second_address = second_socket.local_addr().expect("second direct address");
        drop(first_socket);
        drop(second_socket);
        let first_peer = format!(
            "{second_carrier}@{second_address}={}",
            aster_node::format_node_id(second_mission_id)
        );
        let second_peer = format!(
            "{first_carrier}@{first_address}={}",
            aster_node::format_node_id(first_mission_id)
        );
        let mut first = Command::new(env!("CARGO_BIN_EXE_aster"));
        first
            .args(["node", "--state"])
            .arg(&first_state)
            .args(["--bind", &first_address.to_string()])
            .args(["--mission-bundle-unprotected-reference"])
            .arg(&first_mission_path)
            .args([
                "--peer",
                &first_peer,
                "--controlled-relay-url",
                "https://127.0.0.1:1/",
                "--controlled-relay-trust",
                "webpki",
                "--sync-ms",
                "1000",
                "--run-for",
                "5",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut second = Command::new(env!("CARGO_BIN_EXE_aster"));
        second
            .args(["node", "--state"])
            .arg(&second_state)
            .args(["--bind", &second_address.to_string()])
            .args(["--mission-bundle-unprotected-reference"])
            .arg(&second_mission_path)
            .args([
                "--peer",
                &second_peer,
                "--controlled-relay-url",
                "https://127.0.0.1:1/",
                "--controlled-relay-trust",
                "webpki",
                "--sync-ms",
                "1000",
                "--run-for",
                "5",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut first = first.spawn().expect("spawn first dead relay direct node");
        let second = match second.spawn() {
            Ok(second) => second,
            Err(error) => {
                let _ = first.kill();
                let first_output = first
                    .wait_with_output()
                    .expect("reap first direct node after second spawn failure");
                panic!(
                    "spawn second dead relay direct node: {error}; first_stdout={} first_stderr={}",
                    String::from_utf8_lossy(&first_output.stdout),
                    String::from_utf8_lossy(&first_output.stderr),
                );
            }
        };
        let outputs = wait_for_live_event_workers(first, second);
        if live_event_worker_bind_collision(&outputs.0)
            || live_event_worker_bind_collision(&outputs.1)
        {
            collision = Some(format!(
                "first={} second={}",
                String::from_utf8_lossy(&outputs.0.stderr),
                String::from_utf8_lossy(&outputs.1.stderr)
            ));
            if bind_attempt < 4 {
                continue;
            }
            panic!(
                "dead relay direct nodes exhausted bind-collision retries: {}",
                collision.expect("recorded bind collision")
            );
        }
        break outputs;
    };
    let first_stdout = String::from_utf8(first_output.stdout).expect("UTF-8 first direct stdout");
    let first_stderr = String::from_utf8(first_output.stderr).expect("UTF-8 first direct stderr");
    let second_stdout =
        String::from_utf8(second_output.stdout).expect("UTF-8 second direct stdout");
    let second_stderr =
        String::from_utf8(second_output.stderr).expect("UTF-8 second direct stderr");
    assert!(
        first_output.status.success() && second_output.status.success(),
        "unavailable relay blocked exact direct sync: first_stdout={first_stdout} first_stderr={first_stderr} second_stdout={second_stdout} second_stderr={second_stderr} collision={collision:?}"
    );
    let direct_log = format!("{first_stdout}\n{second_stdout}");
    assert_eq!(
        direct_log
            .lines()
            .filter(|line| {
                line.starts_with("READY ")
                    && line.contains(" carrier_route=direct-plus-controlled-relay ")
                    && line.contains(" controlled_relay_readiness=deferred ")
            })
            .count(),
        2,
        "both direct-capable nodes must become ready with the relay unavailable: {direct_log}"
    );
    let contacts = direct_log
        .lines()
        .filter(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
        .collect::<Vec<_>>();
    assert!(
        contacts.len() >= 2,
        "exact direct contact was not synchronized: {direct_log}"
    );
    assert!(
        contacts.iter().all(|line| {
            line.contains(" carrier_path=direct ")
                && line.contains(" carrier_path_transitions_saturated=false ")
                && line.contains(" path_observation=not-authorization ")
                && receipt_counter(line, "offered") == Some(0)
                && receipt_counter(line, "fetched") == Some(0)
                && receipt_counter(line, "inserted") == Some(0)
        }),
        "exact direct no-op receipts were not stable: {direct_log}"
    );
    assert!(!direct_log.contains(" carrier_path=relay "));
    let direct_stops = direct_log
        .lines()
        .filter(|line| line.starts_with("STOP "))
        .collect::<Vec<_>>();
    assert_eq!(direct_stops.len(), 2);
    assert!(direct_stops.iter().all(|line| {
        receipt_counter(line, "relay_contacts") == Some(0)
            && receipt_counter(line, "unknown_path_contacts") == Some(0)
            && receipt_counter(line, "direct_contacts") == receipt_counter(line, "contacts")
    }));
    assert!(
        direct_stops.iter().all(|line| {
            receipt_counter(line, "direct_contacts").is_some_and(|count| count > 0)
        })
    );
    std::fs::remove_dir_all(root).expect("cleanup dead relay exact direct evidence");
}

#[test]
fn manual_node_rejects_partial_controlled_relay_before_state_or_mission_access() {
    let _process_test = serialize_process_test();
    let state = fresh_root("partial-controlled-relay");
    let missing_mission = state.with_extension("missing-bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args([
            "node",
            "--state",
            state.to_str().expect("UTF-8 state"),
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
            missing_mission.to_str().expect("UTF-8 mission path"),
            "--controlled-relay-url",
            "https://relay.example.invalid",
            "--run-for",
            "1",
        ])
        .output()
        .expect("run partial controlled relay node");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 relay config stderr");
    assert!(!output.status.success());
    assert!(stderr.contains("--controlled-relay-trust"));
    assert!(!state.exists(), "invalid relay config created node state");
    assert!(!missing_mission.exists());
}

#[test]
fn manual_node_rejects_malformed_relay_root_before_state_or_mission_access() {
    let _process_test = serialize_process_test();
    let root = fresh_root("malformed-controlled-relay-root");
    let state = root.join("node-state");
    let missing_mission = root.join("missing.bundle");
    let malformed_root = root.join("malformed.der");
    std::fs::create_dir_all(&root).expect("create malformed relay root fixture");
    std::fs::write(&malformed_root, b"not a DER certificate").expect("write malformed relay root");

    let output = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&missing_mission)
        .args([
            "--controlled-relay-url",
            "https://relay.example.invalid",
            "--controlled-relay-trust",
            "der-roots",
            "--controlled-relay-ca-der",
        ])
        .arg(&malformed_root)
        .args(["--run-for", "1"])
        .output()
        .expect("run malformed controlled relay node");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 malformed relay stderr");
    assert!(!output.status.success());
    assert!(
        stderr.contains("invalid%20relay%20CA%20root%20DER%20certificate"),
        "unexpected malformed relay error: {stderr}"
    );
    assert!(!state.exists(), "malformed relay root created node state");
    assert!(!missing_mission.exists());
    std::fs::remove_dir_all(root).expect("cleanup malformed relay root fixture");
}

#[test]
fn manual_node_redacts_duplicate_token_bearing_relay_url_before_state_access() {
    let _process_test = serialize_process_test();
    let root = fresh_root("duplicate-secret-relay-url");
    let state = root.join("node-state");
    let missing_mission = root.join("missing.bundle");
    let secret = "relay-url-secret-must-not-appear";
    let malicious_url = format!("https://user:{secret}@relay.invalid/?token={secret}");
    let output = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&missing_mission)
        .args([
            "--controlled-relay-url",
            "https://relay.example.invalid",
            "--controlled-relay-url",
        ])
        .arg(&malicious_url)
        .args(["--controlled-relay-trust", "webpki", "--run-for", "1"])
        .output()
        .expect("run duplicate token-bearing relay URL node");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 duplicate relay stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 duplicate relay stderr");
    assert!(!output.status.success());
    assert!(stderr.contains("--controlled-relay-url%20may%20be%20specified%20at%20most%20once"));
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
    assert!(!root.exists(), "duplicate relay URL accessed node state");
}

#[test]
fn manual_node_requires_explicit_unprotected_reference_mission_bundle_before_state() {
    let _process_test = serialize_process_test();
    let state = fresh_root("missing-mission");
    let output = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args([
            "node",
            "--state",
            state.to_str().expect("UTF-8 state"),
            "--bind",
            "127.0.0.1:0",
            "--run-for",
            "1",
        ])
        .output()
        .expect("run node without mission provisioning");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        stderr.contains("ERROR error=")
            && stderr.contains("--mission-bundle-unprotected-reference"),
        "unexpected rejection: {stderr}"
    );
    assert!(
        !state.exists(),
        "missing mission provisioning created node state at {}",
        state.display()
    );
}

#[test]
fn live_node_excludes_a_second_authority_process_on_the_exact_store_path() {
    let _process_test = serialize_process_test();
    let root = fresh_root("cross-process-store-lock");
    let state = root.join("state");
    let mission_path = root.join("authority.bundle");
    std::fs::create_dir_all(&root).expect("test root");
    let scope = Scope::new("test/process-lock").expect("scope");
    let topic = Topic::new("lock-event").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xc1; 32]).expect("lock test provisioner");
    let authority_bundle = provisioner
        .issue_control_authority(1, std::slice::from_ref(&access))
        .expect("authority bundle");
    let authority_bytes = authority_bundle
        .to_bytes()
        .expect("encode authority bundle");
    let subject_bundle = provisioner
        .issue_node(2, &[access])
        .expect("subject bundle");
    let subject = ReferenceEnvelopeSealer::open(subject_bundle)
        .expect("subject service")
        .identity();
    std::fs::write(&mission_path, authority_bytes).expect("write authority bundle");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&mission_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure authority bundle permissions");
    }

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "2", "--sync-ms", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let ready_deadline = Instant::now() + PROCESS_READY_TIMEOUT;
    let mut ready = false;
    while Instant::now() < ready_deadline {
        if let Ok(line) = line_receiver.recv_timeout(Duration::from_millis(100))
            && line.starts_with("READY selected=true ")
        {
            ready = true;
            break;
        }
        if let Some(status) = node.try_wait().expect("poll live node") {
            panic!("node exited before READY with {status}");
        }
    }
    assert!(ready, "live node did not emit READY before deadline");

    let competing = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["control-revoke", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .arg("--subject")
        .arg(aster_node::format_node_id(subject))
        .args(["--generation", "1"])
        .output()
        .expect("run competing authority process");
    assert!(
        !competing.status.success(),
        "second writer unexpectedly opened the live exact store: {}",
        String::from_utf8_lossy(&competing.stdout)
    );
    let competing_error = String::from_utf8(competing.stderr).expect("UTF-8 competing stderr");
    assert!(
        competing_error.contains(
            "control%20administration%20open%20unprotected%20reference:%20selected%20state%20unavailable"
        ),
        "unexpected second-writer rejection: {competing_error}"
    );

    let status = node.wait().expect("wait live node");
    let node_lines = reader.join().expect("join node stdout reader");
    assert!(status.success(), "live node failed: {node_lines:?}");

    // The identical authority operation succeeds once the node releases the
    // OS-backed exact-path writer lock, proving the overlap rejection was the
    // selected state-ownership boundary rather than malformed input.
    let stopped = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["control-revoke", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .arg("--subject")
        .arg(aster_node::format_node_id(subject))
        .args(["--generation", "1"])
        .output()
        .expect("run stopped-state authority process");
    assert!(
        stopped.status.success(),
        "stopped-state authority failed: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        String::from_utf8(stopped.stdout)
            .expect("UTF-8 stopped stdout")
            .contains("publication_disposition=committed-this-call")
    );
    std::fs::remove_dir_all(root).expect("cleanup process-lock root");
}

#[cfg(unix)]
#[test]
fn live_zeroization_drains_node_blocks_restored_credentials_and_preserves_rows() {
    use std::{
        io::Read as _,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    let _process_test = serialize_process_test();
    let root = fresh_root("live-zeroization");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let payload_path = root.join("payload.bin");
    std::fs::create_dir_all(&root).expect("root");
    let mission_bytes = persist_zeroization_bundle(&mission_path, 0xd1);
    std::fs::write(&payload_path, b"preserved-through-zeroization").expect("payload");
    let put = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["put", "--state"])
        .arg(&state)
        .args([
            "--id",
            "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
            "--file",
        ])
        .arg(&payload_path)
        .output()
        .expect("put preserved row");
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30", "--sync-ms", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live zeroization node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut node, &line_receiver);
    let identity_path = state.join("identity.key");
    let identity_bytes = std::fs::read(&identity_path).expect("live identity bytes");

    let zeroize = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .args(["--wait-seconds", "20"])
        .output()
        .expect("request live zeroization");
    let zeroize_stdout = String::from_utf8(zeroize.stdout).expect("zeroize stdout");
    let zeroize_stderr = String::from_utf8(zeroize.stderr).expect("zeroize stderr");
    assert!(
        zeroize.status.success(),
        "live zeroization failed: stdout={zeroize_stdout} stderr={zeroize_stderr}"
    );
    assert!(zeroize_stdout.contains("ZEROIZE status=pass mode=live state=complete"));
    assert!(zeroize_stdout.contains("data_rows_preserved=true opaque_items=1"));
    assert!(zeroize_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));
    assert!(
        zeroize_stdout.contains("assurance=bounded-software physical_sanitization=not-claimed")
    );

    let node_status = node.wait().expect("wait zeroized node");
    let node_lines = reader.join().expect("join node reader");
    let mut node_stderr = String::new();
    node.stderr
        .take()
        .expect("node stderr")
        .read_to_string(&mut node_stderr)
        .expect("read node stderr");
    assert!(
        node_status.success(),
        "zeroized node failed: {node_lines:?} {node_stderr}"
    );
    assert!(node_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=zeroized ")
            && line.contains("assurance=bounded-software")
            && line.contains("physical_sanitization=not-claimed")
    }));
    let mission_tombstone = std::fs::symlink_metadata(&mission_path).expect("mission tombstone");
    let identity_tombstone = std::fs::symlink_metadata(&identity_path).expect("identity tombstone");
    assert_eq!(mission_tombstone.len(), 0);
    assert_eq!(identity_tombstone.len(), 0);

    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect terminal store");
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("inspect stdout");
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    assert!(inspect_stdout.contains("zeroization=complete opaque_items=1"));

    // Rewriting the retained tombstones preserves their inode identities.
    // Terminal state still blocks every normal reopen, and idempotent cleanup
    // deliberately neither overwrites nor deletes the externally restored data.
    std::fs::write(&mission_path, &mission_bytes).expect("restore mission tombstone");
    std::fs::set_permissions(&mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("mission replacement mode");
    std::fs::write(&identity_path, &identity_bytes).expect("restore identity tombstone");
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))
        .expect("identity replacement mode");
    assert_eq!(
        std::fs::symlink_metadata(&mission_path)
            .expect("restored mission metadata")
            .ino(),
        mission_tombstone.ino()
    );
    assert_eq!(
        std::fs::symlink_metadata(&identity_path)
            .expect("restored identity metadata")
            .ino(),
        identity_tombstone.ino()
    );
    let restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("attempt terminal restart");
    assert!(!restart.status.success(), "terminal node restarted");
    let restart_error = String::from_utf8(restart.stderr).expect("restart stderr");
    assert!(restart_error.contains("terminally") || restart_error.contains("locked out"));

    let replay = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .output()
        .expect("replay zeroization");
    let replay_stdout = String::from_utf8(replay.stdout).expect("replay stdout");
    assert!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(replay_stdout.contains("mode=stopped state=complete"));
    assert!(replay_stdout.contains(
        "mission_pathname=retained-external-change carrier_identity_pathname=retained-external-change"
    ));
    assert_eq!(
        std::fs::read(&mission_path).expect("mission retained"),
        mission_bytes
    );
    assert_eq!(
        std::fs::read(&identity_path).expect("identity retained"),
        identity_bytes
    );

    let combined = format!(
        "{zeroize_stdout}{zeroize_stderr}{}{node_stderr}{restart_error}{replay_stdout}",
        node_lines.join("\n")
    );
    assert!(!combined.contains(&bytes_hex(&mission_bytes)));
    assert!(!combined.contains(&bytes_hex(&identity_bytes)));
    std::fs::remove_dir_all(root).expect("cleanup live zeroization root");
}

#[cfg(unix)]
#[test]
fn live_zeroization_stops_a_configured_protected_edge_and_blocks_recontact() {
    use std::{io::Read as _, net::UdpSocket, os::unix::fs::PermissionsExt as _};

    let _process_test = serialize_process_test();
    let root = fresh_root("configured-contact-zeroization");
    let first_state = root.join("first-state");
    let second_state = root.join("second-state");
    let first_mission_path = root.join("first.bundle");
    let second_mission_path = root.join("second.bundle");
    std::fs::create_dir_all(&first_state).expect("first state");
    std::fs::create_dir_all(&second_state).expect("second state");

    let scope = Scope::new("test/configured-contact-zeroization").expect("scope");
    let topic = Topic::new("configured-contact-zeroization").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner = ReferenceProvisioner::from_seed([0xd5; 32]).expect("shared provisioner");
    let first_mission_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .expect("first mission")
        .to_bytes()
        .expect("encode first mission");
    let second_mission_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&access))
        .expect("second mission")
        .to_bytes()
        .expect("encode second mission");
    let first_mission = UnprotectedReferenceMission::from_bytes(first_mission_bytes.clone())
        .expect("parse first mission");
    let first_mission_id = first_mission.identity();
    drop(first_mission);
    let second_mission = UnprotectedReferenceMission::from_bytes(second_mission_bytes.clone())
        .expect("parse second mission");
    let second_mission_id = second_mission.identity();
    drop(second_mission);
    std::fs::write(&first_mission_path, &first_mission_bytes).expect("write first mission");
    std::fs::write(&second_mission_path, &second_mission_bytes).expect("write second mission");
    std::fs::set_permissions(&first_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("first mission permissions");
    std::fs::set_permissions(&second_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("second mission permissions");

    let first_identity = NodeIdentity::load_or_create(&first_state).expect("first identity");
    let first_carrier = first_identity.id();
    let first_identity_path = first_identity.path().to_path_buf();
    let first_identity_bytes = std::fs::read(&first_identity_path).expect("first identity bytes");
    drop(first_identity);
    let second_identity = NodeIdentity::load_or_create(&second_state).expect("second identity");
    let second_carrier = second_identity.id();
    let second_identity_path = second_identity.path().to_path_buf();
    let second_identity_bytes =
        std::fs::read(&second_identity_path).expect("second identity bytes");
    drop(second_identity);

    let first_port = UdpSocket::bind("127.0.0.1:0").expect("reserve first UDP port");
    let second_port = UdpSocket::bind("127.0.0.1:0").expect("reserve second UDP port");
    let first_address = first_port.local_addr().expect("first address");
    let second_address = second_port.local_addr().expect("second address");

    // The selected runtime initiates only from the lower carrier ID. Make that
    // process the survivor so it can observe target endpoint closure itself.
    let (
        target_state,
        target_mission_path,
        target_mission_bytes,
        target_mission_id,
        target_carrier,
        target_identity_path,
        target_identity_bytes,
        target_address,
        target_port,
        survivor_state,
        survivor_mission_path,
        survivor_mission_id,
        survivor_carrier,
        survivor_address,
        survivor_port,
    ) = if first_carrier > second_carrier {
        (
            first_state,
            first_mission_path,
            first_mission_bytes,
            first_mission_id,
            first_carrier,
            first_identity_path,
            first_identity_bytes,
            first_address,
            first_port,
            second_state,
            second_mission_path,
            second_mission_id,
            second_carrier,
            second_address,
            second_port,
        )
    } else {
        (
            second_state,
            second_mission_path,
            second_mission_bytes,
            second_mission_id,
            second_carrier,
            second_identity_path,
            second_identity_bytes,
            second_address,
            second_port,
            first_state,
            first_mission_path,
            first_mission_id,
            first_carrier,
            first_address,
            first_port,
        )
    };
    assert!(survivor_carrier < target_carrier);
    let target_peer = format!(
        "{survivor_carrier}@{survivor_address}={}",
        aster_node::format_node_id(survivor_mission_id)
    );
    let survivor_peer = format!(
        "{target_carrier}@{target_address}={}",
        aster_node::format_node_id(target_mission_id)
    );

    drop(target_port);
    let mut target = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&target_state)
        .arg("--bind")
        .arg(target_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .arg("--peer")
        .arg(&target_peer)
        .args(["--sync-ms", "500", "--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn target node");
    let target_stdout = target.stdout.take().expect("target stdout");
    let (target_line_sender, target_line_receiver) = mpsc::channel();
    let target_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(target_stdout).lines() {
            let line = line.expect("UTF-8 target stdout");
            let _ = target_line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let mut target_stderr = target.stderr.take().expect("target stderr");
    let target_error_reader = thread::spawn(move || {
        let mut error = String::new();
        target_stderr
            .read_to_string(&mut error)
            .expect("read target stderr");
        error
    });
    wait_for_ready(&mut target, &target_line_receiver);

    drop(survivor_port);
    let mut survivor = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&survivor_state)
        .arg("--bind")
        .arg(survivor_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&survivor_mission_path)
        .arg("--peer")
        .arg(&survivor_peer)
        .args(["--sync-ms", "500", "--run-for", "15"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn survivor node");
    let survivor_stdout = survivor.stdout.take().expect("survivor stdout");
    let (survivor_line_sender, survivor_line_receiver) = mpsc::channel();
    let survivor_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(survivor_stdout).lines() {
            let line = line.expect("UTF-8 survivor stdout");
            let _ = survivor_line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let survivor_stderr = survivor.stderr.take().expect("survivor stderr");
    let (survivor_error_sender, survivor_error_receiver) = mpsc::channel();
    let survivor_error_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(survivor_stderr).lines() {
            let line = line.expect("UTF-8 survivor stderr");
            let _ = survivor_error_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut survivor, &survivor_line_receiver);
    let survivor_contact_prefix = format!(
        "CONTACT direction=out carrier_peer={target_carrier} mission_peer={} ",
        aster_node::format_node_id(target_mission_id)
    );
    let target_contact_prefix = format!(
        "CONTACT direction=in carrier_peer={survivor_carrier} mission_peer={} ",
        aster_node::format_node_id(survivor_mission_id)
    );
    let _ = wait_for_protected_contact(
        &mut survivor,
        &survivor_line_receiver,
        &survivor_contact_prefix,
    );
    let _ = wait_for_protected_contact(&mut target, &target_line_receiver, &target_contact_prefix);

    let zeroize = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&target_state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .args(["--wait-seconds", "20"])
        .output()
        .expect("zeroize configured target");
    let zeroize_stdout = String::from_utf8(zeroize.stdout).expect("zeroize stdout");
    let zeroize_stderr = String::from_utf8(zeroize.stderr).expect("zeroize stderr");
    assert!(
        zeroize.status.success(),
        "configured live zeroization failed: stdout={zeroize_stdout} stderr={zeroize_stderr}"
    );
    assert!(zeroize_stdout.contains("ZEROIZE status=pass mode=live state=complete"));
    assert!(zeroize_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));

    let target_deadline = Instant::now() + Duration::from_secs(10);
    let target_status = loop {
        if let Some(status) = target.try_wait().expect("poll zeroized target") {
            break status;
        }
        if Instant::now() >= target_deadline {
            target.kill().expect("kill stuck zeroized target");
            let _ = target.wait();
            panic!("configured target did not exit after live zeroization");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let target_lines = target_reader.join().expect("join target reader");
    let target_errors = target_error_reader.join().expect("join target errors");
    assert!(
        target_status.success(),
        "zeroized target failed: {target_lines:?} {target_errors}"
    );
    assert!(target_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=zeroized sync_status=terminal-lockout ")
            && receipt_counter(line, "contacts").is_some_and(|contacts| contacts > 0)
    }));
    assert_eq!(
        std::fs::symlink_metadata(&target_mission_path)
            .expect("target mission tombstone")
            .len(),
        0
    );
    assert_eq!(
        std::fs::symlink_metadata(&target_identity_path)
            .expect("target identity tombstone")
            .len(),
        0
    );
    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&target_state)
        .output()
        .expect("inspect terminal target");
    assert!(inspect.status.success());
    assert!(
        String::from_utf8(inspect.stdout)
            .expect("inspect stdout")
            .contains("zeroization=complete")
    );

    // A quiet reader-channel interval establishes that pre-STOP pipe backlog
    // was consumed before classifying any later contact receipt or error.
    let expected_closure_prefix = format!(
        "CONTACT direction=out carrier_peer={target_carrier} expected_mission_peer={} status=error error=",
        aster_node::format_node_id(target_mission_id)
    );
    let baseline_deadline = Instant::now() + Duration::from_secs(3);
    let mut quiet_since = Instant::now();
    loop {
        let mut activity = false;
        while survivor_line_receiver.try_recv().is_ok() {
            activity = true;
        }
        while survivor_error_receiver.try_recv().is_ok() {
            activity = true;
        }
        if activity {
            quiet_since = Instant::now();
        } else if quiet_since.elapsed() >= Duration::from_millis(250) {
            break;
        }
        assert!(
            Instant::now() < baseline_deadline,
            "survivor output never reached a quiet post-STOP baseline"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let mut closure_observed = false;
    let closure_deadline = Instant::now() + Duration::from_secs(12);
    let mut protected_after_stop = Vec::new();
    while !closure_observed && Instant::now() < closure_deadline {
        while let Ok(line) = survivor_line_receiver.try_recv() {
            if line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass") {
                protected_after_stop.push(line);
            }
        }
        if let Ok(line) = survivor_error_receiver.recv_timeout(Duration::from_millis(50)) {
            closure_observed |= line.starts_with(&expected_closure_prefix);
        }
    }
    assert!(
        closure_observed,
        "survivor did not observe target endpoint closure"
    );
    std::fs::write(&target_mission_path, &target_mission_bytes)
        .expect("restore target mission tombstone");
    std::fs::set_permissions(&target_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("restored mission permissions");
    std::fs::write(&target_identity_path, &target_identity_bytes)
        .expect("restore target identity tombstone");
    std::fs::set_permissions(
        &target_identity_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("restored identity permissions");
    let restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&target_state)
        .arg("--bind")
        .arg(target_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .arg("--peer")
        .arg(&target_peer)
        .args(["--sync-ms", "500", "--run-for", "1"])
        .output()
        .expect("attempt restored target recontact");
    let restart_stdout = String::from_utf8(restart.stdout).expect("restart stdout");
    let restart_stderr = String::from_utf8(restart.stderr).expect("restart stderr");
    assert!(!restart.status.success(), "terminal target restarted");
    assert!(!restart_stdout.contains("READY selected=true"));
    assert!(!restart_stdout.contains("CONTACT "));
    assert!(restart_stderr.contains("terminally") || restart_stderr.contains("locked out"));
    assert_eq!(
        std::fs::read(&target_mission_path).expect("restored mission retained"),
        target_mission_bytes
    );
    assert_eq!(
        std::fs::read(&target_identity_path).expect("restored identity retained"),
        target_identity_bytes
    );

    let survivor_status = survivor.wait().expect("graceful survivor exit");
    let survivor_lines = survivor_reader.join().expect("join survivor reader");
    let survivor_errors = survivor_error_reader.join().expect("join survivor errors");
    while let Ok(line) = survivor_line_receiver.try_recv() {
        if line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass") {
            protected_after_stop.push(line);
        }
    }
    assert!(
        protected_after_stop.is_empty(),
        "protected contact completed after the quiet post-STOP baseline: {protected_after_stop:?}"
    );
    assert!(
        survivor_status.success(),
        "survivor did not exit through its finite runtime: {survivor_errors:?}"
    );
    assert!(
        survivor_lines
            .iter()
            .any(|line| line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass"))
    );
    assert!(survivor_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=complete sync_status=contacts_observed ")
            && receipt_counter(line, "contact_errors").is_some_and(|errors| errors > 0)
    }));
    assert!(
        survivor_errors
            .iter()
            .any(|line| line.starts_with(&expected_closure_prefix))
    );
    let combined = format!(
        "{zeroize_stdout}{zeroize_stderr}{target_errors}{restart_stdout}{restart_stderr}{}{}",
        target_lines.join("\n"),
        survivor_lines.join("\n")
    );
    assert!(!combined.contains(&bytes_hex(&target_mission_bytes)));
    assert!(!combined.contains(&bytes_hex(&target_identity_bytes)));
    std::fs::remove_dir_all(root).expect("cleanup configured contact root");
}

#[cfg(unix)]
#[test]
fn live_socket_replacement_after_accept_begins_fails_node_once() {
    use std::{
        io::Read as _,
        os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    };

    let _process_test = serialize_process_test();
    let root = fresh_root("live-socket-replacement");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    std::fs::create_dir_all(&root).expect("root");
    persist_zeroization_bundle(&mission_path, 0xd4);

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn socket-integrity node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut node, &line_receiver);

    let store = std::fs::symlink_metadata(state.join("mesh.redb")).expect("store metadata");
    let control_directory = std::fs::canonicalize("/tmp")
        .expect("canonical tmp")
        .join(format!(
            "aster-zeroize-{}",
            rustix::process::geteuid().as_raw()
        ));
    let socket_path = control_directory.join(format!(
        "mesh-{:016x}-{:016x}.sock",
        store.dev(),
        store.ino()
    ));
    let socket = std::fs::symlink_metadata(&socket_path).expect("live socket metadata");
    assert!(socket.file_type().is_socket());
    let displaced_socket = socket_path.with_extension("sock.displaced");
    std::fs::rename(&socket_path, &displaced_socket).expect("replace pathname after accept began");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = node.try_wait().expect("poll integrity-failed node") {
            break status;
        }
        if Instant::now() >= deadline {
            node.kill()
                .expect("kill nonterminating integrity-failed node");
            let _ = node.wait();
            panic!("node stayed live after its exact zeroization socket was replaced");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let node_lines = reader.join().expect("join node reader");
    let mut stderr = String::new();
    node.stderr
        .take()
        .expect("node stderr")
        .read_to_string(&mut stderr)
        .expect("read node stderr");
    assert!(
        !status.success(),
        "socket-integrity failure exited successfully"
    );
    assert_eq!(
        stderr
            .matches("ZEROIZE lifecycle=live control=failed")
            .count(),
        1,
        "integrity failure was not reported exactly once: {stderr}"
    );
    assert!(
        !node_lines
            .iter()
            .any(|line| line.starts_with("STOP lifecycle=complete"))
    );
    std::fs::remove_file(displaced_socket).expect("remove displaced socket");
    std::fs::remove_dir_all(root).expect("cleanup socket-integrity root");
}

#[cfg(unix)]
#[test]
fn sigkill_dirty_live_cli_node_restart_recovers_before_identity_and_socket() {
    use std::io::Read as _;

    let _process_test = serialize_process_test();
    let root = fresh_root("sigkill-dirty-live-restart");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    std::fs::create_dir_all(&root).expect("root");
    persist_zeroization_bundle(&mission_path, 0xd3);

    let mut first = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn first node");
    let stdout = first.stdout.take().expect("first stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 first-node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut first, &line_receiver);
    first.kill().expect("SIGKILL first node");
    let killed = first.wait().expect("wait for killed node");
    assert!(!killed.success());
    let first_lines = reader.join().expect("join first reader");
    assert!(
        first_lines
            .iter()
            .any(|line| line.starts_with("READY selected=true"))
    );
    let mut first_stderr = String::new();
    first
        .stderr
        .take()
        .expect("first stderr")
        .read_to_string(&mut first_stderr)
        .expect("read first stderr");

    let dirty_inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect dirty live state");
    assert!(
        !dirty_inspect.status.success(),
        "SIGKILL did not leave dirty redb state"
    );
    assert!(
        String::from_utf8_lossy(&dirty_inspect.stderr).contains("Database%20repair%20aborted"),
        "unexpected dirty inspection error: {}",
        String::from_utf8_lossy(&dirty_inspect.stderr)
    );

    let restarted = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("restart dirty live node");
    let restarted_stdout = String::from_utf8(restarted.stdout).expect("restart stdout");
    let restarted_stderr = String::from_utf8(restarted.stderr).expect("restart stderr");
    assert!(
        restarted.status.success(),
        "dirty live restart failed: stdout={restarted_stdout} stderr={restarted_stderr} first_stderr={first_stderr}"
    );
    assert!(restarted_stdout.contains("READY selected=true"));
    assert!(restarted_stdout.contains("STOP lifecycle=complete"));
    assert!(!restarted_stderr.contains("repair%20aborted"));
    std::fs::remove_dir_all(root).expect("cleanup dirty live root");
}

#[cfg(unix)]
#[test]
fn zeroization_marker_child_process() {
    let Some(state) = std::env::var_os("ASTER_INTEGRATION_ZEROIZATION_CHILD_STATE") else {
        return;
    };
    let mission_path = std::env::var_os("ASTER_INTEGRATION_ZEROIZATION_CHILD_MISSION")
        .expect("child mission path");
    let state = PathBuf::from(state);
    let mission_path = PathBuf::from(mission_path);
    let mission = UnprotectedReferenceMission::load(&mission_path).expect("load mission");
    let identity = NodeIdentity::load_existing(&state).expect("load identity");
    let prepared_mission = mission
        .prepare_software_erasure()
        .expect("preflight mission");
    let prepared_identity = identity
        .prepare_software_erasure()
        .expect("preflight identity");
    let intent = ZeroizationIntent::new(
        prepared_mission.target().to_bytes(),
        prepared_identity.target().to_bytes(),
    )
    .expect("zeroization intent");
    let mut store = Store::open_for_mission(
        state.join("mesh.redb"),
        prepared_mission.mission_authority_id(),
    )
    .expect("bind store to retained mission");
    store
        .require_process_exclusive_lock()
        .expect("exclusive store writer");
    store.begin_zeroization(&intent).expect("durable marker");
    // This harness is linked only into the integration-test executable. Exit
    // without dropping the redb/artifact handles to model an abrupt process
    // loss immediately after the Immediate-durability marker commit.
    std::process::exit(86);
}

#[cfg(unix)]
#[test]
fn interrupted_terminal_marker_resumes_without_losing_data_rows() {
    let _process_test = serialize_process_test();
    let root = fresh_root("interrupted-zeroization");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let payload_path = root.join("payload.bin");
    std::fs::create_dir_all(&root).expect("root");
    let mission_bytes = persist_zeroization_bundle(&mission_path, 0xd2);
    std::fs::write(&payload_path, b"survives-interrupted-cleanup").expect("payload");
    let init = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["init", "--state"])
        .arg(&state)
        .output()
        .expect("initialize identity");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let identity_path = state.join("identity.key");
    let identity_bytes = std::fs::read(&identity_path).expect("identity bytes");
    let put = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["put", "--state"])
        .arg(&state)
        .args([
            "--id",
            "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
            "--file",
        ])
        .arg(&payload_path)
        .output()
        .expect("put row");
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let interrupted = Command::new(std::env::current_exe().expect("integration test executable"))
        .args(["--exact", "zeroization_marker_child_process", "--nocapture"])
        .env("ASTER_INTEGRATION_ZEROIZATION_CHILD_STATE", &state)
        .env("ASTER_INTEGRATION_ZEROIZATION_CHILD_MISSION", &mission_path)
        .output()
        .expect("interrupt child after marker");
    assert_eq!(interrupted.status.code(), Some(86));
    assert!(mission_path.exists());
    assert!(identity_path.exists());

    // Model credentials restored while the retained database is dirty and
    // terminal. Actual CLI startup must recover lifecycle truth and reject
    // before creating an endpoint or accepting the restored bundle.
    std::fs::write(&mission_path, &mission_bytes).expect("restore mission bytes");
    std::fs::write(&identity_path, &identity_bytes).expect("restore identity bytes");
    let terminal_restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("reject dirty terminal restart");
    let terminal_stdout = String::from_utf8(terminal_restart.stdout).expect("terminal stdout");
    let terminal_stderr = String::from_utf8(terminal_restart.stderr).expect("terminal stderr");
    assert!(
        !terminal_restart.status.success(),
        "dirty terminal node restarted"
    );
    assert!(!terminal_stdout.contains("READY selected=true"));
    assert!(terminal_stderr.contains("terminally%20locked%20out"));
    assert!(!terminal_stderr.contains("repair%20aborted"));
    assert_eq!(
        std::fs::read(&mission_path).expect("mission retained"),
        mission_bytes
    );
    assert_eq!(
        std::fs::read(&identity_path).expect("identity retained"),
        identity_bytes
    );

    let resumed = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .output()
        .expect("resume cleanup");
    let resumed_stdout = String::from_utf8(resumed.stdout).expect("resumed stdout");
    assert!(
        resumed.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(resumed_stdout.contains("state=complete"));
    assert!(resumed_stdout.contains("data_rows_preserved=true opaque_items=1"));
    assert!(resumed_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));
    assert_eq!(
        std::fs::metadata(&mission_path)
            .expect("mission tombstone")
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(&identity_path)
            .expect("identity tombstone")
            .len(),
        0
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect resumed terminal state");
    assert!(
        inspect.status.success(),
        "terminal inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    assert!(
        String::from_utf8(inspect.stdout)
            .expect("inspect stdout")
            .contains("zeroization=complete opaque_items=1")
    );
    std::fs::remove_dir_all(root).expect("cleanup interrupted zeroization root");
}

#[test]
fn four_real_processes_default_to_ping_pong_and_restart_cleanly() {
    let _process_test = serialize_process_test();
    let root = fresh_root("four-process-default-ping-pong-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "4", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mesh demo");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if child.try_wait().expect("poll mesh demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out mesh demo");
            let output = child.wait_with_output().expect("collect timed-out demo");
            panic!(
                "mesh demo exceeded 180 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().expect("collect mesh demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains("PING status=received"));
    assert!(stdout.contains("emitted_by=origin-process"));
    assert!(stdout.contains("producer_process_absent=true"));
    assert!(stdout.contains("PONG status=received"));
    assert!(stdout.contains("emitted_by=destination-process"));
    assert!(stdout.contains(
        "RELAY status=pass intermediates=2 exact_forward=true content_access=denied semantic_acceptance=none"
    ));
    assert!(stdout.contains(
        "SUBSCRIPTIONS status=seeded consume=2 carry=2 selectors=4 interest_exchange=mission-protected lanes=receiver-directed"
    ));
    assert!(stdout.contains(
        "PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    for phase in [
        "ping-forward-0-to-1",
        "ping-forward-1-to-2",
        "ping-forward-2-to-3",
        "pong-return-3-to-2",
        "pong-return-2-to-1",
        "pong-return-1-to-0",
    ] {
        assert!(stdout.contains(&format!("PHASE status=pass name={phase} processes=2")));
    }
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=noop processes=4"));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18 contacts=real-iroh"
    ));
    #[cfg(unix)]
    assert_eq!(
        stdout.matches("completion=condition-observed").count(),
        9,
        "every demo phase must complete from its receipts before its watchdog"
    );
    assert!(stdout.contains(
        "reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none"
    ));
    let process_logs = std::fs::read_dir(root.join("logs"))
        .expect("read process logs")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect::<Vec<_>>();
    assert_eq!(process_logs.len(), 18, "one stdout log per child process");
    let mut emitted_ping = 0usize;
    let mut emitted_pong = 0usize;
    for path in &process_logs {
        let log = std::fs::read_to_string(path).expect("read process log");
        emitted_ping += log.matches("APPLICATION status=emitted kind=ping ").count();
        emitted_pong += log.matches("APPLICATION status=emitted kind=pong ").count();
        assert!(
            log.contains("mission_auth=hybrid-pq provisioning=unprotected-reference"),
            "child omitted the mission/provisioning receipt: {}\n{log}",
            path.display()
        );
        let isolated_application = if path.ends_with("ping-publish-node-0.log") {
            Some("ping-emitter")
        } else if path.ends_with("pong-publish-node-3.log") {
            Some("pong-responder")
        } else {
            None
        };
        if let Some(application) = isolated_application {
            assert!(log.lines().any(|line| {
                line.starts_with("READY ")
                    && line.contains(" peers=0 ")
                    && line.contains(&format!(" application={application} "))
            }));
            assert!(log.lines().any(|line| {
                line.starts_with("STOP ")
                    && line.contains(" sync_status=no_successful_contact ")
                    && line.contains(" contacts=0 ")
            }));
            assert!(!log.lines().any(|line| line.starts_with("CONTACT ")));
            continue;
        }
        assert!(
            log.contains("STOP lifecycle=complete sync_status=contacts_observed"),
            "child did not report a successful mission contact: {}\n{log}",
            path.display()
        );
        let protected_contact = log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.ends_with("status=pass")
                && line.contains(" mission_auth=hybrid-pq ")
                && receipt_counter(line, "handshake_frames") == Some(4)
                && receipt_counter(line, "handshake_bytes").is_some_and(|bytes| bytes > 0)
                && receipt_counter(line, "protected_frames").is_some_and(|frames| frames > 0)
                && receipt_counter(line, "protected_bytes").is_some_and(|bytes| bytes > 0)
        });
        assert!(
            protected_contact,
            "child omitted a completed authenticated/protected contact receipt: {}\n{log}",
            path.display()
        );
    }
    assert_eq!(
        emitted_ping, 1,
        "Ping must be emitted by one live process once"
    );
    assert_eq!(
        emitted_pong, 1,
        "Pong must be emitted by one live process once"
    );

    let ping_publish = std::fs::read_to_string(root.join("logs/ping-publish-node-0.log"))
        .expect("isolated Ping publisher log");
    assert!(ping_publish.contains("APPLICATION status=emitted kind=ping "));
    let pong_publish = std::fs::read_to_string(root.join("logs/pong-publish-node-3.log"))
        .expect("isolated Pong publisher log");
    assert!(pong_publish.contains("APPLICATION status=emitted kind=pong "));

    for left in 0..3 {
        let right = left + 1;
        assert_exact_event_edge(
            &root,
            &format!("ping-forward-{left}-to-{right}"),
            left,
            right,
        );
    }
    for left in (0..3).rev() {
        let right = left + 1;
        assert_exact_event_edge(
            &root,
            &format!("pong-return-{right}-to-{left}"),
            right,
            left,
        );
    }

    let noop_ping =
        std::fs::read_to_string(root.join("logs/noop-node-0.log")).expect("read no-op Ping log");
    let noop_pong =
        std::fs::read_to_string(root.join("logs/noop-node-3.log")).expect("read no-op Pong log");
    assert!(noop_ping.contains("APPLICATION status=existing kind=ping "));
    assert!(noop_pong.contains("APPLICATION status=existing kind=pong "));
    for node in 0..4 {
        assert_default_noop_node(&root, node, node == 0 || node == 3);
    }
    std::fs::remove_dir_all(&root).expect("remove successful demo root");
}

#[test]
fn two_real_processes_use_the_same_stopped_state_ping_pong_plan() {
    let _process_test = serialize_process_test();
    let root = fresh_root("two-process-default-ping-pong-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "2", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn two-node mesh demo");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if child.try_wait().expect("poll two-node mesh demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out two-node mesh demo");
            let output = child
                .wait_with_output()
                .expect("collect timed-out two-node demo");
            panic!(
                "two-node mesh demo exceeded 180 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child
        .wait_with_output()
        .expect("collect two-node mesh demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "two-node mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains(
        "PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=ping-forward-0-to-1 processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=pong-return-1-to-0 processes=2"));
    assert!(stdout.contains("PHASE status=pass name=noop processes=2"));
    assert!(stdout.contains("PING status=received emitted_by=origin-process"));
    assert!(stdout.contains("producer_process_absent=true"));
    assert!(stdout.contains("PONG status=received emitted_by=destination-process"));
    assert!(stdout.contains("RELAY status=not-applicable intermediates=0"));
    assert!(stdout.contains(
        "SUBSCRIPTIONS status=seeded consume=2 carry=0 selectors=2 interest_exchange=mission-protected lanes=receiver-directed"
    ));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=ping-pong nodes=2 processes=8 contacts=real-iroh"
    ));
    #[cfg(unix)]
    assert_eq!(
        stdout.matches("completion=condition-observed").count(),
        5,
        "every two-node phase must complete from its receipts before its watchdog"
    );
    assert!(stdout.contains("payload_blind_relays=not-applicable ttl=durable-none"));

    let process_logs = std::fs::read_dir(root.join("logs"))
        .expect("read two-node process logs")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect::<Vec<_>>();
    assert_eq!(process_logs.len(), 8, "one stdout log per child process");
    let emitted_ping = process_logs
        .iter()
        .map(|path| std::fs::read_to_string(path).expect("read two-node process log"))
        .map(|log| log.matches("APPLICATION status=emitted kind=ping ").count())
        .sum::<usize>();
    let emitted_pong = process_logs
        .iter()
        .map(|path| std::fs::read_to_string(path).expect("read two-node process log"))
        .map(|log| log.matches("APPLICATION status=emitted kind=pong ").count())
        .sum::<usize>();
    assert_eq!(emitted_ping, 1);
    assert_eq!(emitted_pong, 1);
    assert_peerless_application(&root, "ping-publish", 0, "ping-emitter", "ping");
    assert_peerless_application(&root, "pong-publish", 1, "pong-responder", "pong");
    assert_exact_event_edge(&root, "ping-forward-0-to-1", 0, 1);
    assert_exact_event_edge(&root, "pong-return-1-to-0", 1, 0);

    let noop_ping =
        std::fs::read_to_string(root.join("logs/noop-node-0.log")).expect("two-node no-op Ping");
    let noop_pong =
        std::fs::read_to_string(root.join("logs/noop-node-1.log")).expect("two-node no-op Pong");
    assert!(noop_ping.contains("APPLICATION status=existing kind=ping "));
    assert!(noop_pong.contains("APPLICATION status=existing kind=pong "));
    assert_default_noop_node(&root, 0, true);
    assert_default_noop_node(&root, 1, true);
    std::fs::remove_dir_all(&root).expect("remove successful two-node demo root");
}

#[test]
fn four_real_processes_propagate_controls_without_authority_and_exclude_captured_leaf() {
    let _process_test = serialize_process_test();
    let root = fresh_root("four-process-controlled-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "4", "--scenario", "control", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn controlled mesh demo");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if child.try_wait().expect("poll controlled demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out controlled demo");
            let output = child.wait_with_output().expect("collect timed-out demo");
            panic!(
                "controlled mesh demo exceeded 180 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().expect("collect controlled demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "controlled mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains("PHASE status=pass name=control-authority-seed processes=2"));
    assert!(stdout.contains("PHASE status=pass name=control-authority-absent-forward processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=control-authority-absent-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(
        stdout
            .contains("PHASE status=pass name=control-authority-absent-event-forward processes=2")
    );
    assert!(stdout.contains("PHASE status=pass name=captured-publication-denied processes=2"));
    assert!(stdout.contains("PHASE status=pass name=captured-rejoin-denied processes=2"));
    assert!(stdout.contains("PHASE status=pass name=pong-ping-forward processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=pong-relay-forward processes=2"));
    assert!(stdout.contains("PHASE status=pass name=pong-return processes=2"));
    assert!(stdout.contains("PHASE status=pass name=noop processes=3"));
    assert!(stdout.contains("PING status=received") && stdout.contains("key_epoch=2"));
    assert!(stdout.contains("PONG status=received") && stdout.contains("key_epoch=2"));
    assert!(stdout.contains(
        "CONTROL_RESULT status=pass nodes=4 authority_processes=2 emitted_by=authority-process controls=2 control_priority=flash authority_absent_forwarding=pass route_only_forward=pass survivor_epoch=2 captured_node=3 captured_sync=denied captured_epoch2_read=denied captured_mesh_publication=denied captured_rejoin=denied captured_local_signing=stale-only"
    ));
    assert!(stdout.contains(
        "SUBSCRIPTIONS status=seeded consume=3 carry=1 selectors=4 interest_exchange=mission-protected lanes=receiver-directed"
    ));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=control nodes=4 processes=23 contacts=real-iroh mission_auth=hybrid-pq"
    ));
    #[cfg(unix)]
    assert_eq!(
        stdout.matches("completion=condition-observed").count(),
        11,
        "every controlled phase must complete from its receipts before its watchdog"
    );
    let revoke = std::fs::read_to_string(root.join("logs/authority-revoke.log"))
        .expect("authority revoke log");
    let rekey = std::fs::read_to_string(root.join("logs/authority-rekey.log"))
        .expect("authority rekey log");
    assert!(
        revoke.contains("status=emitted")
            && revoke.contains("publication_disposition=committed-this-call")
    );
    assert!(rekey.contains("status=emitted") && rekey.contains("recipient_filtered=true"));
    assert!(
        !root
            .join("logs/control-authority-absent-forward-node-0.log")
            .exists()
    );
    assert!(
        !root
            .join("logs/control-authority-absent-event-forward-node-0.log")
            .exists()
    );
    assert!(
        !root
            .join("logs/control-authority-absent-publish-node-0.log")
            .exists()
    );
    let isolated_publisher =
        std::fs::read_to_string(root.join("logs/control-authority-absent-publish-node-2.log"))
            .expect("isolated epoch-two publisher log");
    assert!(isolated_publisher.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(" application=epoch2-ping-emitter ")
    }));
    assert!(isolated_publisher.contains("APPLICATION status=emitted kind=ping "));
    assert!(isolated_publisher.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(
        !isolated_publisher
            .lines()
            .any(|line| line.starts_with("CONTACT "))
    );

    let event_forward = [1, 2]
        .into_iter()
        .map(|node| {
            std::fs::read_to_string(root.join(format!(
                "logs/control-authority-absent-event-forward-node-{node}.log"
            )))
            .expect("authority-absent Event-forward log")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(event_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" offered=1 ")
            && line.ends_with("status=pass")
    }));

    let ping_forward = [0, 1]
        .into_iter()
        .map(|node| {
            std::fs::read_to_string(root.join(format!("logs/pong-ping-forward-node-{node}.log")))
                .expect("Ping-to-Pong-member forwarding log")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ping_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" offered=1 ")
            && line.ends_with("status=pass")
    }));
    assert!(ping_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" fetched=1 ")
            && line.contains(" inserted=1 ")
            && line.contains(" remaining=0 ")
            && line.ends_with("status=pass")
    }));

    let isolated_pong = std::fs::read_to_string(root.join("logs/pong-publish-node-0.log"))
        .expect("isolated Pong publisher log");
    assert!(isolated_pong.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(" application=pong-responder ")
    }));
    assert!(isolated_pong.contains("APPLICATION status=emitted kind=pong "));
    assert!(isolated_pong.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(
        !isolated_pong
            .lines()
            .any(|line| line.starts_with("CONTACT "))
    );

    for (phase, source, destination) in [("pong-relay-forward", 0, 1), ("pong-return", 1, 2)] {
        let source_log =
            std::fs::read_to_string(root.join(format!("logs/{phase}-node-{source}.log")))
                .expect("Pong forwarding source log");
        let destination_log =
            std::fs::read_to_string(root.join(format!("logs/{phase}-node-{destination}.log")))
                .expect("Pong forwarding destination log");
        assert!(source_log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.contains(" control_offered=0 ")
                && line.contains(" control_fetched=0 ")
                && line.contains(" offered=1 ")
                && line.ends_with("status=pass")
        }));
        assert!(destination_log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.contains(" control_offered=0 ")
                && line.contains(" control_fetched=0 ")
                && line.contains(" fetched=1 ")
                && line.contains(" inserted=1 ")
                && line.contains(" remaining=0 ")
                && line.ends_with("status=pass")
        }));
    }
    assert!(event_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" fetched=1 ")
            && line.contains(" inserted=1 ")
            && line.contains(" remaining=0 ")
            && line.ends_with("status=pass")
    }));

    for node in 0..3 {
        let noop = std::fs::read_to_string(root.join(format!("logs/noop-node-{node}.log")))
            .expect("equal-inventory no-op log");
        let passing_contacts = noop
            .lines()
            .filter(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
            .collect::<Vec<_>>();
        assert!(!passing_contacts.is_empty());
        assert!(passing_contacts.iter().all(|line| {
            [
                " control_offered=0 ",
                " control_fetched=0 ",
                " control_retained=0 ",
                " control_duplicates=0 ",
                " control_activated=0 ",
                " control_remaining=0 ",
                " offered=0 ",
                " fetched=0 ",
                " inserted=0 ",
                " duplicates=0 ",
                " remaining=0 ",
            ]
            .into_iter()
            .all(|field| line.contains(field))
        }));
        let stop = noop
            .lines()
            .find(|line| line.starts_with("STOP "))
            .expect("equal-inventory no-op STOP receipt");
        assert!(stop.contains(" controls=2 "));
        assert!(stop.contains(" applied_controls=2 "));
        assert!(stop.contains(" pending_controls=0 "));
        assert!(stop.contains(" control_highwater=2 "));
        if node == 1 {
            assert!(stop.contains(" events=0 "));
            assert!(stop.contains(" route_cached_events=2 "));
        } else {
            assert!(stop.contains(" events=2 "));
            assert!(stop.contains(" route_cached_events=0 "));
        }
    }
    for phase in ["captured-publication-denied", "captured-rejoin-denied"] {
        let survivor = std::fs::read_to_string(root.join(format!("logs/{phase}-node-2.log")))
            .expect("survivor denial log");
        let captured = std::fs::read_to_string(root.join(format!("logs/{phase}-node-3.log")))
            .expect("captured denial log");
        assert!(!survivor.contains("status=pass"));
        assert!(!captured.contains("status=pass"));
    }
    std::fs::remove_dir_all(&root).expect("remove successful controlled demo root");
}
