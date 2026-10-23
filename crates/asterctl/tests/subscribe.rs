use buffa::Message;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

const TOKEN: &str = "asterctl-test-token-00000000000000";
const ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn cli(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(args)
        // Keep stdin open: creating a subscription must not wait for input.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("subscribe waited for input or failed to finish");
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn run(port: u16, args: &[&str]) -> Output {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "asterctl-owned-fixture-{}-{}-subscribe.redb",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let journal = path.to_str().unwrap();
    assert!(
        cli(&[
            "publication-init",
            "--journal",
            journal,
            "--client-id",
            "fixture-client"
        ])
        .status
        .success()
    );
    let split = args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len());
    let output = cli(&[
        &["--token", TOKEN, "--port", &port.to_string()][..],
        &args[..split],
        &["--journal", journal, "--client-id", "fixture-client"],
        &args[split..],
    ]
    .concat());
    let _ = std::fs::remove_file(path);
    output
}

fn serve(
    status: &str,
    content_type: &str,
    response: Vec<u8>,
) -> (
    SocketAddr,
    mpsc::Receiver<api::CreateEventSubscriptionRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut connection = loop {
                match listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("no subscription request: {error}"),
                }
            };
            // Accepted sockets inherit nonblocking mode on macOS/BSD.
            connection.set_nonblocking(false).unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            connection
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                connection.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() <= 8192);
            }
            let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
            if header.contains("/begineventpublicationsession ")
                || header.contains("/completeeventpublicationrecovery ")
            {
                let length: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap_or("0")
                    .parse()
                    .unwrap();
                let mut body = vec![0; length];
                connection.read_exact(&mut body).unwrap();
                let response = if header.contains("/begineventpublicationsession ") {
                    let claim =
                        api::BeginEventPublicationSessionRequest::decode_from_slice(&body).unwrap();
                    assert_eq!(claim.client_id, b"fixture-client");
                    assert_eq!(claim.expected_session, 0);
                    assert_eq!(claim.claim_nonce.len(), 32);
                    api::BeginEventPublicationSessionResponse {
                        session: 1,
                        snapshot_revision: 1,
                        ..Default::default()
                    }
                    .encode_to_vec()
                } else {
                    api::CompleteEventPublicationRecoveryResponse::default().encode_to_vec()
                };
                write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                connection.write_all(&response).unwrap();
                continue;
            }
            assert!(header.starts_with(
            "post /aster.application.v1alpha1.asterapplicationservice/createeventsubscription http/1.1\r\n"
        ));
            assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
            assert!(header.contains("content-type: application/proto\r\n"));
            assert!(header.contains("connect-timeout-ms:"));
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(length <= 1024);
            let mut body = vec![0; length];
            connection.read_exact(&mut body).unwrap();
            sender
                .send(api::CreateEventSubscriptionRequest::decode_from_slice(&body).unwrap())
                .unwrap();
            connection.write_all(reply.as_bytes()).unwrap();
            connection.write_all(&response).unwrap();
            break;
        }
    });
    (address, receiver, server)
}

fn subscribe(args: &[&str], inserted: bool) -> (api::CreateEventSubscriptionRequest, Output) {
    let response = api::CreateEventSubscriptionResponse {
        subscription_id: (0..32).collect(),
        inserted,
        ..Default::default()
    };
    let (address, requests, server) =
        serve("200 OK", "application/proto", response.encode_to_vec());
    let output = run(address.port(), args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut expected = String::new();
    if args.contains(&"--operation-key=auto") {
        expected.push_str(&format!(
            "asterctl: operation-key={}\n",
            std::str::from_utf8(&request.operation_key).unwrap()
        ));
    }
    assert_eq!(output.stderr, expected.as_bytes());
    server.join().unwrap();
    (request, output)
}

#[test]
fn subscribe_help_does_not_require_token_topic_or_scope() {
    let output = cli(&["subscribe", "--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--scope SCOPE --operation-key KEY|auto [SUBSCRIBE-OPTIONS] TOPIC"));
    assert!(help.contains("--scope"));
    assert!(help.contains("--operation-key"));
    assert!(!help.contains("--topic"));
}

#[test]
fn subscribe_sends_positional_topic_scope_and_utf8_key_and_prints_only_id() {
    let (request, output) = subscribe(
        &[
            "subscribe",
            "chat.events",
            "--scope",
            "mission/team/alpha",
            "--operation-key",
            "читач-1",
        ],
        true,
    );
    assert_eq!(request.topic, "chat.events");
    assert_eq!(request.scope, "mission/team/alpha");
    assert!(!request.include_descendant_scopes);
    assert_eq!(request.operation_key, "читач-1".as_bytes());
    assert_eq!(output.stdout, format!("{ID}\n").as_bytes());
}

#[test]
fn subscribe_maps_scope_wildcard_and_preserves_false_in_json_receipt() {
    for inserted in [true, false] {
        let (request, output) = subscribe(
            &[
                "--json",
                "subscribe",
                "--scope=mission/team/*",
                "--operation-key=chat-reader",
                "chat.events",
            ],
            inserted,
        );
        assert_eq!(request.topic, "chat.events");
        assert_eq!(request.scope, "mission/team");
        assert!(request.include_descendant_scopes);
        assert_eq!(request.operation_key, b"chat-reader");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            value,
            json!({"subscriptionId": ID, "inserted": inserted, "operation_key": "chat-reader"})
        );
    }
}

#[test]
fn existing_subscription_succeeds_with_the_same_plain_id() {
    let (_, output) = subscribe(
        &["subscribe", "x", "--scope=x", "--operation-key=reader"],
        false,
    );
    assert_eq!(output.stdout, format!("{ID}\n").as_bytes());
}

#[test]
fn subscribe_generates_a_fresh_text_operation_key_for_each_invocation() {
    let mut keys = Vec::new();
    for _ in 0..2 {
        let (request, output) = subscribe(
            &["subscribe", "--scope=x", "--operation-key=auto", "x"],
            true,
        );
        assert_eq!(request.operation_key.len(), 32);
        assert!(std::str::from_utf8(&request.operation_key).is_ok());
        keys.push(request.operation_key);
        assert_eq!(output.stdout, format!("{ID}\n").as_bytes());
    }
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn subscribe_accepts_command_names_and_dash_prefixed_topics_after_separator() {
    for topic in ["status", "publish", "query", "subscribe", "-events"] {
        let (request, output) = subscribe(
            &[
                "subscribe",
                "--scope=x",
                "--operation-key=test",
                "--",
                topic,
            ],
            false,
        );
        assert_eq!(request.topic, topic);
        assert_eq!(output.stdout, format!("{ID}\n").as_bytes());
    }
}

#[test]
fn subscribe_rejects_missing_ambiguous_and_invalid_arguments() {
    let long_topic = "x".repeat(129);
    let long_key = "я".repeat(129);
    for args in [
        vec!["subscribe"],
        vec!["subscribe", "--scope=x"],
        vec!["subscribe", "x"],
        vec!["subscribe", "--scope=x", ""],
        vec!["subscribe", "--scope=x", "x", "y"],
        vec!["subscribe", "--scope=x", "--topic=x"],
        vec!["subscribe", "--scope=x", "a/b"],
        vec!["subscribe", "--scope=x", "topic=invalid"],
        vec!["subscribe", "--scope=x", &long_topic],
        vec!["subscribe", "--scope=x", "--scope=y", "x"],
        vec!["subscribe", "--scope=", "x"],
        vec!["subscribe", "--scope=/*", "x"],
        vec!["subscribe", "--scope=x/**", "x"],
        vec!["subscribe", "--scope=x//y", "x"],
        vec!["subscribe", "--scope=x/../y", "x"],
        vec!["subscribe", "--scope=x", "--operation-key=", "x"],
        vec!["subscribe", "--scope=x", "--operation-key", &long_key, "x"],
        vec![
            "subscribe",
            "--scope=x",
            "--operation-key=a",
            "--operation-key=b",
            "x",
        ],
        vec!["subscribe", "--scope=x", "x", "--operation-key"],
        vec!["subscribe", "--scope=x", "--publisher=x", "x"],
        vec!["status", "subscribe", "--scope=x", "x"],
        vec!["query", "subscribe", "--scope=x", "x"],
        vec!["subscribe", "--scope=x", "--", "x", "--json"],
    ] {
        let output = run(1, &args);
        assert_eq!(output.status.code(), Some(2), "accepted {args:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    }
}

#[test]
fn subscribe_preserves_topic_scope_and_operation_key_byte_boundaries() {
    let topic = "x".repeat(128);
    let scope = format!("{}/*", "y".repeat(128));
    let key = "я".repeat(128);
    let (request, _) = subscribe(
        &[
            "subscribe",
            "--scope",
            &scope,
            "--operation-key",
            &key,
            &topic,
        ],
        true,
    );
    assert_eq!(request.topic, topic);
    assert_eq!(request.scope.len(), 128);
    assert!(request.include_descendant_scopes);
    assert_eq!(request.operation_key, key.as_bytes());
}

#[test]
fn subscribe_rpc_errors_and_invalid_receipts_fail_without_id_or_remote_message() {
    let error = format!(r#"{{"code":"aborted","message":"secret {TOKEN}"}}"#);
    let short_id = api::CreateEventSubscriptionResponse {
        subscription_id: vec![1; 31],
        inserted: true,
        ..Default::default()
    }
    .encode_to_vec();
    for (status, content_type, body, expected) in [
        (
            "409 Conflict",
            "application/json",
            error.into_bytes(),
            "aborted",
        ),
        (
            "200 OK",
            "application/proto",
            vec![0x0a, 0xff],
            "CreateEventSubscription outcome unknown",
        ),
        (
            "200 OK",
            "application/proto",
            short_id,
            "invalid subscription ID",
        ),
    ] {
        let (address, requests, server) = serve(status, content_type, body);
        let output = run(
            address.port(),
            &["subscribe", "--scope=x", "--operation-key=test", "x"],
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(TOKEN));
        assert!(!message.contains("secret"));
        assert_eq!(
            message.contains("retry the identical request with --operation-key=test"),
            status == "200 OK"
        );
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}
