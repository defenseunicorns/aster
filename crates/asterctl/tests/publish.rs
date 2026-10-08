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

mod support;

mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

const TOKEN: &str = "asterctl-test-token-00000000000000";
const ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn run(port: u16, args: &[&str], input: Option<&[u8]>) -> Output {
    let journal = support::Journal::new();
    run_with_journal(port, args, input, &journal)
}

fn run_with_journal(
    port: u16,
    args: &[&str],
    input: Option<&[u8]>,
    journal: &support::Journal,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_asterctl"));
    command
        .args(["--token", TOKEN, "--port", &port.to_string()])
        .arg(args[0]);
    journal.configure(&mut command);
    let mut child = command
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Leave stdin open when absent: MSG and tombstone must not wait for EOF.
    let mut stdin = child.stdin.take().unwrap();
    if let Some(input) = input {
        match stdin.write_all(input) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("write stdin: {error}"),
        }
        drop(stdin);
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("publish waited for input or failed to finish");
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn serve(
    status: &str,
    content_type: &str,
    response: Vec<u8>,
) -> (
    SocketAddr,
    mpsc::Receiver<api::PublishNumberedEventRequest>,
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
        for phase in 0..3 {
            let mut connection = loop {
                match listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("no publication request: {error}"),
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
            let method = [
                "begineventpublicationsession",
                "completeeventpublicationrecovery",
                "publishnumberedevent",
            ][phase];
            assert!(header.starts_with(&format!(
                "post /aster.application.v1alpha1.asterapplicationservice/{method} http/1.1\r\n"
            )));
            assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
            assert!(header.contains("content-type: application/proto\r\n"));
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(length <= 1024 * 1024);
            let mut body = vec![0; length];
            connection.read_exact(&mut body).unwrap();
            if phase < 2 {
                let response = if phase == 0 {
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
            } else {
                sender
                    .send(api::PublishNumberedEventRequest::decode_from_slice(&body).unwrap())
                    .unwrap();
                connection.write_all(reply.as_bytes()).unwrap();
                connection.write_all(&response).unwrap();
            }
        }
    });
    (address, receiver, server)
}

fn receipt(inserted: bool, _ttl_ms: Option<u64>) -> api::PublishNumberedEventResponse {
    api::PublishNumberedEventResponse {
        result: api::CommittedPublicationResult {
            operation_sequence: 1,
            receipt: api::CommittedEventReceipt {
                event_id: (0..32).collect(),
                transfer_id: (32..64).collect(),
                acceptance_marker: 128,
                ..Default::default()
            }
            .into(),
            content: api::CommittedContentStatus::Available.into(),
            ..Default::default()
        }
        .into(),
        inserted,
        ..Default::default()
    }
}

fn publish(
    args: &[&str],
    input: Option<&[u8]>,
    response: api::PublishNumberedEventResponse,
) -> (api::PublishNumberedEventRequest, Output) {
    let (address, requests, server) =
        serve("200 OK", "application/proto", response.encode_to_vec());
    let output = run(address.port(), args, input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(output.stderr, b"asterctl: operation-sequence=1\n");
    server.join().unwrap();
    (request, output)
}

#[test]
fn publish_sends_all_fields_and_formats_the_rpc_receipt_as_protojson() {
    let (request, output) = publish(
        &[
            "publish",
            "--topic",
            "chat.events",
            "--scope",
            "mission/team/alpha",
            "--priority",
            "flash",
            "--logical-key",
            "пристрій-1",
            "--predecessor",
            ID,
            "--ttl-ms",
            "30001",
            "--json",
            "Hello = Aster!\n",
        ],
        None,
        receipt(true, Some(30001)),
    );
    assert_eq!(request.client_id, b"asterctl-test");
    assert_eq!(request.session, 1);
    assert_eq!(request.operation_sequence, 1);
    assert_eq!(request.topic, "chat.events");
    assert_eq!(request.scope, "mission/team/alpha");
    assert_eq!(request.priority, api::Priority::PRIORITY_FLASH);
    assert_eq!(request.logical_key, "пристрій-1".as_bytes());
    assert_eq!(request.payload, b"Hello = Aster!\n");
    assert_eq!(request.predecessor_id, Some((0..32).collect()));
    assert_eq!(request.ttl_ms, Some(30001));
    assert!(!request.tombstone);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({ "operationSequence": "1", "receipt": { "eventId": ID, "transferId": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=", "acceptanceMarker": "128" }, "content": "COMMITTED_CONTENT_STATUS_AVAILABLE" })
    );
}

#[test]
fn publish_preserves_binary_stdin_and_uses_the_stable_journal_identity() {
    for _ in 0..2 {
        let (request, output) = publish(
            &["publish", "--topic=x", "--scope=x"],
            Some(b"\0\xff\x89PNG\r\n\0\n"),
            receipt(true, None),
        );
        assert_eq!(request.payload, b"\0\xff\x89PNG\r\n\0\n");
        assert_eq!(request.priority, api::Priority::PRIORITY_ROUTINE);
        assert!(request.logical_key.is_empty());
        assert_eq!(request.predecessor_id, None);
        assert_eq!(request.ttl_ms, None);
        assert_eq!(request.client_id, b"asterctl-test");
        assert_eq!(request.operation_sequence, 1);
        let text = String::from_utf8(output.stdout).unwrap();
        for expected in ["EVENT:", "Committed locally", ID, "Operation sequence: 1"] {
            assert!(text.contains(expected), "{text}");
        }
    }
}

#[test]
fn publish_empty_and_option_like_messages_do_not_read_stdin() {
    for message in ["", "--help", "--json", "a=b", "publish", "status"] {
        let (request, _) = publish(
            &["publish", "--topic", "x", "--scope", "x", "--", message],
            None,
            receipt(true, None),
        );
        assert_eq!(request.payload, message.as_bytes());
    }
}

#[test]
fn publish_tombstone_uses_an_empty_payload_without_waiting_for_stdin() {
    let (request, output) = publish(
        &[
            "publish",
            "--topic",
            "x",
            "--scope",
            "x",
            "--tombstone",
            "--json",
        ],
        None,
        receipt(false, None),
    );
    assert!(request.tombstone);
    assert!(request.payload.is_empty());
    assert_eq!(request.ttl_ms, None);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["content"], "COMMITTED_CONTENT_STATUS_AVAILABLE");
    assert!(value.get("ttlMs").is_none());
    let (_, output) = publish(
        &["publish", "--topic", "x", "--scope", "x", "--tombstone"],
        None,
        receipt(false, None),
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Committed locally")
    );
}

#[test]
fn invalid_publication_arguments_fail_before_rpc_or_stdin() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for extra in [
        vec!["--priority", "urgent"],
        vec!["--topic", ""],
        vec!["--topic", "a/b"],
        vec!["--scope", "/a"],
        vec!["--scope", "a//b"],
        vec!["--scope", "a/../b"],
        vec!["--client-id", ""],
        vec!["--ttl-ms", "0"],
        vec!["--ttl-ms", "-1"],
        vec!["--ttl-ms", "18446744073709551616"],
        vec!["--predecessor", "AA=="],
        vec!["--predecessor", "invalid"],
        vec!["--tombstone", "nonempty"],
        vec!["--tombstone", "--ttl-ms", "1"],
        vec!["one", "two"],
    ] {
        let mut args = vec!["publish", "--topic", "x", "--scope", "x"];
        args.extend(extra);
        let output = run(listener.local_addr().unwrap().port(), &args, None);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn publication_limit_includes_metadata_and_payload() {
    let max = 1024 * 1024;
    let template = api::PublishNumberedEventRequest {
        client_id: b"asterctl-test".to_vec(),
        session: u64::MAX,
        operation_sequence: u64::MAX,
        topic: "x".to_owned(),
        scope: "x".to_owned(),
        priority: api::Priority::Routine.into(),
        payload: vec![42; max],
        ..Default::default()
    };
    let overhead = template.encoded_len() as usize - max;
    let payload = vec![42; max - overhead];
    let args = ["publish", "--topic", "x", "--scope", "x"];
    let (request, _) = publish(&args, Some(&payload), receipt(true, None));
    assert_eq!(request.payload, payload);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for length in [payload.len() + 1, 1024 * 1024 + 1] {
        let output = run(
            listener.local_addr().unwrap().port(),
            &args,
            Some(&vec![42; length]),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("1 MiB"));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn publication_errors_hide_remote_text_and_do_not_print_a_receipt() {
    let body = format!(r#"{{"code":"aborted","message":"secret {TOKEN}"}}"#);
    let (address, requests, server) = serve("409 Conflict", "application/json", body.into_bytes());
    let output = run(
        address.port(),
        &["publish", "--topic", "x", "--scope", "x", "hello"],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("Numbered publication failed: aborted"),
        "{error}"
    );
    assert!(!error.contains(TOKEN));
    assert!(!error.contains("secret"));
    assert!(!error.contains("outcome unknown"));
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[test]
fn publish_help_does_not_require_a_token_or_read_stdin() {
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["publish", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("[MSG]"));
    assert!(text.contains("--journal"));
    assert!(text.contains("--tombstone"));
}

#[test]
fn publication_rejects_missing_or_mismatched_numbered_receipts() {
    for response in [
        api::PublishNumberedEventResponse::default(),
        api::PublishNumberedEventResponse {
            result: api::CommittedPublicationResult {
                operation_sequence: 2,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    ] {
        let (address, requests, server) =
            serve("200 OK", "application/proto", response.encode_to_vec());
        let output = run(
            address.port(),
            &["publish", "--topic=x", "--scope=x", "--ttl-ms=1", "hello"],
            None,
        );
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("remains journaled"));
    }
}

#[test]
fn lost_publication_receipt_is_recovered_and_acknowledged_across_cli_processes() {
    let journal = support::Journal::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let committed = receipt(true, None).result.into_option().unwrap();
    let expected = committed.clone();
    let server = thread::spawn(move || {
        let mut publication_count = 0;
        for session in 1..=5 {
            // Each CLI process claims a fresh fenced session. Retain the result
            // until explicit acknowledgement, including after a lost response.
            let outstanding = if session > 1 && session < 5 {
                vec![committed.clone()]
            } else {
                vec![]
            };
            let snapshot = api::BeginEventPublicationSessionResponse {
                session,
                allocated_through: u64::from(session > 1),
                snapshot_revision: session,
                outstanding,
                ..Default::default()
            };
            let mut steps = vec![
                (
                    "begineventpublicationsession",
                    Some(snapshot.encode_to_vec()),
                ),
                ("completeeventpublicationrecovery", Some(Vec::new())),
            ];
            if session == 1 {
                steps.push(("publishnumberedevent", None));
            }
            if session == 4 {
                steps.push(("acknowledgeeventpublicationresult", Some(Vec::new())));
            }
            for (method, response) in steps {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut connection = loop {
                    match listener.accept() {
                        Ok((connection, _)) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("no {method} request: {error}"),
                    }
                };
                connection.set_nonblocking(false).unwrap();
                connection
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    connection.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() <= 8192);
                }
                let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
                assert!(header.starts_with(&format!(
                    "post /aster.application.v1alpha1.asterapplicationservice/{method} http/1.1\r\n"
                )));
                assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                let mut body = vec![0; length];
                connection.read_exact(&mut body).unwrap();
                match method {
                    "begineventpublicationsession" => {
                        let request =
                            api::BeginEventPublicationSessionRequest::decode_from_slice(&body)
                                .unwrap();
                        assert_eq!(request.client_id, b"asterctl-test");
                        assert_eq!(request.expected_session, session - 1);
                        assert_eq!(request.claim_nonce.len(), 32);
                    }
                    "publishnumberedevent" => {
                        let request =
                            api::PublishNumberedEventRequest::decode_from_slice(&body).unwrap();
                        assert_eq!(request.client_id, b"asterctl-test");
                        assert_eq!(request.session, 1);
                        assert_eq!(request.operation_sequence, 1);
                        assert_eq!(request.payload, b"original durable intent");
                        publication_count += 1;
                        // Treat the publication as committed, then lose its
                        // response. No second publication may be submitted.
                    }
                    "acknowledgeeventpublicationresult" => {
                        let request =
                            api::AcknowledgeEventPublicationResultRequest::decode_from_slice(&body)
                                .unwrap();
                        assert_eq!(request.operation_sequence, 1);
                        assert_eq!(request.session, 4);
                    }
                    _ => {}
                }
                if let Some(response) = response {
                    write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                    connection.write_all(&response).unwrap();
                }
            }
        }
        assert_eq!(publication_count, 1);
    });
    let failed = run_with_journal(
        address.port(),
        &[
            "publish",
            "--topic=x",
            "--scope=x",
            "original durable intent",
        ],
        None,
        &journal,
    );
    assert_eq!(failed.status.code(), Some(1));
    assert!(failed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("sequence 1 remains journaled"));
    let original = run_with_journal(
        address.port(),
        &["publication-show", "--sequence=1"],
        None,
        &journal,
    );
    assert!(original.status.success());
    let intent: api::PublishNumberedEventRequest =
        serde_json::from_slice(&original.stdout).unwrap();
    assert_eq!(intent.payload, b"original durable intent");
    assert_eq!(intent.operation_sequence, 1);
    let recovered = run_with_journal(address.port(), &["publication-recover"], None, &journal);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(report["operations"][0]["state"], "committed");
    let retried = run_with_journal(
        address.port(),
        &["publication-retry", "--sequence=1", "--json"],
        None,
        &journal,
    );
    assert!(retried.status.success());
    assert_eq!(
        serde_json::from_slice::<api::CommittedPublicationResult>(&retried.stdout).unwrap(),
        expected
    );
    let acknowledged = run_with_journal(
        address.port(),
        &["publication-ack", "--sequence=1"],
        None,
        &journal,
    );
    assert!(acknowledged.status.success());
    let compacted = run_with_journal(address.port(), &["publication-recover"], None, &journal);
    assert!(compacted.status.success());
    let report: serde_json::Value = serde_json::from_slice(&compacted.stdout).unwrap();
    assert_eq!(report["allocatedThrough"], "1");
    assert_eq!(report["operations"], json!([]));
    server.join().unwrap();
}

#[test]
fn journal_initialization_and_missing_or_corrupt_state_fail_closed_before_rpc() {
    let journal = support::Journal::new();
    std::fs::remove_file(&journal.path).unwrap();
    let initialize = || {
        Command::new(env!("CARGO_BIN_EXE_asterctl"))
            .arg("publication-init")
            .arg("--journal")
            .arg(&journal.path)
            .args(["--client-id", "asterctl-test"])
            .output()
            .unwrap()
    };
    assert!(
        initialize().status.success(),
        "local initialization requires no token"
    );
    let original = std::fs::read(&journal.path).unwrap();
    assert_eq!(initialize().status.code(), Some(1));
    assert_eq!(
        std::fs::read(&journal.path).unwrap(),
        original,
        "initialization must not overwrite established state"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let missing = support::Journal {
        path: journal.path.with_extension("missing"),
    };
    let args = ["publish", "--topic=x", "--scope=x"];
    let output = run_with_journal(listener.local_addr().unwrap().port(), &args, None, &missing);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !missing.path.exists(),
        "opening must not recreate a missing journal"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );

    std::fs::write(&journal.path, b"corrupt publication state").unwrap();
    let output = run_with_journal(listener.local_addr().unwrap().port(), &args, None, &journal);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        std::fs::read(&journal.path).unwrap(),
        b"corrupt publication state"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
