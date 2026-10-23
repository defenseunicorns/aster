use buffa::Message;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

const TOKEN: &str = "asterctl-test-token-00000000000000";

fn command(kind: &str, port: u16, key: Option<&str>) -> Command {
    command_with_timeout(kind, port, key, None)
}

fn command_with_timeout(
    kind: &str,
    port: u16,
    key: Option<&str>,
    timeout_seconds: Option<&str>,
) -> Command {
    let directory = std::env::temp_dir().join(format!(
        "asterctl-key-owner-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.join("journal.redb");
    if !path.exists() {
        assert!(
            Command::new(env!("CARGO_BIN_EXE_asterctl"))
                .args([
                    "publication-init",
                    "--journal",
                    path.to_str().unwrap(),
                    "--client-id",
                    "key-fixture"
                ])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_asterctl"));
    command.args(["--token", TOKEN, "--port", &port.to_string(), "--json"]);
    if let Some(timeout_seconds) = timeout_seconds {
        command.arg(format!("--timeout={timeout_seconds}"));
    }
    command.args([kind, "--scope=x"]);
    if let Some(key) = key {
        command.args(["--operation-key", key]);
    }
    if kind == "subscribe" {
        command.arg("x");
    }
    command.args([
        "--journal",
        path.to_str().unwrap(),
        "--client-id",
        "key-fixture",
    ]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn finish(child: Child) -> Output {
    finish_with_timeout(child, Duration::from_secs(5))
}

fn finish_with_timeout(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "command did not finish: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets inherit nonblocking mode on macOS/BSD.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                // Claim/recovery are explicit control calls preceding each CLI mutation.
                let mut stream = stream;
                let header = read_header(&mut stream);
                let size: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                let mut body = vec![0; size];
                stream.read_exact(&mut body).unwrap();
                if header.contains("/begineventpublicationsession ")
                    || header.contains("/completeeventpublicationrecovery ")
                {
                    let body = if header.contains("/begineventpublicationsession ") {
                        let claim =
                            api::BeginEventPublicationSessionRequest::decode_from_slice(&body)
                                .unwrap();
                        api::BeginEventPublicationSessionResponse {
                            session: claim.expected_session + 1,
                            snapshot_revision: 1,
                            ..Default::default()
                        }
                        .encode_to_vec()
                    } else {
                        api::CompleteEventPublicationRecoveryResponse::default().encode_to_vec()
                    };
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                    continue;
                }
                // Keep the parsed mutation available to the original request assertions.
                REQUESTS.with(|saved| *saved.borrow_mut() = Some(body));
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("no request: {e}"),
        }
    }
}

thread_local! { static REQUESTS: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) }; }
fn request(_stream: &mut TcpStream) -> Vec<u8> {
    REQUESTS.with(|saved| saved.borrow_mut().take().unwrap())
}
fn read_header(stream: &mut TcpStream) -> String {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() <= 8192);
    }
    String::from_utf8(header).unwrap().to_ascii_lowercase()
}

fn key_from_request(_kind: &str, body: &[u8]) -> String {
    String::from_utf8(
        api::CreateEventSubscriptionRequest::decode_from_slice(body)
            .unwrap()
            .operation_key,
    )
    .unwrap()
}

fn respond(stream: &mut TcpStream, _kind: &str, inserted: bool) {
    let body = api::CreateEventSubscriptionResponse {
        subscription_id: vec![1; 32],
        inserted,
        ..Default::default()
    }
    .encode_to_vec();
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(&body).unwrap();
}

#[test]
fn missing_key_fails_before_stdin_or_rpc() {
    let kind = "subscribe";
    let listener = listener();
    let child = command(kind, listener.local_addr().unwrap().port(), None)
        .spawn()
        .unwrap();
    let output = finish(child);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "asterctl: --operation-key is required; specify a key or 'auto'\n"
    );
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn auto_key_is_available_before_rpc_response_and_matches_json_and_request() {
    let kind = "subscribe";
    let listener = listener();
    let mut cmd = command(kind, listener.local_addr().unwrap().port(), Some("auto"));
    let mut child = cmd.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stderr).read_line(&mut line).unwrap();
        tx.send(line).unwrap();
    });
    let line = rx.recv_timeout(Duration::from_secs(2));
    if line.is_err() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    let line = line.expect("auto key must be flushed before waiting for the agent");
    let mut stream = accept(&listener);
    let key = key_from_request(kind, &request(&mut stream));
    assert_eq!(key.len(), 32);
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(line, format!("asterctl: operation-key={key}\n"));
    respond(&mut stream, kind, true);
    let output = finish(child);
    reader.join().unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["operation_key"], key);
}

#[test]
fn explicit_keys_are_preserved_and_json_escaped() {
    let kind = "subscribe";
    let listener = listener();
    let key = "читач\t\n'\"$()`\\";
    let mut cmd = command(kind, listener.local_addr().unwrap().port(), Some(key));
    let child = cmd.spawn().unwrap();
    let mut stream = accept(&listener);
    assert_eq!(key_from_request(kind, &request(&mut stream)), key);
    respond(&mut stream, kind, true);
    let output = finish(child);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["operation_key"], key);
}

#[test]
fn lost_response_allows_manual_retry_with_identical_request_and_key() {
    let kind = "subscribe";
    let listener = listener();
    let port = listener.local_addr().unwrap().port();
    let mut cmd = command(kind, port, Some("auto"));
    let child = cmd.spawn().unwrap();
    let mut stream = accept(&listener);
    let original = request(&mut stream);
    let key = key_from_request(kind, &original);
    // The agent committed the mutation, but the response was lost.
    drop(stream);
    let output = finish(child);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("outcome unknown"), "{error}");
    assert!(
        error.contains(&format!(
            "retry the identical request with --operation-key={key}"
        )),
        "{error}"
    );
    assert!(!error.contains(TOKEN));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    let mut cmd = command(kind, port, Some(&key));
    let child = cmd.spawn().unwrap();
    let mut stream = accept(&listener);
    let retry = request(&mut stream);
    let mut old = api::CreateEventSubscriptionRequest::decode_from_slice(&original).unwrap();
    let mut new = api::CreateEventSubscriptionRequest::decode_from_slice(&retry).unwrap();
    old.client = Default::default();
    new.client = Default::default();
    assert_eq!(old, new);
    respond(&mut stream, kind, false);
    let output = finish(child);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["operation_key"], key);
    assert_eq!(value["inserted"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn auto_does_not_send_rpc_if_stderr_write_fails() {
    let kind = "subscribe";
    let listener = listener();
    let mut cmd = command(kind, listener.local_addr().unwrap().port(), Some("auto"));
    cmd.stderr(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    );
    let output = finish(cmd.spawn().unwrap());
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn unusable_receipts_keep_the_key_and_report_unknown_outcomes() {
    let kind = "subscribe";
    for body in [vec![], vec![0x0a, 0xff], vec![0; 4 * 1024 * 1024 + 1]] {
        let listener = listener();
        let mut cmd = command(
            kind,
            listener.local_addr().unwrap().port(),
            Some("saved-key"),
        );
        if kind == "publish" {
            cmd.arg("payload");
        }
        let child = cmd.spawn().unwrap();
        let mut stream = accept(&listener);
        request(&mut stream);
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.write_all(&body).unwrap();
        let output = finish(child);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("outcome unknown"), "{error}");
        assert!(
            error.contains("retry the identical request with --operation-key=saved-key"),
            "{error}"
        );
    }
}

#[test]
fn timeouts_preserve_the_generated_key_without_retrying() {
    let cases: Vec<_> = ["subscribe"].into_iter().map(|kind| thread::spawn(move || {
        let listener = listener();
        let mut cmd = command_with_timeout(
            kind,
            listener.local_addr().unwrap().port(),
            Some("auto"),
            Some("1"),
        );
        let child = cmd.spawn().unwrap();
        let mut stream = accept(&listener);
        let key = key_from_request(kind, &request(&mut stream));
        // Keep the connection open without replying until the client's deadline.
        let output = finish_with_timeout(child, Duration::from_secs(15));
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("outcome unknown: deadline_exceeded"), "{error}");
        assert!(error.contains(&format!("retry the identical request with --operation-key={key}")), "{error}");
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    })).collect();
    for case in cases {
        case.join().unwrap();
    }
}

#[test]
fn client_status_after_publication_init_omits_unissued_session() {
    let listener = listener();
    let port = listener.local_addr().unwrap().port();
    let root = std::env::temp_dir().join(format!(
        "asterctl-fresh-status-{}-{port}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("journal.redb");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_asterctl"))
            .args([
                "publication-init",
                "--journal",
                path.to_str().unwrap(),
                "--client-id",
                "fresh-status",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args([
            "--token",
            TOKEN,
            "--port",
            &port.to_string(),
            "client-status",
            "--journal",
            path.to_str().unwrap(),
            "--client-id",
            "fresh-status",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("status connection failed: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let header = read_header(&mut stream);
    assert!(
        header.contains("/geteventclientstatus "),
        "status must not claim or recover: {header}"
    );
    let size: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; size];
    stream.read_exact(&mut body).unwrap();
    let request = api::GetEventClientStatusRequest::decode_from_slice(&body).unwrap();
    assert_eq!(request.client_id, b"fresh-status");
    assert_eq!(request.observed_session, None);
    let response = api::GetEventClientStatusResponse {
        disposition: api::EventClientDisposition::Unregistered.into(),
        ..Default::default()
    }
    .encode_to_vec();
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
    stream.write_all(&response).unwrap();
    drop(stream);
    let output = finish(child);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        status["disposition"],
        "EVENT_CLIENT_DISPOSITION_UNREGISTERED"
    );
    // redb may update file bookkeeping on open; publication state stays untouched.
    let sdk = aster_agent::sdk::NumberedEventSdk::open(
        aster_agent::proto::aster::application::v1alpha1::AsterApplicationServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            connectrpc::client::ClientConfig::new(
                format!("http://127.0.0.1:{port}").parse().unwrap(),
            ),
        ),
        &path,
        b"fresh-status",
    )
    .unwrap();
    assert_eq!(sdk.session().unwrap(), 0);
    assert!(sdk.client_context().is_err());
    drop(sdk);
    std::fs::remove_dir_all(root).unwrap();
}
