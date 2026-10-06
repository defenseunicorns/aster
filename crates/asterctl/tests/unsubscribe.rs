use buffa::Message;
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
        // Keep stdin open: deleting subscriptions must not wait for input.
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
            panic!("unsubscribe waited for input or failed to finish");
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn run(port: u16, args: &[&str]) -> Output {
    cli(&[&["--token", TOKEN, "--port", &port.to_string()][..], args].concat())
}

fn serve(
    status: &str,
    content_type: &str,
    response: Vec<u8>,
) -> (
    SocketAddr,
    mpsc::Receiver<api::DeleteEventSubscriptionRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let drop_response = status == "DROP";
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
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
        assert!(header.starts_with(
            "post /aster.application.v1alpha1.asterapplicationservice/deleteeventsubscription http/1.1\r\n"
        ));
        assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
        assert!(header.contains("content-type: application/proto\r\n"));
        assert!(header.contains("connect-timeout-ms:"));
        let length: usize = header
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap_or("0")
            .parse()
            .unwrap();
        assert!(length <= 1024);
        let mut body = vec![0; length];
        connection.read_exact(&mut body).unwrap();
        sender
            .send(api::DeleteEventSubscriptionRequest::decode_from_slice(&body).unwrap())
            .unwrap();
        if !drop_response {
            connection.write_all(reply.as_bytes()).unwrap();
            let _ = connection.write_all(&response);
        }
        drop(connection);
        // Keep the listener alive long enough to detect automatic retries.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
    (address, receiver, server)
}

#[test]
fn unsubscribe_help_needs_no_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["unsubscribe", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("unsubscribe SUBSCRIPTION_ID"));
    assert!(help.contains("32-byte"));
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsubscribe"));
}

#[test]
fn invalid_arguments_and_ids_fail_before_network_or_token_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for args in [
        vec!["unsubscribe"],
        vec!["unsubscribe", ""],
        vec!["unsubscribe", "not-base64"],
        vec!["unsubscribe", "AA=="],
        vec![
            "unsubscribe",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        ],
        vec![
            "unsubscribe",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ],
        vec!["unsubscribe", ID, ID],
        vec!["unsubscribe", ID, "status"],
        vec!["status", "unsubscribe", ID],
        vec!["query", "unsubscribe", ID],
        vec!["unsubscribe", ID, "--operation-key=x"],
        vec!["unsubscribe", ID, "--scope=x"],
        vec!["unsubscribe=x"],
        vec!["unsubscribe", "--", ID],
    ] {
        let output = cli(&[
            &[
                "--token-file",
                "/no-such-asterctl-token",
                "--port",
                &listener.local_addr().unwrap().port().to_string(),
            ][..],
            &args,
        ]
        .concat());
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(ID));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    assert_eq!(cli(&["unsubscribe", ID]).status.code(), Some(2));
}

#[test]
fn unknown_outcomes_are_redacted_and_retry_the_same_id() {
    for (status, content_type, body) in [
        ("200 OK", "application/proto", vec![0x08, 0xff]),
        (
            "503 Service Unavailable",
            "application/json",
            format!(r#"{{"code":"unavailable","message":"secret {TOKEN}"}}"#).into_bytes(),
        ),
        (
            "429 Too Many Requests",
            "application/json",
            format!(r#"{{"code":"resource_exhausted","message":"secret {TOKEN}"}}"#).into_bytes(),
        ),
    ] {
        let (address, requests, server) = serve(status, content_type, body);
        let output = run(address.port(), &["unsubscribe", ID]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.starts_with("asterctl: DeleteEventSubscription outcome unknown:"),
            "{error}"
        );
        assert!(error.ends_with("\nretry unsubscribe with the same subscription ID\n"));
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("secret"));
        assert!(!error.contains("failed"));
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn rejection_codes_do_not_claim_an_unknown_outcome_or_echo_remote_text() {
    for code in [
        "unauthenticated",
        "permission_denied",
        "invalid_argument",
        "failed_precondition",
    ] {
        let body = format!(r#"{{"code":"{code}","message":"secret {TOKEN}"}}"#).into_bytes();
        let (address, requests, server) = serve("403 Forbidden", "application/json", body);
        let output = run(address.port(), &["unsubscribe", ID, "--json"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.starts_with(&format!("asterctl: DeleteEventSubscription failed: {code}")));
        assert!(!error.contains("outcome unknown"));
        assert!(!error.contains("retry unsubscribe"));
        assert!(!error.contains("secret"));
        assert!(!error.contains(TOKEN));
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn lost_response_is_unknown_without_retrying() {
    let (address, requests, server) = serve("DROP", "application/proto", vec![]);
    let output = run(address.port(), &["unsubscribe", ID]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.starts_with("asterctl: DeleteEventSubscription outcome unknown:"));
    assert!(error.ends_with("\nretry unsubscribe with the same subscription ID\n"));
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn closed_stdout_succeeds_and_other_output_errors_fail() {
    use std::os::unix::net::UnixStream;
    for broken_pipe in [true, false] {
        let (address, requests, server) = serve("200 OK", "application/proto", vec![]);
        let stdout = if broken_pipe {
            let (writer, reader) = UnixStream::pair().unwrap();
            drop(reader);
            Stdio::from(std::os::fd::OwnedFd::from(writer))
        } else {
            Stdio::from(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap(),
            )
        };
        let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
            .args([
                "--token",
                TOKEN,
                "--port",
                &address.port().to_string(),
                "unsubscribe",
                ID,
            ])
            .stdout(stdout)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(if broken_pipe { 0 } else { 1 }));
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn token_io_failure_does_not_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let output = cli(&[
        "--token-file",
        "/no-such-asterctl-token",
        "--port",
        &listener.local_addr().unwrap().port().to_string(),
        "unsubscribe",
        ID,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn timeout_is_unknown_and_never_retried() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let start = Instant::now();
    let output = run(
        listener.local_addr().unwrap().port(),
        &["unsubscribe", ID, "--timeout=1"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"asterctl: DeleteEventSubscription outcome unknown: deadline_exceeded\nretry unsubscribe with the same subscription ID\n");
    assert!(start.elapsed() < Duration::from_secs(5));
    listener.set_nonblocking(true).unwrap();
    let _connection = listener.accept().unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn both_outcomes_have_exact_text_and_pretty_protojson() {
    for absent in [false, true] {
        for json in [false, true] {
            let response = api::DeleteEventSubscriptionResponse {
                already_absent: absent,
                ..Default::default()
            };
            let (address, requests, server) =
                serve("200 OK", "application/proto", response.encode_to_vec());
            let args = if json {
                vec!["--json", "unsubscribe", ID]
            } else {
                vec!["unsubscribe", ID]
            };
            let output = run(address.port(), &args);
            assert!(output.status.success());
            let expected = if json {
                format!("{{\n  \"alreadyAbsent\": {absent}\n}}\n")
            } else if absent {
                "Subscription already absent\n".into()
            } else {
                "Subscription removed\n".into()
            };
            assert_eq!(output.stdout, expected.as_bytes());
            assert!(output.stderr.is_empty());
            requests.recv_timeout(Duration::from_secs(1)).unwrap();
            server.join().unwrap();
        }
    }
}

#[test]
fn removed_uses_authenticated_delete_request_and_global_options() {
    let (address, requests, server) = serve("200 OK", "application/proto", vec![]);
    let output = run(
        address.port(),
        &["unsubscribe", ID, "--host=127.0.0.1", "--timeout=2"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Subscription removed\n");
    assert!(output.stderr.is_empty());
    assert_eq!(
        requests
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .subscription_id,
        (0..32).collect::<Vec<u8>>()
    );
    server.join().unwrap();
}
