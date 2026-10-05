use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const TOKEN: &str = "asterctl-test-token-00000000000000";

fn cli(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("asterctl did not terminate within 15 seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn serve(
    address: IpAddr,
    status: &str,
    content_type: &str,
    body: &[u8],
    delay: Duration,
) -> (SocketAddr, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((address, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let body = body.to_vec();
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut connection = loop {
            match listener.accept() {
                Ok((connection, _)) => break connection,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("no client request: {e}"),
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
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8];
            connection.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 8192);
        }
        sender.send(String::from_utf8(request).unwrap()).unwrap();
        thread::sleep(delay);
        // The client may close early after its deadline or a response limit.
        let _ = connection.write_all(reply.as_bytes());
        let _ = connection.write_all(&body);
    });
    (address, receiver, server)
}

struct TokenFile(PathBuf);
impl TokenFile {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "asterctl-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        writeln!(options.open(&path).unwrap(), "{TOKEN}").unwrap();
        Self(path)
    }
}
impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn help_needs_neither_token_nor_agent() {
    let output = cli(&["--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--host",
        "--port",
        "--json",
        "--token",
        "--token-file",
        "--help",
    ] {
        assert!(text.contains(flag));
    }
}

#[test]
fn bad_arguments_fail_on_stderr_without_echoing_credentials() {
    for args in [
        vec![],
        vec!["status"],
        vec!["status", "--token", "invalid-secret"],
        vec!["--token", TOKEN, "status", "--port", "invalid"],
        vec!["status", "--token", TOKEN, "--token-file", "ignored"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.is_empty());
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("invalid-secret"));
    }
}

#[test]
fn explicit_and_default_status_use_get_status_with_both_token_sources_and_ip_versions() {
    // Independent protobuf fixture: identity=aabb, sync=OFFLINE,
    // authenticated_contacts=uint64::MAX, present empty capacity messages.
    let body = [
        0x0a, 2, 0xaa, 0xbb, 0x18, 1, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        1, 0x52, 0, 0x5a, 0,
    ];
    for (host, json, explicit) in [
        ("127.0.0.1", false, true),
        ("::1", true, true),
        ("127.0.0.1", false, false),
        ("::1", true, false),
    ] {
        let (address, requests, server) = serve(
            host.parse().unwrap(),
            "200 OK",
            "application/proto",
            &body,
            Duration::ZERO,
        );
        let port = address.port().to_string();
        let file = TokenFile::new();
        let mut args = vec!["--host", host, "--port", &port];
        if explicit {
            args.push("status");
        }
        if json {
            args.extend(["--json", "--token-file", file.0.to_str().unwrap()]);
        } else {
            args.extend(["-t", TOKEN]);
        }
        let output = cli(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let request = requests
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .to_ascii_lowercase();
        assert!(request.starts_with(
            "post /aster.application.v1alpha1.asterapplicationservice/getstatus http/1.1\r\n"
        ));
        assert!(request.contains(&format!("authorization: bearer {TOKEN}\r\n")));
        assert!(request.contains("content-type: application/proto\r\n"));
        assert!(request.contains("connect-timeout-ms:"));
        server.join().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(TOKEN));
        if json {
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["identity"], "qrs=");
            assert_eq!(value["sync"], "SYNC_STATUS_OFFLINE");
            assert_eq!(value["authenticatedContacts"], "18446744073709551615");
            assert_eq!(
                value["publishOperationCapacity"]["estimatedSecondsToExhaustion"],
                "0"
            );
            assert_eq!(value["deliveryCapacity"]["profileSaturated"], false);
        } else {
            assert!(text.starts_with("NODE:\n  Identity:                qrs=\n"));
            assert!(text.contains("  Authenticated contacts:  18,446,744,073,709,551,615\n"));
            assert!(text.contains("  Estimated exhaustion:    0 s\n"));
            assert!(text.contains("  Profile saturated:       No\n"));
        }
    }
}

#[test]
fn rpc_errors_do_not_echo_server_messages_and_malformed_responses_do_not_print_status() {
    let message = format!(r#"{{"code":"unauthenticated","message":"echoed-secret: {TOKEN}"}}"#);
    for (status, content_type, body, expected) in [
        (
            "401 Unauthorized",
            "application/json",
            message.as_bytes(),
            "unauthenticated",
        ),
        (
            "200 OK",
            "application/proto",
            &[0x0a, 0xff][..],
            "GetStatus failed",
        ),
    ] {
        let (address, requests, server) = serve(
            Ipv4Addr::LOCALHOST.into(),
            status,
            content_type,
            body,
            Duration::ZERO,
        );
        let output = cli(&[
            "status",
            "--token",
            TOKEN,
            "-p",
            &address.port().to_string(),
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("echoed-secret"));
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn unreachable_agent_and_unreadable_token_fail_without_status_output() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    for args in [
        vec!["status", "--token", TOKEN, "--port", &port],
        vec!["status", "--token-file", "/does-not-exist/asterctl-token"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!String::from_utf8(output.stderr).unwrap().contains(TOKEN));
    }
}

#[test]
fn stalled_agent_is_bounded_by_the_request_deadline() {
    let (address, requests, server) = serve(
        Ipv4Addr::LOCALHOST.into(),
        "200 OK",
        "application/proto",
        &[],
        Duration::from_secs(11),
    );
    let output = cli(&["status", "-t", TOKEN, "-p", &address.port().to_string()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("deadline_exceeded")
    );
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[test]
fn timeout_before_command_sets_the_rpc_deadline_without_changing_output() {
    let (address, requests, server) = serve(
        Ipv4Addr::LOCALHOST.into(),
        "200 OK",
        "application/proto",
        &[],
        Duration::ZERO,
    );
    let output = cli(&[
        "--token",
        TOKEN,
        "--timeout=20",
        "--port",
        &address.port().to_string(),
        "status",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = requests
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .to_ascii_lowercase();
    let milliseconds: u64 = request
        .lines()
        .find_map(|line| line.strip_prefix("connect-timeout-ms: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!((19_000..=20_000).contains(&milliseconds), "{milliseconds}");
    server.join().unwrap();
}

#[test]
fn non_loopback_is_rejected_before_loading_credentials_or_payload() {
    for command in ["status", "publish", "query", "subscribe"] {
        let output = cli(&[
            command,
            "--host",
            "192.0.2.1",
            "--token-file",
            "/nonexistent/asterctl-review-token",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("host must be a loopback")
        );
        assert!(output.stdout.is_empty());
    }
}
