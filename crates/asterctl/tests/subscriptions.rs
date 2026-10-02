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
        // Keep stdin open: listing subscriptions must not wait for input.
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
            panic!("subscriptions waited for input or failed to finish");
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
    mpsc::Receiver<api::ListEventSubscriptionsRequest>,
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
            "post /aster.application.v1alpha1.asterapplicationservice/listeventsubscriptions http/1.1\r\n"
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
            .send(api::ListEventSubscriptionsRequest::decode_from_slice(&body).unwrap())
            .unwrap();
        connection.write_all(reply.as_bytes()).unwrap();
        let _ = connection.write_all(&response);
    });
    (address, receiver, server)
}

#[test]
fn empty_subscriptions_use_authenticated_empty_request_and_global_options() {
    for (args, expected) in [
        (vec!["subscriptions", "--host=127.0.0.1", "--timeout=2"], ""),
        (vec!["--json", "subscriptions"], "[]\n"),
    ] {
        let (address, requests, server) = serve("200 OK", "application/proto", vec![]);
        let output = run(address.port(), &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
        assert_eq!(
            requests.recv_timeout(Duration::from_secs(1)).unwrap(),
            api::ListEventSubscriptionsRequest::default()
        );
        server.join().unwrap();
    }
}

fn rows() -> api::ListEventSubscriptionsResponse {
    api::ListEventSubscriptionsResponse {
        subscriptions: vec![
            api::EventSubscription {
                subscription_id: (0..32).collect(),
                topic: "z\"\n\u{1b}".into(),
                scope: "mission/\"team\n".into(),
                include_descendant_scopes: true,
                operation_key: "читач\"\n\u{1b}".as_bytes().to_vec(),
                ..Default::default()
            },
            api::EventSubscription {
                subscription_id: vec![0; 32],
                topic: "a".into(),
                scope: "mission/exact".into(),
                operation_key: vec![0xff, 0, 0x80],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[test]
fn text_rows_preserve_order_and_escape_text_or_encode_binary() {
    let (address, requests, server) = serve("200 OK", "application/proto", rows().encode_to_vec());
    let output = run(address.port(), &["subscriptions"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let mut expected = String::new();
    for (index, row) in rows().subscriptions.iter().enumerate() {
        if index > 0 {
            expected.push('\n');
        }
        expected.push_str("SUBSCRIPTION:\n");
        let id = if index == 0 {
            ID
        } else {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        };
        let scope = if row.include_descendant_scopes {
            format!("{}/*", row.scope)
        } else {
            row.scope.clone()
        };
        for (label, value) in [
            ("ID:", id.to_owned()),
            ("Topic:", format!("{:?}", row.topic)),
            ("Scope:", format!("{scope:?}")),
            (
                if index == 0 {
                    "Operation key:"
                } else {
                    "Operation key (Base64):"
                },
                if index == 0 {
                    format!("{:?}", std::str::from_utf8(&row.operation_key).unwrap())
                } else {
                    "/wCA".into()
                },
            ),
        ] {
            expected.push_str(&format!("  {label:<25}{value}\n"));
        }
    }
    assert_eq!(output.stdout, expected.as_bytes());
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[test]
fn json_rows_preserve_order_raw_scope_base64_bytes_and_defaults() {
    let mut response = rows();
    response.subscriptions.push(api::EventSubscription {
        subscription_id: vec![0; 32],
        ..Default::default()
    });
    let (address, requests, server) =
        serve("200 OK", "application/proto", response.encode_to_vec());
    let output = run(address.port(), &["subscriptions", "-j"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected: Vec<_> = response.subscriptions.iter().enumerate().map(|(i, row)| json!({
        "subscriptionId": if i == 0 { ID } else { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
        "topic": row.topic,
        "scope": row.scope,
        "includeDescendantScopes": row.include_descendant_scopes,
        "operationKey": if i == 0 { "0YfQuNGC0LDRhyIKGw==" } else if i == 1 { "/wCA" } else { "" },
    })).collect();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!(expected)
    );
    requests.recv_timeout(Duration::from_secs(1)).unwrap();
    server.join().unwrap();
}

#[test]
fn malformed_ids_fail_atomically_without_printing_rows() {
    for length in [0, 31, 33] {
        for json in [false, true] {
            let mut response = rows();
            response.subscriptions[1].subscription_id = vec![1; length];
            let (address, requests, server) =
                serve("200 OK", "application/proto", response.encode_to_vec());
            let args = if json {
                vec!["subscriptions", "--json"]
            } else {
                vec!["subscriptions"]
            };
            let output = run(address.port(), &args);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("ListEventSubscriptions failed: invalid subscription ID")
            );
            requests.recv_timeout(Duration::from_secs(1)).unwrap();
            server.join().unwrap();
        }
    }
}

#[test]
fn subscriptions_rejects_filters_positionals_and_multiple_commands() {
    for args in [
        vec!["subscriptions", "status"],
        vec!["subscriptions", "subscriptions"],
        vec!["subscriptions", "query"],
        vec!["subscriptions", "publish", "--help"],
        vec!["subscriptions", "subscribe", "--help"],
        vec!["status", "subscriptions"],
        vec!["query", "subscriptions"],
        vec!["subscriptions", "--topic=x"],
        vec!["subscriptions", "--scope=x"],
        vec!["subscriptions", "--limit=1"],
        vec!["subscriptions", "--operation-key=x"],
        vec!["subscriptions", "x"],
        vec!["subscriptions", "--", "x"],
        vec!["subscriptions=x"],
        vec!["subscriptions", "--timeout=0"],
        vec!["subscriptions", "--json=true"],
    ] {
        let output = run(1, &args);
        assert_eq!(output.status.code(), Some(2), "accepted {args:?}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    }
    let output = cli(&["subscriptions"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn top_level_help_lists_subscriptions() {
    let output = cli(&["--help"]);
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("subscriptions     List Event subscriptions")
    );
}

#[test]
fn rpc_failures_are_sanitized_and_bounded_without_partial_output() {
    for (status, content_type, response, expected) in [
        (
            "401 Unauthorized",
            "application/json",
            format!(r#"{{"code":"unauthenticated","message":"secret {TOKEN}"}}"#).into_bytes(),
            "unauthenticated",
        ),
        (
            "403 Forbidden",
            "application/json",
            format!(r#"{{"code":"permission_denied","message":"secret {TOKEN}"}}"#).into_bytes(),
            "permission_denied",
        ),
        (
            "200 OK",
            "application/proto",
            vec![0x0a, 0xff],
            "ListEventSubscriptions failed:",
        ),
        (
            "200 OK",
            "application/proto",
            vec![0; 4 * 1024 * 1024 + 1],
            "resource_exhausted",
        ),
    ] {
        let (address, requests, server) = serve(status, content_type, response);
        let output = run(address.port(), &["subscriptions", "--json"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("secret"));
        assert!(!error.contains("outcome unknown"));
        requests.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn unreachable_agent_and_unreadable_token_fail_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let output = run(port, &["subscriptions"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unavailable"));
    let missing =
        std::env::temp_dir().join(format!("asterctl-missing-token-{}", std::process::id()));
    let output = cli(&["subscriptions", "--token-file", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn stalled_agent_honors_timeout_without_retrying() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let start = Instant::now();
    // The listener remains open, but never sends an HTTP response.
    let output = run(
        listener.local_addr().unwrap().port(),
        &["subscriptions", "--timeout=1"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ListEventSubscriptions failed: deadline_exceeded")
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    listener.set_nonblocking(true).unwrap();
    let _connection = listener.accept().unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn subscriptions_help_needs_no_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["subscriptions", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[OPTIONS] subscriptions"));
    assert!(help.contains("List Event subscriptions"));
}
