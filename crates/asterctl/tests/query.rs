use buffa::Message;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

mod proto {
    connectrpc::include_generated!();
}
use proto::aster::application::v1alpha1 as api;

const TOKEN: &str = "asterctl-test-token-00000000000000";
const ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn run(port: u16, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["--token", TOKEN, "--port", &port.to_string()])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain concurrently so a large result cannot block on a full output pipe.
    let mut stdout = child.stdout.take().unwrap();
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("query did not finish");
        }
        thread::sleep(Duration::from_millis(5));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

struct Reply {
    body: Vec<u8>,
    error: bool,
    done: bool,
}

fn result(events: Vec<api::Event>, scanned_through: u64, has_more: bool, done: bool) -> Reply {
    Reply {
        body: api::QueryEventsResponse {
            events,
            scanned_through,
            has_more,
            ..Default::default()
        }
        .encode_to_vec(),
        error: false,
        done,
    }
}

fn error(code: &str, done: bool) -> Reply {
    Reply {
        body: format!(r#"{{"code":"{code}","message":"secret {TOKEN}"}}"#).into_bytes(),
        error: true,
        done,
    }
}

fn serve(
    mut respond: impl FnMut(api::QueryEventsRequest) -> Reply + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        loop {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("no query request: {e}"),
                }
            };
            // Accepted sockets inherit nonblocking mode on macOS/BSD.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() <= 8192);
            }
            let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
            assert!(header.starts_with(
                "post /aster.application.v1alpha1.asterapplicationservice/queryevents http/1.1\r\n"
            ));
            assert!(header.contains(&format!("authorization: bearer {TOKEN}\r\n")));
            assert!(header.contains("content-type: application/proto\r\n"));
            let length: usize = header
                .lines()
                .find_map(|s| s.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(length <= 1024 * 1024);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let request = api::QueryEventsRequest::decode_from_slice(&body).unwrap();
            assert!((1..=1024).contains(&request.limit));
            let reply = respond(request);
            let (status, content_type) = if reply.error {
                ("429 Too Many Requests", "application/json")
            } else {
                ("200 OK", "application/proto")
            };
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.body.len()).unwrap();
            stream.write_all(&reply.body).unwrap();
            if reply.done {
                break;
            }
        }
    });
    (address, server)
}

fn event(marker: u64) -> api::Event {
    api::Event {
        id: vec![7; 32],
        publisher: (0..32).collect(),
        publisher_counter: u64::MAX,
        event_sequence: marker,
        topic: "chat.events".into(),
        scope: "mission/team/alpha".into(),
        priority: api::Priority::PRIORITY_ROUTINE.into(),
        logical_key: b"key".to_vec(),
        payload: b"Hello\n".to_vec(),
        acceptance_marker: marker,
        ..Default::default()
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn query_reads_all_matches_and_continues_after_empty_responses() {
    let (address, server) = serve(|r| {
        assert_eq!(r.topic.as_deref(), Some("chat.events"));
        assert_eq!(r.scope.as_deref(), Some("mission/team"));
        assert!(r.include_descendant_scopes);
        assert_eq!(r.publisher, Some((0..32).collect()));
        assert_eq!(r.logical_key, Some(Vec::new()));
        match r.after_acceptance_marker {
            0 => result(vec![], 17, true, false),
            17 => result(vec![event(18), event(19)], 25, true, false),
            25 => result(vec![event(26)], 30, false, true),
            marker => panic!("unexpected continuation: {marker}"),
        }
    });
    let output = run(
        address.port(),
        &[
            "query",
            "--topic=chat.events",
            "--scope=mission/team/*",
            "--publisher",
            ID,
            "--logical-key=",
        ],
    );
    success(&output);
    server.join().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().filter(|s| *s == "EVENT:").count(), 3);
    assert!(text.contains("Hello\\n"));
    assert!(!text.contains("Has more"));
    assert!(!text.contains("Scanned through"));
}

#[test]
fn query_limit_counts_returned_events_across_many_requests() {
    let (address, server) = serve(|r| {
        assert!(
            r.publisher.is_none()
                && r.topic.is_none()
                && r.scope.is_none()
                && r.logical_key.is_none()
        );
        assert!(!r.include_descendant_scopes);
        if r.after_acceptance_marker == 0 {
            return result(vec![], 100, true, false);
        }
        let end = r.after_acceptance_marker + u64::from(r.limit);
        assert!(
            end <= 102_120,
            "client requested beyond the remaining result limit"
        );
        result(
            ((r.after_acceptance_marker + 1)..=end).map(event).collect(),
            end,
            true,
            end == 102_120,
        )
    });
    let output = run(address.port(), &["query", "--limit=102020"]);
    success(&output);
    server.join().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().filter(|s| *s == "EVENT:").count(), 102_020);
}

#[test]
fn query_stops_successfully_when_fewer_events_exist_than_the_limit() {
    let (address, server) = serve(|r| {
        assert_eq!(r.scope.as_deref(), Some("mission/team"));
        assert!(!r.include_descendant_scopes);
        result(vec![event(1)], 1, false, true)
    });
    let output = run(
        address.port(),
        &[
            "query",
            "--scope=mission/team",
            "--limit=18446744073709551615",
        ],
    );
    success(&output);
    server.join().unwrap();
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|s| *s == "EVENT:")
            .count(),
        1
    );
}

#[test]
fn query_reduces_internal_request_size_for_large_results() {
    let mut last_limit = None;
    let (address, server) = serve(move |r| {
        assert_eq!(r.after_acceptance_marker, 0);
        if let Some(last) = last_limit {
            assert!(r.limit < last);
        }
        last_limit = Some(r.limit);
        if r.limit > 1 {
            return error("resource_exhausted", false);
        }
        let mut e = event(1);
        e.payload = vec![0xff; 1_000_000];
        result(vec![e], 1, false, true)
    });
    let output = run(address.port(), &["query"]);
    success(&output);
    server.join().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Payload (Base64)"));
    assert!(!text.contains(TOKEN));
}

#[test]
fn query_rejects_invalid_arguments_without_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for args in [
        vec!["query", "--topic=a/b"],
        vec!["query", "--topic="],
        vec!["query", "--scope=mission/**"],
        vec!["query", "--scope=*/team"],
        vec!["query", "--scope=*"],
        vec!["query", "--scope=mission//team/*"],
        vec!["query", "--scope="],
        vec!["query", "--publisher=AA=="],
        vec!["query", "--limit=-1"],
        vec!["query", "--limit=+1"],
        vec!["query", "--limit=1.5"],
        vec!["query", "--limit=18446744073709551616"],
        vec!["query", "--limit=1", "--limit=2"],
        vec!["query", "--after=1"],
        vec!["query", "--include-descendant-scopes"],
        vec!["query", "unexpected"],
        vec!["status", "query"],
        vec!["query", "publish"],
        vec!["query", "--ttl-ms=1"],
    ] {
        let output = run(listener.local_addr().unwrap().port(), &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn query_fails_on_nonadvancing_responses_instead_of_looping() {
    let (address, server) = serve(|_| result(vec![], 0, true, true));
    let output = run(address.port(), &["query"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
}

#[test]
fn query_errors_do_not_echo_server_messages() {
    let (address, server) = serve(|_| error("permission_denied", true));
    let output = run(address.port(), &["query"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("QueryEvents failed: permission_denied"));
    assert!(!error.contains(TOKEN));
    assert!(!error.contains("secret"));
}

#[test]
fn query_help_needs_no_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["query", "--help"])
        .output()
        .unwrap();
    success(&output);
}

#[test]
fn query_json_preserves_rpc_event_fields_types_and_binary_payloads() {
    let (address, server) = serve(|r| match r.after_acceptance_marker {
        0 => {
            let mut e = event(1);
            e.payload = vec![0, 255];
            e.logical_key = "ключ".as_bytes().to_vec();
            e.priority = 77.into();
            e.ttl_ms = Some(1);
            result(vec![e], 1, true, false)
        }
        1 => result(
            vec![api::Event {
                acceptance_marker: 2,
                ..Default::default()
            }],
            2,
            false,
            true,
        ),
        other => panic!("unexpected cursor {other}"),
    });
    let output = run(address.port(), &["-j", "query"]);
    success(&output);
    server.join().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([
            {"id":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=", "publisher": ID,
             "publisherCounter":"18446744073709551615", "eventSequence":"1",
             "topic":"chat.events", "scope":"mission/team/alpha", "priority":77,
             "logicalKey":"0LrQu9GO0Yc=", "payload":"AP8=", "tombstone":false,
             "acceptanceMarker":"1", "ttlMs":"1"},
            {"id":"", "publisher":"", "publisherCounter":"0", "eventSequence":"0",
             "topic":"", "scope":"", "priority":"PRIORITY_UNSPECIFIED",
             "logicalKey":"", "payload":"", "tombstone":false, "acceptanceMarker":"2"}
        ])
    );
    assert!(output.stdout.ends_with(b"\n"));
}

#[test]
fn query_empty_results_and_zero_limit_succeed() {
    for json in [false, true] {
        let mut args = vec!["query"];
        if json {
            args.push("--json");
        }
        let (address, server) = serve(|_| result(vec![], 0, false, true));
        let output = run(address.port(), &args);
        success(&output);
        server.join().unwrap();
        assert_eq!(output.stdout, if json { b"[]\n".as_slice() } else { b"" });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        args.push("--limit=0");
        let output = run(listener.local_addr().unwrap().port(), &args);
        success(&output);
        assert_eq!(output.stdout, if json { b"[]\n".as_slice() } else { b"" });
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn query_text_escapes_untrusted_strings_instead_of_emitting_terminal_controls() {
    let (address, server) = serve(|_| {
        let mut e = event(1);
        e.topic = "bad\x1b[31m".into();
        e.scope = "bad\r\nFIELD:".into();
        e.logical_key = vec![0, 27, 127];
        e.payload = "text\n\x1b[2J\u{009b}31m\u{202e}".as_bytes().to_vec();
        result(vec![e], 1, false, true)
    });
    let output = run(address.port(), &["query"]);
    success(&output);
    server.join().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(['\0', '\x1b', '\r', '\x7f', '\u{009b}', '\u{202e}']));
    assert!(text.contains("text\\n"));
}

#[test]
fn query_exits_on_invalid_order_or_excess_results_before_printing_them() {
    for (events, scanned, more) in [
        (vec![event(2), event(1)], 2, false),
        (vec![event(1), event(1)], 1, false),
        (vec![event(2)], 1, false),
        (vec![event(0)], 1, false),
        (vec![], 0, true),
    ] {
        let mut events = Some(events);
        let (address, server) = serve(move |_| result(events.take().unwrap(), scanned, more, true));
        let output = run(address.port(), &["query"]);
        server.join().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    let (address, server) = serve(|_| result(vec![event(1), event(2)], 2, false, true));
    let output = run(address.port(), &["query", "--limit=1"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn query_fails_if_even_one_record_exceeds_the_response_budget() {
    let (address, server) = serve(|r| error("resource_exhausted", r.limit == 1));
    let output = run(address.port(), &["query"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("QueryEvents failed: resource_exhausted")
    );
}

#[test]
fn query_stops_reading_when_the_output_pipe_is_closed() {
    let (closed, wait_closed) = std::sync::mpsc::channel();
    let (address, server) = serve(move |_| {
        // Deliver only after the reader closes, regardless of process scheduling.
        wait_closed.recv_timeout(Duration::from_secs(5)).unwrap();
        result(vec![event(1)], 1, true, true)
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args([
            "--token",
            TOKEN,
            "--port",
            &address.port().to_string(),
            "query",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    closed.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    success(&output);
    server.join().unwrap();
}

#[test]
fn query_reports_later_errors_after_writing_earlier_events() {
    let (address, server) = serve(|r| match r.after_acceptance_marker {
        0 => result(vec![event(1)], 1, true, false),
        1 => error("unavailable", true),
        other => panic!("unexpected cursor {other}"),
    });
    let output = run(address.port(), &["query"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|s| *s == "EVENT:")
            .count(),
        1
    );
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("QueryEvents failed: unavailable"));
    assert!(!error.contains(TOKEN));
}

#[test]
fn query_timeout_is_per_page_not_for_the_whole_query() {
    let (address, server) = serve(|request| {
        thread::sleep(Duration::from_millis(650));
        match request.after_acceptance_marker {
            0 => result(vec![event(1)], 1, true, false),
            1 => result(vec![event(2)], 2, false, true),
            other => panic!("unexpected cursor {other}"),
        }
    });
    let output = run(address.port(), &["--timeout=1", "query", "--json"]);
    success(&output);
    assert_eq!(
        serde_json::from_slice::<Vec<Value>>(&output.stdout)
            .unwrap()
            .len(),
        2
    );
    server.join().unwrap();
}
