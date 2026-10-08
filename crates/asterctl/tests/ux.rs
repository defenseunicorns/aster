use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

mod support;

const TOKEN: &str = "asterctl-test-token-00000000000000";

fn command(kind: &str, port: u16) -> (Command, Option<support::Journal>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_asterctl"));
    command.args(["--token", TOKEN, "--port", &port.to_string(), kind]);
    let journal = (kind == "publish").then(support::Journal::new);
    if let Some(journal) = &journal {
        journal.configure(&mut command);
    }
    match kind {
        "publish" => {
            command.args(["--topic=x", "--scope=x", "hello"]);
        }
        "subscribe" => {
            command.args(["--scope=x", "--operation-key=retry-key", "x"]);
        }
        _ => {}
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (command, journal)
}

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(4);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CLI did not respect its configured deadline");
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

fn request(listener: &TcpListener) -> (TcpStream, String) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("no RPC request: {error}"),
        }
    };
    // Accepted sockets inherit nonblocking mode on macOS/BSD.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() <= 8192);
    }
    let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
    let size: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap_or("0")
        .parse()
        .unwrap();
    assert!(size < 4096);
    stream.read_exact(&mut vec![0; size]).unwrap();
    (stream, header)
}

#[test]
fn timeout_rejects_invalid_values_before_rpc() {
    for value in [
        "",
        "0",
        "-1",
        "1.5",
        "NaN",
        "1s",
        "+1",
        "86401",
        "18446744073709551615",
    ] {
        let output = command("status", 1)
            .0
            .arg(format!("--timeout={value}"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("timeout must be an integer"), "{error}");
        assert!(!error.contains(TOKEN));
    }
    let output = command("status", 1).0.arg("--timeout").output().unwrap();
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--timeout requires a value")
    );
}

#[test]
fn configured_timeout_bounds_every_rpc_and_preserves_mutation_recovery() {
    let cases: Vec<_> = ["status", "query", "publish", "subscribe"].into_iter().map(|kind| thread::spawn(move || {
        let listener = listener();
        let (mut command, _journal) = command(kind, listener.local_addr().unwrap().port());
        command.args(["--timeout", "1"]);
        let started = Instant::now();
        let child = command.spawn().unwrap();
        let (_stream, header) = request(&listener);
        let ms: u64 = header.lines().find_map(|line| line.strip_prefix("connect-timeout-ms: ")).unwrap().parse().unwrap();
        assert!((1..=1000).contains(&ms), "{ms}");
        let output = finish(child);
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("deadline_exceeded"), "{error}");
        assert!(error.contains("--timeout"), "{error}");
        if kind == "subscribe" {
            assert!(error.contains("outcome unknown"), "{error}");
            assert!(error.contains("retry the identical request with --operation-key=retry-key"), "{error}");
        }
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    })).collect();
    for case in cases {
        case.join().unwrap();
    }
}

#[test]
fn rpc_hints_are_local_and_do_not_echo_server_messages_or_tokens() {
    for kind in ["status", "query", "publish", "subscribe"] {
        for (code, hint) in [
            ("unavailable", "--host and --port"),
            ("unauthenticated", "token"),
            ("permission_denied", "permission"),
        ] {
            let listener = listener();
            let (mut command, _journal) = command(kind, listener.local_addr().unwrap().port());
            let child = command.spawn().unwrap();
            let (mut stream, _) = request(&listener);
            let body = format!(r#"{{"code":"{code}","message":"REMOTE-CANARY {TOKEN}"}}"#);
            write!(stream, "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            drop(stream);
            let output = finish(child);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains(code), "{error}");
            assert!(error.contains("Check "), "{error}");
            assert!(error.contains(hint), "{error}");
            assert!(!error.contains("REMOTE-CANARY"));
            assert!(!error.contains(TOKEN));
        }
    }
}

#[cfg(unix)]
#[test]
fn stdin_hint_is_shown_before_reading_only_for_terminal_payloads() {
    let output = Command::new("python3")
        .args([
            "-c",
            include_str!("terminal.py"),
            env!("CARGO_BIN_EXE_asterctl"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
