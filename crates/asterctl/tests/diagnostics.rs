use std::process::{Command, Output};

const TOKEN: &str = "asterctl-test-token-00000000000000";

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(["--token", TOKEN])
        .args(args)
        .output()
        .unwrap()
}

fn argument_error(args: &[&str]) -> String {
    let output = cli(args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains(TOKEN));
    error
}

#[test]
fn missing_required_arguments_are_distinct_from_invalid_values() {
    for (args, field) in [
        (vec!["publish", "--scope=mission/team"], "--topic"),
        (vec!["publish", "--topic=chat.events"], "--scope"),
        (vec!["subscribe", "--scope=mission/team"], "TOPIC"),
        (vec!["subscribe", "chat.events"], "--scope"),
    ] {
        let error = argument_error(&args);
        assert!(error.contains(field), "{error}");
        assert!(error.contains("required"), "{error}");
    }

    // An explicitly supplied empty value is invalid, not a missing argument.
    for topic in ["", "test/topic/123", "topic with spaces", "тема"] {
        for args in [
            vec!["publish", "--topic", topic],
            vec!["publish", "--topic", topic, "--scope=mission/team"],
            vec!["query", "--topic", topic],
            vec!["subscribe", "--scope=mission/team", topic],
        ] {
            let error = argument_error(&args);
            assert!(error.to_ascii_lowercase().contains("topic"), "{error}");
            assert!(!error.contains("required"), "{error}");
            assert!(!error.contains("missing"), "{error}");
        }
    }
    for scope in [
        "",
        "/mission",
        "mission/",
        "mission//team",
        "mission/../team",
    ] {
        for args in [
            vec!["publish", "--scope", scope],
            vec!["publish", "--topic=chat.events", "--scope", scope],
            vec!["query", "--scope", scope],
            vec!["subscribe", "chat.events", "--scope", scope],
        ] {
            let error = argument_error(&args);
            assert!(error.contains("scope"), "{error}");
            assert!(!error.contains("required"), "{error}");
            assert!(!error.contains("missing"), "{error}");
        }
    }
}

#[test]
fn missing_option_values_identify_the_option_in_every_command() {
    for command in ["status", "publish", "query", "subscribe"] {
        for option in [
            "-h",
            "--host",
            "-p",
            "--port",
            "-t",
            "--token",
            "--token-file",
        ] {
            let error = argument_error(&[command, option]);
            assert!(error.contains(option), "{command}: {error}");
            assert!(error.contains("requires a value"), "{error}");
        }
    }
    for (command, options) in [
        (
            "publish",
            &[
                "--topic",
                "--scope",
                "--priority",
                "--logical-key",
                "--predecessor",
                "--ttl-ms",
                "--journal",
                "--client-id",
            ][..],
        ),
        (
            "query",
            &[
                "--topic",
                "--scope",
                "--publisher",
                "--logical-key",
                "--limit",
            ][..],
        ),
        ("subscribe", &["--scope", "--operation-key"][..]),
    ] {
        for option in options {
            let error = argument_error(&[command, option]);
            assert!(error.contains(option), "{error}");
            assert!(error.contains("requires a value"), "{error}");
        }
    }
}

#[test]
fn repeated_options_and_values_on_boolean_flags_report_the_actual_problem() {
    for (command, option) in [
        ("publish", "--topic"),
        ("publish", "--scope"),
        ("query", "--topic"),
        ("query", "--scope"),
        ("subscribe", "--scope"),
        ("subscribe", "--operation-key"),
    ] {
        let error = argument_error(&[command, option, "x", option, "x"]);
        assert!(error.contains(option), "{error}");
        assert!(error.contains("repeated"), "{error}");
    }
    for command in ["status", "publish", "query", "subscribe"] {
        for flag in ["--json", "-j", "--help"] {
            let argument = format!("{flag}=true");
            let error = argument_error(&[command, &argument]);
            assert!(error.contains(flag), "{error}");
            assert!(error.contains("does not take a value"), "{error}");
        }
    }
}

#[test]
fn other_invalid_values_are_not_reported_as_missing_arguments() {
    for (args, field) in [
        (vec!["status", "--host=localhost"], "host"),
        (vec!["status", "--port=0"], "port"),
        (
            vec!["publish", "--topic=x", "--scope=x", "--priority=invalid"],
            "priority",
        ),
        (
            vec!["publish", "--topic=x", "--scope=x", "--ttl-ms=0"],
            "TTL",
        ),
        (
            vec!["publish", "--topic=x", "--scope=x", "--predecessor=invalid"],
            "predecessor",
        ),
        (
            vec!["publish", "--topic=x", "--scope=x", "--client-id="],
            "client ID",
        ),
        (vec!["query", "--publisher=invalid"], "publisher"),
        (vec!["query", "--limit=-1"], "limit"),
        (
            vec!["subscribe", "--scope=x", "--operation-key=", "x"],
            "operation key",
        ),
    ] {
        let error = argument_error(&args);
        assert!(error.contains(field), "{error}");
        assert!(!error.contains("required"), "{error}");
        assert!(!error.contains("missing"), "{error}");
    }
}
