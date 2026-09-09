//! Process-level validation ordering for the packaged administration binary.

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

const REJECTED: &[u8] = b"ERROR provisioning secret store rejected the request\n";

#[test]
fn invalid_grammar_and_missing_input_fail_before_root_provider_open() {
    // Break caught: moving provider open before parser or required-stdin
    // validation changes these root-independent rejections to Unavailable.
    let binary = env!("CARGO_BIN_EXE_aster-credential-admin");
    let operation = "11".repeat(32);
    let load = "22".repeat(32);
    let cases = [
        vec!["backup".to_owned()],
        vec![
            "install".to_owned(),
            "--operation".to_owned(),
            operation,
            "--load-operation".to_owned(),
            load,
        ],
    ];

    for arguments in cases {
        let output = Command::new(binary)
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .expect("run production administration binary");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, REJECTED);
    }
}
