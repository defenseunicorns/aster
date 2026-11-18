#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use aster_agent::config::{ValidatedSystemdAgentConfig, load_and_validate_config};
use aster_mesh::ProvisioningSecretRef;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn customer_binary_statically_selects_the_systemd_provider() {
    // Break caught: leaving the customer invocation as a placeholder or
    // restoring runtime provider selection would prevent the approved D06
    // provider from failing closed before state or listeners are opened.
    let fixture = BinaryFixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .arg("--config")
        .arg(&fixture.config)
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .expect("run customer binary");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stdout.is_empty(), "unexpected stdout: {stdout}");
    assert_eq!(stderr, "ERROR provisioning secret store is unavailable\n");
    assert!(!stderr.contains("protected provider required"));
    assert!(
        fs::read_dir(&fixture.state)
            .expect("inspect state directory")
            .next()
            .is_none(),
        "provider construction failure must not create durable state"
    );
}

#[test]
fn enabled_btle_binary_uses_real_systemd_wrapper_and_fails_closed_when_source_is_missing() {
    // Break caught: unit-testing only an injected startup closure could leave
    // the packaged binary disconnected from the exact systemd roster loader.
    let fixture = BinaryFixture::new();
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.config).expect("read systemd config"))
            .expect("parse systemd config");
    config["btle"] = serde_json::json!({
        "enabled": true,
        "peer": "aa".repeat(32),
        "deployment_scope_id": "42".repeat(32),
        "policy": "rostered",
        "emission_policy": "normal",
        "priority": 100,
        "credential": "aster-btle-roster"
    });
    fs::write(&fixture.config, config.to_string()).expect("enable BTLE policy");

    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .arg("--config")
        .arg(&fixture.config)
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .expect("run enabled customer binary");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "ERROR BTLE startup credential validation failed\n"
    );
    assert!(
        fs::read_dir(&fixture.state)
            .expect("inspect state directory")
            .next()
            .is_none(),
        "missing roster source must not publish checkpoint state"
    );
}

#[test]
fn customer_startup_rejects_duplicate_iroh_and_btle_peer_before_btle_credentials() {
    // Break caught: normal packaged startup must reject an unsafe
    // mixed-transport roster before the missing BTLE credential source can
    // replace the duplicate-mission error or create durable state.
    let fixture = BinaryFixture::new();
    let carrier = aster_iroh::SecretKey::from_bytes(&[11; 32]).public();
    let iroh_peer = format!("{carrier}@127.0.0.1:9001={}", "aa".repeat(32));
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.config).expect("read systemd config"))
            .expect("parse systemd config");
    config["mesh"]["peers"] = serde_json::json!([iroh_peer]);
    config["btle"] = serde_json::json!({
        "enabled": true,
        "peer": "aa".repeat(32),
        "deployment_scope_id": "42".repeat(32),
        "policy": "rostered",
        "emission_policy": "normal",
        "priority": 100,
        "credential": "aster-btle-roster"
    });
    fs::write(&fixture.config, config.to_string()).expect("write overlapping roster");

    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .arg("--config")
        .arg(&fixture.config)
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .expect("run packaged customer startup");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "ERROR configuration contains a duplicate peer mission\n"
    );
    assert!(
        fs::read_dir(&fixture.state)
            .expect("inspect state directory")
            .next()
            .is_none(),
        "rejected configuration must not create durable state"
    );
}

#[test]
fn systemd_binary_accepts_only_schema_v1_and_has_no_compose_contract() {
    // Break caught: admitting schema v2 or linking the Compose provider would
    // turn provider choice into a runtime/configuration property.
    let fixture = BinaryFixture::new();
    let v2 = fixture.root.join("agent-v2.json");
    fs::write(&v2, fixture.compose_config()).expect("write schema-v2 config");
    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .arg("--check-config")
        .arg(&v2)
        .output()
        .expect("run systemd binary with schema v2");
    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stderr)
            .expect("UTF-8 stderr")
            .is_empty()
    );

    let validated = load_and_validate_config(&fixture.config).expect("schema-v1 config");
    fn assert_systemd_config(_: &ValidatedSystemdAgentConfig) {}
    assert_systemd_config(&validated);
    let _ = validated.runtime();
}

#[test]
fn systemd_binary_has_no_runtime_provider_selector() {
    // Break caught: a CLI or environment selector could switch the packaged
    // binary away from its statically linked provider.
    let fixture = BinaryFixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .args(["--provider", "compose", "--config"])
        .arg(&fixture.config)
        .output()
        .expect("run forbidden provider selector");
    assert!(!output.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_aster-agent"))
        .arg("--config")
        .arg(&fixture.config)
        .env("ASTER_CREDENTIAL_PROVIDER", "compose")
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .expect("run with ignored provider environment");
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "ERROR provisioning secret store is unavailable\n"
    );
}

struct BinaryFixture {
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

impl BinaryFixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-systemd-binary-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect fixture root");
        let state = root.join("state");
        fs::create_dir(&state).expect("create state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect state directory");
        let token = root.join("client-token");
        fs::write(&token, b"0123456789abcdef0123456789abcdef\n").expect("write token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("protect token");
        let reference = root.join("mission-reference");
        let encoded_ref = ProvisioningSecretRef::from_opaque(b"provider-reference".to_vec())
            .expect("bounded reference")
            .to_bytes();
        fs::write(&reference, encoded_ref).expect("write reference");
        fs::set_permissions(&reference, fs::Permissions::from_mode(0o600))
            .expect("protect reference");
        let config = root.join("agent.json");
        fs::write(
            &config,
            format!(
                r#"{{"schema_version":1,"state":{{"directory":"{}"}},"application":{{"listen":"127.0.0.1:41831"}},"health":{{"listen":"127.0.0.1:41832"}},"mesh":{{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"{}","mission_secret_ref_file":"{}","mission_load_id":"{}"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#,
                state.display(),
                token.display(),
                reference.display(),
                "11".repeat(32),
            ),
        )
        .expect("write config");
        Self {
            root,
            config,
            state,
        }
    }

    fn compose_config(&self) -> String {
        format!(
            r#"{{"schema_version":2,"state":{{"directory":"{}"}},"application":{{"listen":"127.0.0.1:41831"}},"health":{{"listen":"127.0.0.1:41832"}},"mesh":{{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#,
            self.state.display(),
        )
    }
}

impl Drop for BinaryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
