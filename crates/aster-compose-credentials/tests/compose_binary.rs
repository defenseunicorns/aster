#![cfg(unix)]

use sha2::{Digest as _, Sha256};
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn compose_binary_accepts_only_exact_schema_v2() {
    // Break caught: a permissive parser could admit schema v1, aliases,
    // duplicate fields, alternate mounts, or provider selection in config.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let accepted = fixture.run_check(&fixture.v2_config());
    assert!(!accepted.status.success());
    assert_eq!(utf8(accepted.stderr), expected_credential_failure());

    let cases = [
        (
            fixture.v1_config(),
            "ERROR configuration schema version is unsupported\n",
        ),
        (
            fixture.v2_config().replace(
                "\"mission_activation_file\":",
                "\"unknown\":true,\"mission_activation_file\":",
            ),
            "ERROR configuration contains an unknown field\n",
        ),
        (
            fixture.v2_config().replace(
                "\"mission_activation_file\":",
                "\"client_token_file\":\"/run/secrets/aster-client-token\",\"mission_activation_file\":",
            ),
            "ERROR configuration contains a duplicate field\n",
        ),
        (
            fixture
                .v2_config()
                .replace("/run/secrets/aster-client-token", "/tmp/client-token"),
            "ERROR credential file boundary is invalid\n",
        ),
        (
            fixture.v2_config().replace("/var/lib/aster", "/tmp/aster"),
            "ERROR configuration state boundary is invalid\n",
        ),
        (
            fixture
                .v2_config()
                .replace("/var/lib/aster", "/var/lib/aster/../aster"),
            "ERROR configuration state boundary is invalid\n",
        ),
        (
            fixture.v2_config().replace(
                "\"storage\":",
                "\"provider\":\"systemd\",\"storage\":",
            ),
            "ERROR configuration contains an unknown field\n",
        ),
    ];
    for (config, expected) in cases {
        let output = fixture.run_check(&config);
        assert!(!output.status.success(), "configuration was admitted");
        assert_eq!(utf8(output.stderr), expected);
    }
}

#[test]
fn compose_check_config_preflights_credentials_without_state_or_listeners() {
    // Break caught: preflight opening state or listeners before all fixed
    // credentials validate would mutate or expose the service on failure.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let initial = fixture.run_check(&fixture.v2_config());
    assert!(!initial.status.success());
    assert!(!fixture.state.exists(), "preflight created durable state");
    let Ok(application) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIP Compose listener preflight: loopback sockets denied by sandbox");
        return;
    };
    let health = TcpListener::bind("127.0.0.1:0").expect("reserve health listener");
    let config = fixture
        .v2_config()
        .replace(
            "127.0.0.1:41831",
            &application.local_addr().unwrap().to_string(),
        )
        .replace("127.0.0.1:41832", &health.local_addr().unwrap().to_string());
    let output = fixture.run_check(&config);
    assert!(!output.status.success());
    assert_eq!(utf8(output.stderr), expected_credential_failure());
    assert!(!fixture.state.exists(), "preflight created durable state");
    assert_eq!(
        application.local_addr().unwrap().ip().to_string(),
        "127.0.0.1"
    );
    assert_eq!(health.local_addr().unwrap().ip().to_string(), "127.0.0.1");
}

#[test]
fn compose_binary_has_only_the_compose_provider_and_no_legacy_mode() {
    // Break caught: linking systemd/admin code or retaining the unprotected
    // development CLI would create an alternate customer credential path.
    let binary_path = compose_binary_path();
    let binary = fs::read(binary_path).expect("read Compose agent binary");
    assert!(contains(&binary, b"aster-compose-secret-store/v1"));
    for forbidden in [
        b"aster-systemd-credential-store/v2".as_slice(),
        b"CREDENTIALS_DIRECTORY".as_slice(),
        b"aster-credential-admin".as_slice(),
        b"SystemdCredentialLoader".as_slice(),
        b"aster_systemd_credentials".as_slice(),
        b"--mission-bundle-unprotected-reference".as_slice(),
    ] {
        assert!(
            !contains(&binary, forbidden),
            "forbidden binary contract present"
        );
    }

    let fixture = BinaryFixture::new(binary_path);
    let output = Command::new(binary_path)
        .args(["--provider", "systemd", "--check-config"])
        .arg(fixture.write_config(&fixture.v2_config()))
        .env("ASTER_CREDENTIAL_PROVIDER", "systemd")
        .output()
        .expect("run forbidden provider selector");
    assert!(!output.status.success());

    let output = Command::new(binary_path)
        .args([
            "--state",
            "/tmp/state",
            "--mission-bundle-unprotected-reference",
            "/tmp/bundle",
        ])
        .output()
        .expect("run forbidden legacy mode");
    assert!(!output.status.success());
}

#[test]
fn compose_binary_rejects_config_changed_after_delivery_validation() {
    // Break caught: Compose can reopen different config bytes after the
    // delivery validator records its plan digest.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let config_path = fixture.write_config(&fixture.v2_config());
    for (digest, expected) in [
        (None, "ERROR configuration digest is required\n"),
        (
            Some("not-a-digest".to_owned()),
            "ERROR configuration digest is invalid\n",
        ),
        (
            Some("0".repeat(64)),
            "ERROR configuration digest does not match\n",
        ),
    ] {
        let mut command = Command::new(binary_path);
        command
            .args(["--check-config", config_path.to_str().expect("UTF-8 path")])
            .env_remove("ASTER_AGENT_CONFIG_SHA256");
        if let Some(digest) = digest {
            command.env("ASTER_AGENT_CONFIG_SHA256", digest);
        }
        let output = command.output().expect("run digest-bound preflight");
        assert!(!output.status.success());
        assert_eq!(utf8(output.stderr), expected);
    }
}

#[test]
fn compose_binary_rejects_oversized_config_before_hash_or_parse() {
    // Break caught: a selected config replaced after plan validation could be
    // read without bound before its digest mismatch or syntax is rejected.
    let binary_path = compose_binary_path();
    let fixture = BinaryFixture::new(binary_path);
    let config = vec![b' '; 256 * 1024 + 1];
    let config_path = fixture.root.join("oversized-agent.json");
    fs::write(&config_path, &config).expect("write oversized config");
    let digest = Sha256::digest(&config)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = Command::new(binary_path)
        .args(["--check-config", config_path.to_str().expect("UTF-8 path")])
        .env("ASTER_AGENT_CONFIG_SHA256", digest)
        .output()
        .expect("run bounded preflight");
    assert!(!output.status.success());
    assert_eq!(utf8(output.stderr), "ERROR configuration file is invalid\n");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn compose_binary_path() -> &'static str {
    let binary_path = env!("CARGO_BIN_EXE_aster-compose-agent");
    let binary = fs::read(binary_path).expect("read candidate Compose agent binary");
    assert!(
        contains(&binary, b"aster-compose-secret-store/v1"),
        "Compose tests must inspect the Compose aster-agent binary"
    );
    binary_path
}

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("UTF-8 process output")
}

const fn expected_credential_failure() -> &'static str {
    if cfg!(target_os = "linux") {
        "ERROR credential mount boundary is invalid\n"
    } else {
        "ERROR unsupported credential platform\n"
    }
}

struct BinaryFixture {
    binary: &'static str,
    root: PathBuf,
    state: PathBuf,
}

impl BinaryFixture {
    fn new(binary: &'static str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-compose-binary-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect fixture");
        let state = root.join("state");
        Self {
            binary,
            root,
            state,
        }
    }

    fn run_check(&self, config: &str) -> std::process::Output {
        let digest = Sha256::digest(config.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Command::new(self.binary)
            .arg("--check-config")
            .arg(self.write_config(config))
            .env("ASTER_AGENT_CONFIG_SHA256", digest)
            .output()
            .expect("run Compose preflight")
    }

    fn write_config(&self, config: &str) -> PathBuf {
        let path = self.root.join("agent.json");
        fs::write(&path, config).expect("write agent config");
        path
    }

    fn v2_config(&self) -> String {
        r#"{"schema_version":2,"state":{"directory":"/var/lib/aster"},"application":{"listen":"127.0.0.1:41831"},"health":{"listen":"127.0.0.1:41832"},"mesh":{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]},"credentials":{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"},"storage":{"max_items":10000,"max_payload_bytes":67108864,"operations":{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}"#.to_owned()
    }

    fn v1_config(&self) -> String {
        self.v2_config()
            .replace("\"schema_version\":2", "\"schema_version\":1")
    }
}

impl Drop for BinaryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
