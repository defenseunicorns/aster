#![cfg(unix)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

#[cfg(target_os = "linux")]
use serde_json::Value;

#[cfg(target_os = "linux")]
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
#[test]
fn healthcheck_accepts_only_a_bounded_ready_response() {
    // Break caught: using the old fixed 8182 endpoint ignores a deployment's
    // reviewed health.listen value; accepting a non-200 still fails closed.
    let fixture = Fixture::new();
    let ready = OneShotHttp::start("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let config = fixture.write_config("127.0.0.1:41831", &ready.address);
    let output = Command::new(env!("CARGO_BIN_EXE_aster-compose-healthcheck"))
        .args(["--config", config.to_str().unwrap()])
        .output()
        .expect("run healthcheck");
    assert!(output.status.success());
    assert_eq!(utf8(output.stdout), "HEALTH status=ready\n");
    assert_eq!(utf8(output.stderr), "");
    ready.join();

    let unavailable =
        OneShotHttp::start("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
    let config = fixture.write_config("127.0.0.1:41831", &unavailable.address);
    let output = Command::new(env!("CARGO_BIN_EXE_aster-compose-healthcheck"))
        .args(["--config", config.to_str().unwrap()])
        .output()
        .expect("run healthcheck");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(utf8(output.stdout), "");
    assert_eq!(utf8(output.stderr), "ERROR health status is not ready\n");
    unavailable.join();
}

#[test]
fn verifier_fails_closed_without_its_fixed_token_and_manifest_mounts() {
    // Break caught: verifier fallback to environment/arguments could bypass
    // the exact token-plus-manifest grant in the Compose model.
    let output = Command::new(env!("CARGO_BIN_EXE_aster-compose-verify"))
        .env_remove("ASTER_CLIENT_TOKEN")
        .env_remove("ASTER_CREDENTIAL_GENERATION")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(utf8(output.stdout), "");
    assert_eq!(
        utf8(output.stderr),
        "ERROR verification input is unavailable\n"
    );
}

#[test]
fn compose_image_contexts_include_every_required_build_input() {
    // Break caught: falling back to the repository-wide .dockerignore can
    // silently omit proto/ even though both image builds copy that directory.
    let image_root = workspace_root().join("docker/compose-agent");
    for dockerfile in ["Dockerfile.agent", "Dockerfile.admin"] {
        let ignore = fs::read_to_string(image_root.join(format!("{dockerfile}.dockerignore")))
            .unwrap_or_else(|error| panic!("read {dockerfile}.dockerignore: {error}"));
        for required in [
            "!Cargo.toml",
            "!Cargo.lock",
            "!LICENSE",
            "!THIRD_PARTY_NOTICES.md",
            "!crates/**",
            "!proto/**",
            "!third-party/**",
        ] {
            assert!(
                ignore.lines().any(|line| line == required),
                "{dockerfile}.dockerignore must contain {required}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rendered_compose_model_enforces_the_hardened_service_boundaries() {
    // Break caught: a Compose edit could grant an extra secret/state/network,
    // weaken runtime hardening, or restore a privileged initializer.
    let model = render_compose_model("aster-task5-a");
    assert!(model.get("volumes").is_none());

    let services = model["services"].as_object().expect("services object");
    assert_eq!(
        services.keys().map(String::as_str).collect::<Vec<_>>(),
        ["aster-agent", "preflight", "verify"]
    );

    let runtime = &services["aster-agent"];
    assert_eq!(
        runtime["image"],
        "registry.example/aster-agent@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(runtime["user"], "10001:10001");
    assert_eq!(runtime["read_only"], true);
    assert_eq!(runtime["cap_drop"], serde_json::json!(["ALL"]));
    assert_eq!(
        runtime["security_opt"],
        serde_json::json!(["no-new-privileges:true"])
    );
    assert_eq!(runtime["restart"], "on-failure:3");
    assert_eq!(
        runtime["environment"]["ASTER_AGENT_CONFIG_SHA256"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(runtime["stop_signal"], "SIGTERM");
    assert_eq!(runtime["stop_grace_period"], "40s");
    assert!(runtime.get("ports").is_none());
    assert!(runtime.to_string().find("docker.sock").is_none());
    assert_eq!(
        secret_targets(runtime),
        [
            "/run/secrets/aster-client-token",
            "/run/secrets/aster-mission-activation",
            "/run/secrets/aster-provisioning-bundle",
        ]
    );
    assert_eq!(runtime["volumes"].as_array().unwrap().len(), 1);
    assert_eq!(runtime["volumes"][0]["type"], "bind");
    assert_eq!(runtime["volumes"][0]["source"], "/srv/aster/state-test");
    assert_eq!(runtime["volumes"][0]["target"], "/var/lib/aster");
    assert_eq!(runtime["tmpfs"].as_array().unwrap().len(), 1);
    assert_eq!(runtime["logging"]["driver"], "json-file");
    assert_eq!(runtime["logging"]["options"]["max-file"], "3");
    assert_eq!(runtime["logging"]["options"]["max-size"], "5m");

    for service in services.values() {
        assert_ne!(service["user"], "0:0");
        assert!(service.get("cap_add").is_none());
    }

    let preflight = &services["preflight"];
    assert_eq!(preflight["network_mode"], "none");
    assert_eq!(
        preflight["environment"]["ASTER_AGENT_CONFIG_SHA256"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(preflight.get("volumes").is_none());
    assert_eq!(secret_targets(preflight).len(), 3);

    let verify = &services["verify"];
    assert_eq!(verify["network_mode"], "service:aster-agent");
    assert_eq!(verify["volumes"].as_array().unwrap().len(), 1);
    assert_eq!(
        verify["volumes"][0]["target"],
        "/run/aster-generation/manifest.json"
    );
    assert_eq!(secret_targets(verify), ["/run/secrets/aster-client-token"]);
    assert_eq!(verify["configs"][0]["target"], "/etc/aster/agent.json");

    let secrets = model["secrets"].as_object().expect("top-level secrets");
    assert_eq!(secrets.len(), 3);
    for (name, file) in [
        ("aster-client-token", "aster-client-token"),
        ("aster-mission-activation", "aster-mission-activation"),
        ("aster-provisioning-bundle", "aster-provisioning-bundle"),
    ] {
        assert_eq!(
            secrets[name]["file"],
            format!("/srv/aster/generation-test/{file}")
        );
        assert!(secrets[name].get("environment").is_none());
    }
}

#[cfg(target_os = "linux")]
fn render_compose_model(project: &str) -> Value {
    let compose = workspace_root().join("docker/compose-agent/compose.yaml");
    let output = Command::new("docker")
        .args(["compose", "--project-name", project, "-f"])
        .arg(&compose)
        .args(["config", "--format", "json"])
        .env("ASTER_CREDENTIAL_GENERATION_DIR", "/srv/aster/generation-test")
        .env(
            "ASTER_AGENT_CONFIG_FILE",
            workspace_root().join("docker/compose-agent/agent.example.json"),
        )
        .env(
            "ASTER_AGENT_CONFIG_SHA256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .env("ASTER_UID", "10001")
        .env("ASTER_GID", "10001")
        .env("ASTER_STATE_DIR", "/srv/aster/state-test")
        .env(
            "ASTER_AGENT_IMAGE_DIGEST",
            "registry.example/aster-agent@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .env(
            "ASTER_ADMIN_IMAGE_DIGEST",
            "registry.example/aster-admin@sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .output()
        .expect("render Compose model");
    assert!(
        output.status.success(),
        "Compose render failed: {}",
        utf8(output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Compose JSON")
}

#[cfg(target_os = "linux")]
fn secret_targets(service: &Value) -> Vec<&str> {
    service["secrets"]
        .as_array()
        .expect("service secrets")
        .iter()
        .map(|secret| secret["target"].as_str().expect("secret target"))
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("UTF-8 output")
}

#[cfg(target_os = "linux")]
struct Fixture {
    root: PathBuf,
}

#[cfg(target_os = "linux")]
impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-compose-helper-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        Self { root }
    }

    fn write_config(&self, application: &str, health: &str) -> PathBuf {
        let path = self.root.join("agent.json");
        fs::write(
            &path,
            format!(
                r#"{{"schema_version":2,"state":{{"directory":"/var/lib/aster"}},"application":{{"listen":"{application}"}},"health":{{"listen":"{health}"}},"mesh":{{"bind":"127.0.0.1:41833","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#
            ),
        )
        .expect("write config");
        path
    }
}

#[cfg(target_os = "linux")]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(target_os = "linux")]
struct OneShotHttp {
    address: String,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl OneShotHttp {
    fn start(response: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock health server");
        let address = listener.local_addr().unwrap().to_string();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept healthcheck");
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).expect("read request");
            assert!(request[..read].starts_with(b"GET /readyz HTTP/1.1\r\n"));
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        Self {
            address,
            thread: Some(thread),
        }
    }

    fn join(mut self) {
        self.thread.take().unwrap().join().unwrap();
    }
}
