use std::{
    fs::{self, File, Metadata},
    io::Read as _,
    net::SocketAddr,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
    process::ExitCode,
    time::Duration,
};

use aster_agent::config::load_and_validate_compose_config;
use aster_agent::proto::aster::application::v1alpha1 as api;
use aster_compose_credentials::{ComposeClientToken, ComposeCredentialGeneration};
use connectrpc::client::{ClientConfig, HttpClient};
use serde::Deserialize;
use zeroize::Zeroize as _;

const MANIFEST_PATH: &str = "/run/aster-generation/manifest.json";
const CONFIG_PATH: &str = "/etc/aster/agent.json";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    provider_contract: String,
    generation: String,
    #[serde(rename = "created_at_utc")]
    _created_at_utc: String,
    #[serde(rename = "created_at_unix_seconds")]
    _created_at_unix_seconds: u64,
    #[serde(rename = "files")]
    _files: serde_json::Map<String, serde_json::Value>,
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return fail("verification runtime failed"),
    };
    match runtime.block_on(verify()) {
        Ok(()) => {
            println!("VERIFY status=pass");
            ExitCode::SUCCESS
        }
        Err(message) => fail(message),
    }
}

fn fail(message: &'static str) -> ExitCode {
    eprintln!("ERROR {message}");
    ExitCode::FAILURE
}

async fn verify() -> Result<(), &'static str> {
    if !rustix::process::geteuid().is_root() {
        // The positive branch is intentional: verification must be non-root.
    } else {
        return Err("verification identity is invalid");
    }
    let generation = read_manifest_generation()?;
    let token = ComposeClientToken::from_fixed_file()
        .map_err(|_| "verification input is unavailable")?
        .into_token_for_generation(generation)
        .map_err(|_| "verification generation does not match")?;
    let address = read_application_address_from(Path::new(CONFIG_PATH))?;
    verify_status(address, STATUS_TIMEOUT, &token, generation).await
}

fn read_application_address_from(path: &Path) -> Result<SocketAddr, &'static str> {
    load_and_validate_compose_config(path)
        .map(|config| config.runtime().application())
        .map_err(|_| "verification configuration failed")
}

async fn verify_status(
    address: SocketAddr,
    timeout: Duration,
    token: &[u8],
    generation: ComposeCredentialGeneration,
) -> Result<(), &'static str> {
    if !address.ip().is_loopback() {
        return Err("verification configuration failed");
    }
    let mut authorization = String::from("Bearer ");
    authorization
        .push_str(std::str::from_utf8(token).map_err(|_| "verification input is invalid")?);
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(
            format!("http://{address}")
                .parse()
                .map_err(|_| "verification configuration failed")?,
        )
        .with_default_timeout(timeout)
        .with_default_header("authorization", &authorization),
    );
    authorization.zeroize();
    let response: api::GetStatusResponse = client
        .get_status(api::GetStatusRequest::default())
        .await
        .map_err(|_| "authenticated status request failed")?
        .into_owned();
    if response.credential_generation.as_slice() != generation.as_bytes() {
        return Err("status generation does not match");
    }
    Ok(())
}

fn read_manifest_generation() -> Result<ComposeCredentialGeneration, &'static str> {
    read_manifest_generation_from(Path::new(MANIFEST_PATH))
}

fn read_manifest_generation_from(path: &Path) -> Result<ComposeCredentialGeneration, &'static str> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "verification input is unavailable")?;
    let before = file
        .metadata()
        .map_err(|_| "verification input is unavailable")?;
    if !before.is_file() {
        return Err("verification input is invalid");
    }
    let encoded = read_stable_manifest_bytes(&mut file, &before)?;
    let manifest: Manifest =
        serde_json::from_slice(&encoded).map_err(|_| "verification input is invalid")?;
    if manifest.schema != "aster-compose-secret-generation/v1"
        || manifest.provider_contract != aster_compose_credentials::PROVIDER_CONTRACT
    {
        return Err("verification input is invalid");
    }
    let bytes = decode_generation(&manifest.generation)?;
    let generation = ComposeCredentialGeneration::new(bytes);
    if generation.as_bytes().iter().all(|byte| *byte == 0) {
        return Err("verification input is invalid");
    }
    Ok(generation)
}

fn read_stable_manifest_bytes(file: &mut File, before: &Metadata) -> Result<Vec<u8>, &'static str> {
    let mut encoded = Vec::with_capacity(MAX_MANIFEST_BYTES.min(before.len() as usize) + 1);
    file.take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| "verification input is invalid")?;
    if encoded.len() > MAX_MANIFEST_BYTES {
        return Err("verification input is invalid");
    }
    let after = file
        .metadata()
        .map_err(|_| "verification input is invalid")?;
    if !same_manifest_metadata(before, &after) {
        return Err("verification input is invalid");
    }
    Ok(encoded)
}

fn same_manifest_metadata(before: &Metadata, after: &Metadata) -> bool {
    before.is_file()
        && after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn decode_generation(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("verification input is invalid");
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(bytes)
}

fn nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("verification input is invalid"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    const GENERATION: [u8; 32] = [0x42; 32];
    const TOKEN: &[u8] = b"verifier-test-token-000000000001";

    #[test]
    fn manifest_reader_rejects_max_plus_one_bytes() {
        // Break caught: trusting only pre-read metadata can parse a manifest
        // that grows beyond the bound after opening.
        let fixture = Fixture::new();
        let path = fixture.root.join("manifest.json");
        let mut oversized = manifest(GENERATION);
        oversized.resize(MAX_MANIFEST_BYTES + 1, b' ');
        fs::write(&path, oversized).unwrap();
        assert_eq!(
            read_manifest_generation_from(&path),
            Err("verification input is invalid")
        );
    }

    #[test]
    fn manifest_reader_rejects_descriptor_metadata_change() {
        // Break caught: parsing bytes after the opened file changes can bind
        // verification to a moving operator comparison value.
        let fixture = Fixture::new();
        let path = fixture.root.join("manifest.json");
        fs::write(&path, manifest(GENERATION)).unwrap();
        let mut file = File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        assert_eq!(
            read_stable_manifest_bytes(&mut file, &before),
            Err("verification input is invalid")
        );
    }

    #[test]
    fn application_address_comes_from_compose_config() {
        // Break caught: retaining the former fixed 127.0.0.1:8181 endpoint
        // verifies the wrong socket after an operator changes application.listen.
        let fixture = Fixture::new();
        let path = fixture.root.join("agent.json");
        fs::write(&path, compose_config("127.0.0.1:42831", "127.0.0.1:42832")).unwrap();
        assert_eq!(
            read_application_address_from(&path),
            Ok("127.0.0.1:42831".parse().unwrap())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_status_accepts_only_the_selected_generation() {
        // Break caught: omitting the bearer token or accepting another status
        // generation would let verification attest the wrong agent instance.
        let matching = StatusPeer::reply(GENERATION, TOKEN, Duration::ZERO);
        assert_eq!(
            verify_status(
                matching.address,
                Duration::from_secs(1),
                TOKEN,
                ComposeCredentialGeneration::new(GENERATION),
            )
            .await,
            Ok(())
        );
        matching.join();

        let different = [0x43; 32];
        let mismatched = StatusPeer::reply(different, TOKEN, Duration::ZERO);
        assert_eq!(
            verify_status(
                mismatched.address,
                Duration::from_secs(1),
                TOKEN,
                ComposeCredentialGeneration::new(GENERATION),
            )
            .await,
            Err("status generation does not match")
        );
        mismatched.join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_request_is_bounded_and_loopback_only() {
        // Break caught: a verifier that can leave the shared agent namespace
        // or wait indefinitely weakens the service-network boundary.
        let stalled = StatusPeer::reply(GENERATION, TOKEN, Duration::from_millis(250));
        let started = Instant::now();
        assert_eq!(
            verify_status(
                stalled.address,
                Duration::from_millis(25),
                TOKEN,
                ComposeCredentialGeneration::new(GENERATION),
            )
            .await,
            Err("authenticated status request failed")
        );
        assert!(started.elapsed() < Duration::from_millis(200));
        stalled.join();

        assert_eq!(
            verify_status(
                "192.0.2.1:8181".parse().unwrap(),
                Duration::from_millis(25),
                TOKEN,
                ComposeCredentialGeneration::new(GENERATION),
            )
            .await,
            Err("verification configuration failed")
        );
    }

    fn manifest(generation: [u8; 32]) -> Vec<u8> {
        format!(
            "{{\"schema\":\"aster-compose-secret-generation/v1\",\
             \"provider_contract\":\"{}\",\
             \"generation\":\"{}\",\
             \"created_at_utc\":\"2026-10-08T00:00:00Z\",\
             \"created_at_unix_seconds\":1791417600,\"files\":{{}}}}",
            aster_compose_credentials::PROVIDER_CONTRACT,
            generation
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
        .into_bytes()
    }

    fn compose_config(application: &str, health: &str) -> String {
        format!(
            r#"{{"schema_version":2,"state":{{"directory":"/var/lib/aster"}},"application":{{"listen":"{application}"}},"health":{{"listen":"{health}"}},"mesh":{{"bind":"127.0.0.1:42833","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#
        )
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-compose-verifier-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct StatusPeer {
        address: SocketAddr,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl StatusPeer {
        fn reply(generation: [u8; 32], token: &'static [u8], delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let thread = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).unwrap();
                    assert_ne!(read, 0);
                    request.extend_from_slice(&chunk[..read]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(
                    "POST /aster.application.v1alpha1.AsterApplicationService/GetStatus "
                ));
                assert!(request.contains(&format!(
                    "authorization: Bearer {}\r\n",
                    std::str::from_utf8(token).unwrap()
                )));
                thread::sleep(delay);
                let body = connectrpc::codec::encode_proto(&api::GetStatusResponse {
                    credential_generation: generation.to_vec(),
                    ..Default::default()
                })
                .unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
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
}
