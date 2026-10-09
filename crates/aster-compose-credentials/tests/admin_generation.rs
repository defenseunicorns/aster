#![cfg(target_os = "linux")]

use aster_compose_credentials::{ComposeActivation, ComposeClientToken};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const TOKEN_CANARY: &[u8] = b"compose-admin-token-canary-7f61b8\n";
const BUNDLE: &[u8] =
    include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
const FILE_NAMES: [&str; 4] = [
    "aster-client-token",
    "aster-mission-activation",
    "aster-provisioning-bundle",
    "manifest.json",
];

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    parent: PathBuf,
    token_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-compose-admin-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        let parent = root.join("generations");
        fs::create_dir(&parent).expect("create generation parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protect generation parent");
        let token_file = root.join("client-token.input");
        fs::write(&token_file, TOKEN_CANARY).expect("write token fixture");
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o400))
            .expect("protect token fixture");
        Self {
            root,
            parent,
            token_file,
        }
    }

    fn create(&self) -> Output {
        self.create_with(BUNDLE)
    }

    fn create_with(&self, bundle: &[u8]) -> Output {
        let binary = env!("CARGO_BIN_EXE_aster-compose-credential-admin");
        let arguments = [
            "create".as_bytes(),
            "--output-parent".as_bytes(),
            self.parent.as_os_str().as_encoded_bytes(),
            "--token-file".as_bytes(),
            self.token_file.as_os_str().as_encoded_bytes(),
        ];
        for argument in arguments {
            assert!(!contains(argument, TOKEN_CANARY));
            assert!(!contains(argument, BUNDLE));
        }

        let mut child = Command::new(binary)
            .args([
                "create",
                "--output-parent",
                self.parent.to_str().expect("UTF-8 fixture path"),
                "--token-file",
                self.token_file.to_str().expect("UTF-8 fixture path"),
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn admin command");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(bundle)
            .expect("write canonical bundle only on stdin");
        child.wait_with_output().expect("collect admin output")
    }

    fn generations(&self) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(&self.parent)
            .expect("read generation parent")
            .map(|entry| entry.expect("generation entry").path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for path in self.generations() {
            if path.is_dir() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("make generation removable");
            }
        }
        fs::set_permissions(&self.token_file, fs::Permissions::from_mode(0o600))
            .expect("make token fixture removable");
        fs::remove_dir_all(&self.root).expect("remove fixture");
    }
}

#[test]
fn create_publishes_exact_immutable_generation_without_secret_output() {
    // Break caught: the admin command can expose a credential, publish a
    // partial generation, or drift from the fixed provider contract.
    let fixture = Fixture::new();
    let output = fixture.create();
    assert!(output.status.success(), "stderr={:?}", output.stderr);
    assert!(output.stderr.is_empty());
    assert!(!contains(&output.stdout, TOKEN_CANARY));
    assert!(!contains(&output.stdout, BUNDLE));

    let stdout = std::str::from_utf8(&output.stdout).expect("UTF-8 success output");
    let generation = stdout
        .strip_prefix("CREATE disposition=created generation=")
        .and_then(|value| value.strip_suffix('\n'))
        .expect("exact success schema");
    assert_lower_hex_64(generation);

    let generations = fixture.generations();
    assert_eq!(generations.len(), 1);
    let directory = &generations[0];
    assert_eq!(
        directory.file_name().and_then(|name| name.to_str()),
        Some(format!("generation-{generation}").as_str())
    );
    let directory_metadata = directory.metadata().expect("generation metadata");
    assert_eq!(directory_metadata.mode() & 0o7777, 0o500);
    assert_eq!(
        directory_metadata.uid(),
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(
        directory_metadata.gid(),
        rustix::process::getegid().as_raw()
    );

    let entries = sorted_names(directory);
    assert_eq!(entries, FILE_NAMES);
    for name in &FILE_NAMES {
        let metadata = directory.join(name).metadata().expect("secret metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o400, "file {name}");
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.gid(), rustix::process::getegid().as_raw());
        assert_eq!(metadata.nlink(), 1);
    }
    let activation = fs::read(directory.join("aster-mission-activation")).expect("activation");
    let envelope = fs::read(directory.join("aster-provisioning-bundle")).expect("envelope");
    assert_eq!(&activation[..8], b"ASTRCSAC");
    assert_eq!(&envelope[..8], b"ASTRCSEN");
    let activation = ComposeActivation::from_bytes(&activation).expect("parse activation");
    let token_envelope = fs::read(directory.join("aster-client-token")).expect("token envelope");
    assert_eq!(&token_envelope[..8], b"ASTRCSTK");
    let token = ComposeClientToken::from_bytes(&token_envelope).expect("parse token envelope");
    assert_eq!(hex(token.generation().as_bytes()), generation);
    assert_eq!(
        token
            .into_token_for_activation(&activation)
            .expect("token generation binding")
            .as_slice(),
        &TOKEN_CANARY[..TOKEN_CANARY.len() - 1]
    );

    let manifest_bytes = fs::read(directory.join("manifest.json")).expect("manifest");
    assert!(!contains(&manifest_bytes, TOKEN_CANARY));
    assert!(!contains(&manifest_bytes, BUNDLE));
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
    assert_manifest(&manifest, generation, directory);
}

#[test]
fn creating_a_fresh_generation_never_changes_an_existing_generation() {
    // Break caught: a later create can mutate or replace an already-published
    // immutable generation instead of adding a fresh sibling.
    let fixture = Fixture::new();
    let first = fixture.create();
    assert!(first.status.success(), "stderr={:?}", first.stderr);
    let first_directory = fixture.generations().pop().expect("first generation");
    let before = snapshot(&first_directory);

    let second = fixture.create();
    assert!(second.status.success(), "stderr={:?}", second.stderr);
    let generations = fixture.generations();
    assert_eq!(generations.len(), 2);
    assert_eq!(snapshot(&first_directory), before);
    assert_ne!(first.stdout, second.stdout);
    assert!(generations.iter().all(|path| {
        !path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".staging-")
    }));
}

#[test]
fn rejected_inputs_emit_only_fixed_redacted_errors_and_create_no_stage() {
    // Break caught: parser and protected-file failures can include dynamic
    // paths, OS messages, or credential bytes in public diagnostics.
    let fixture = Fixture::new();
    let malformed_bundle = b"malformed-bundle-canary-42";
    let output = fixture.create_with(malformed_bundle);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"ERROR credential bundle is invalid\n");
    assert!(!contains(&output.stderr, TOKEN_CANARY));
    assert!(!contains(&output.stderr, malformed_bundle));
    assert!(fixture.generations().is_empty());

    fs::set_permissions(&fixture.token_file, fs::Permissions::from_mode(0o644))
        .expect("make token presentation invalid");
    let output = fixture.create();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"ERROR credential input is invalid\n");
    assert!(!contains(&output.stderr, TOKEN_CANARY));
    assert!(!contains(&output.stderr, BUNDLE));
    assert!(fixture.generations().is_empty());
}

fn assert_manifest(manifest: &Value, generation: &str, directory: &Path) {
    let object = manifest.as_object().expect("manifest object");
    let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "created_at_unix_seconds",
            "created_at_utc",
            "files",
            "generation",
            "provider_contract",
            "schema",
        ]
    );
    assert_eq!(manifest["schema"], "aster-compose-secret-generation/v1");
    assert_eq!(
        manifest["provider_contract"],
        "aster-compose-secret-store/v1"
    );
    assert_eq!(manifest["generation"], generation);
    assert!(manifest["created_at_unix_seconds"].as_u64().unwrap() > 0);
    let utc = manifest["created_at_utc"].as_str().expect("UTC string");
    assert_eq!(utc.len(), 20);
    assert!(utc.ends_with('Z'));

    let files = manifest["files"].as_object().expect("files object");
    assert_eq!(files.len(), 3);
    for name in &FILE_NAMES[..3] {
        let evidence = files.get(*name).expect("file evidence");
        let evidence_keys = evidence
            .as_object()
            .expect("file evidence object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(evidence_keys, ["sha256", "size"]);
        let bytes = fs::read(directory.join(name)).expect("generation file");
        assert_eq!(evidence["size"], bytes.len() as u64);
        assert_eq!(evidence["sha256"], hex(&Sha256::digest(&bytes)));
    }
}

fn snapshot(directory: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    FILE_NAMES
        .iter()
        .map(|name| {
            let path = directory.join(name);
            let mode = path.metadata().expect("snapshot metadata").mode() & 0o7777;
            let bytes = fs::read(path).expect("snapshot bytes");
            ((*name).to_owned(), (mode, bytes))
        })
        .collect()
}

fn sorted_names(directory: &Path) -> Vec<String> {
    let mut names = fs::read_dir(directory)
        .expect("read generation")
        .map(|entry| {
            entry
                .expect("generation entry")
                .file_name()
                .into_string()
                .expect("UTF-8 generation entry")
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_lower_hex_64(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
