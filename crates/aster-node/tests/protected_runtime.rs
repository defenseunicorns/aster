use std::{
    error::Error as _,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aster_iroh::{ExpectedPeer, SecretKey};
use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningAccess, ProvisioningLoadId,
    ProvisioningLoadReceipt, ProvisioningProtectionError, ProvisioningSecretLoader,
    ProvisioningSecretRef, ProvisioningSecretStoreError, ProvisioningUnprotector,
    ReferenceProvisioner, Scope, Topic, UnprotectedProvisioning,
};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{
    MissionExpectedPeer, MissionProvisioningOrigin, MutableSourceInterests, NodeApplication,
    NodeBootstrapError, NodeBootstrapErrorKind, NodeConfig, NodeConfigOptions, NodeError,
    SourceInterestSelector, start_node,
};
use aster_profile::ItemId;
use aster_redb_store::{Store, ZeroizationIntent};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        assert!(
            label.len() <= 48
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "test-root label must be a short safe path component"
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after the Unix epoch")
            .as_nanos();
        let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let component = format!(
            "aster-protected-runtime-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        );
        assert!(component.len() <= 160, "test-root component is bounded");
        let path = std::env::temp_dir().join(component);
        fs::create_dir(&path).expect("create unique protected-runtime test root");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn canonical_mission_bytes() -> Vec<u8> {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES
        .get_or_init(|| {
            let scope = Scope::new("test/protected-runtime").expect("test scope");
            let topic = Topic::new("bootstrap").expect("test topic");
            let access =
                ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("test access");
            let mut provisioner =
                ReferenceProvisioner::from_seed([0x47; 32]).expect("test provisioner");
            provisioner
                .issue_node(1, &[access])
                .expect("issue test mission")
                .to_bytes()
                .expect("encode test mission")
        })
        .clone()
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn valid_options() -> NodeConfigOptions {
    NodeConfigOptions::new(loopback(0), Duration::from_millis(37))
}

fn bootstrap_error(result: Result<NodeConfig, NodeBootstrapError>) -> NodeBootstrapError {
    match result {
        Ok(_) => panic!("protected bootstrap unexpectedly succeeded"),
        Err(error) => error,
    }
}

struct RecordingUnprotector {
    calls: usize,
    seen_protected: Option<Vec<u8>>,
    seen_max_plaintext_len: Option<usize>,
    plaintext: Option<Vec<u8>>,
    failure: Option<ProvisioningProtectionError>,
}

impl RecordingUnprotector {
    fn succeeding(plaintext: Vec<u8>) -> Self {
        Self {
            calls: 0,
            seen_protected: None,
            seen_max_plaintext_len: None,
            plaintext: Some(plaintext),
            failure: None,
        }
    }

    fn rejecting() -> Self {
        Self {
            calls: 0,
            seen_protected: None,
            seen_max_plaintext_len: None,
            plaintext: None,
            failure: Some(ProvisioningProtectionError::Rejected),
        }
    }
}

impl ProvisioningUnprotector for RecordingUnprotector {
    fn unprotect(
        &mut self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
        self.calls += 1;
        self.seen_protected = Some(protected.to_vec());
        self.seen_max_plaintext_len = Some(max_plaintext_len);
        if let Some(error) = self.failure {
            return Err(error);
        }
        UnprotectedProvisioning::new(
            self.plaintext
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)?,
        )
    }
}

struct RecordingSecretLoader {
    calls: usize,
    seen_operation: Option<ProvisioningLoadId>,
    seen_secret_ref: Option<ProvisioningSecretRef>,
    returned_operation: ProvisioningLoadId,
    returned_secret_ref: ProvisioningSecretRef,
    plaintext: Option<Vec<u8>>,
}

#[derive(Default)]
struct RejectingSecretLoader {
    calls: usize,
}

impl ProvisioningSecretLoader for RejectingSecretLoader {
    fn load(
        &mut self,
        _operation: ProvisioningLoadId,
        _secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        Err(ProvisioningSecretStoreError::Rejected)
    }
}

impl RecordingSecretLoader {
    fn new(
        returned_operation: ProvisioningLoadId,
        returned_secret_ref: ProvisioningSecretRef,
        plaintext: Vec<u8>,
    ) -> Self {
        Self {
            calls: 0,
            seen_operation: None,
            seen_secret_ref: None,
            returned_operation,
            returned_secret_ref,
            plaintext: Some(plaintext),
        }
    }
}

impl ProvisioningSecretLoader for RecordingSecretLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        self.seen_operation = Some(operation);
        self.seen_secret_ref = Some(secret_ref.clone());
        let plaintext = UnprotectedProvisioning::new(
            self.plaintext
                .take()
                .ok_or(ProvisioningSecretStoreError::Unavailable)?,
        )
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
        Ok(ProvisioningLoadReceipt::new(
            self.returned_operation,
            self.returned_secret_ref.clone(),
            plaintext,
        ))
    }
}

struct CurrentDirGuard(PathBuf);

impl CurrentDirGuard {
    fn capture() -> Self {
        Self(std::env::current_dir().expect("capture original current directory"))
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).expect("restore original current directory");
    }
}

fn run_isolated_cwd_test(test_name: &str, body: impl FnOnce()) {
    const CHILD_ENV: &str = "ASTER_PROTECTED_RUNTIME_CWD_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).as_deref() == Some(std::ffi::OsStr::new(test_name)) {
        body();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_ENV, test_name)
        .output()
        .expect("run isolated protected-runtime current-directory regression child");
    assert!(
        output.status.success(),
        "isolated protected-runtime current-directory regression failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

struct ChdirPath {
    destination: PathBuf,
    relative: PathBuf,
}

impl AsRef<Path> for ChdirPath {
    fn as_ref(&self) -> &Path {
        std::env::set_current_dir(&self.destination)
            .expect("state-path callback changes current directory");
        &self.relative
    }
}

struct ChdirUnprotector {
    calls: usize,
    destination: PathBuf,
    plaintext: Option<Vec<u8>>,
}

impl ProvisioningUnprotector for ChdirUnprotector {
    fn unprotect(
        &mut self,
        _protected: &[u8],
        _max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
        self.calls += 1;
        std::env::set_current_dir(&self.destination)
            .expect("protection provider changes current directory");
        UnprotectedProvisioning::new(
            self.plaintext
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)?,
        )
    }
}

struct ChdirSecretLoader {
    calls: usize,
    destination: PathBuf,
    plaintext: Option<Vec<u8>>,
}

impl ProvisioningSecretLoader for ChdirSecretLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        std::env::set_current_dir(&self.destination)
            .expect("secret loader changes current directory");
        let plaintext = UnprotectedProvisioning::new(
            self.plaintext
                .take()
                .ok_or(ProvisioningSecretStoreError::Unavailable)?,
        )
        .map_err(|_| ProvisioningSecretStoreError::Rejected)?;
        Ok(ProvisioningLoadReceipt::new(
            operation,
            secret_ref.clone(),
            plaintext,
        ))
    }
}

#[test]
fn protected_bytes_preserve_exact_options_and_origin_without_creating_state() {
    let root = TestRoot::new("valid-bytes");
    let state = root.path().join("selected-state");
    let protected: &[u8] = b"authenticated-provider-envelope";
    let bind = loopback(38_411);
    let peers = vec![MissionExpectedPeer {
        carrier: ExpectedPeer {
            id: SecretKey::from_bytes(&[0x59; 32]).public(),
            address: loopback(38_412),
        },
        mission: [0xa4; 32],
    }];
    let interests = MutableSourceInterests::new(
        vec![SourceInterestSelector::new(
            Topic::new("state-bootstrap").expect("state topic"),
            Scope::new("test/protected-runtime/state").expect("state scope"),
            true,
        )],
        vec![SourceInterestSelector::new(
            Topic::new("record-bootstrap").expect("record topic"),
            Scope::new("test/protected-runtime/record").expect("record scope"),
            false,
        )],
    )
    .with_blob(vec![SourceInterestSelector::new(
        Topic::new("blob-bootstrap").expect("blob topic"),
        Scope::new("test/protected-runtime/blob").expect("blob scope"),
        false,
    )]);
    let sync_interval = Duration::from_millis(73);
    let run_for = Some(Duration::from_secs(11));
    let application = NodeApplication::PongResponder;
    let options = NodeConfigOptions::new(bind, sync_interval)
        .with_peers(peers.clone())
        .with_mutable_interests(interests.clone())
        .with_run_for(run_for)
        .with_application(application);
    let mut provider = RecordingUnprotector::succeeding(canonical_mission_bytes());

    let config = NodeConfig::from_protected_bytes(&state, protected, options, &mut provider)
        .expect("valid provider-protected mission config");

    assert_eq!(provider.calls, 1);
    assert_eq!(provider.seen_protected.as_deref(), Some(protected));
    assert_eq!(
        provider.seen_max_plaintext_len,
        Some(MAX_UNPROTECTED_PROVISIONING_BYTES)
    );
    assert_eq!(config.state, state);
    assert_eq!(config.bind, bind);
    assert_eq!(config.peers, peers);
    assert_eq!(config.mutable_interests, interests);
    assert_eq!(config.sync_interval, sync_interval);
    assert_eq!(config.run_for, run_for);
    assert_eq!(config.application, application);
    assert_eq!(
        config.provisioning_origin(),
        MissionProvisioningOrigin::ProtectedArtifact
    );
    assert!(config.mission.persistent_secret_ref().is_none());
    assert!(!state.exists(), "config construction must not create state");
}

#[test]
fn protected_artifact_invokes_provider_once_without_creating_state() {
    let root = TestRoot::new("valid-artifact");
    let state = root.path().join("selected-state");
    let artifact = root.path().join("mission.protected");
    let protected = b"authenticated-provider-file-envelope";
    fs::write(&artifact, protected).expect("write protected artifact fixture");
    let mut provider = RecordingUnprotector::succeeding(canonical_mission_bytes());

    let config = NodeConfig::open_protected(&state, &artifact, valid_options(), &mut provider)
        .expect("valid provider-protected mission artifact config");

    assert_eq!(provider.calls, 1);
    assert_eq!(
        provider.seen_protected.as_deref(),
        Some(protected.as_slice())
    );
    assert_eq!(
        provider.seen_max_plaintext_len,
        Some(MAX_UNPROTECTED_PROVISIONING_BYTES)
    );
    assert_eq!(config.state, state);
    assert_eq!(
        config.provisioning_origin(),
        MissionProvisioningOrigin::ProtectedArtifact
    );
    assert!(artifact.is_file());
    assert!(!state.exists(), "config construction must not create state");
}

#[test]
fn relative_state_is_bound_before_path_provider_and_loader_cwd_callbacks() {
    run_isolated_cwd_test(
        "relative_state_is_bound_before_path_provider_and_loader_cwd_callbacks",
        || {
            let root = TestRoot::new("relative-state-cwd");
            let _cwd_guard = CurrentDirGuard::capture();
            let origin = root.path().join("origin");
            let callback_cwd = root.path().join("callback-cwd");
            fs::create_dir(&origin).expect("create origin current directory");
            fs::create_dir(&callback_cwd).expect("create callback current directory");
            std::env::set_current_dir(&origin).expect("select origin current directory");
            let bound_origin = std::env::current_dir().expect("resolve origin current directory");

            let protected_relative = PathBuf::from("protected-relative-state");
            let protected_path = ChdirPath {
                destination: callback_cwd.clone(),
                relative: protected_relative.clone(),
            };
            let mut provider = ChdirUnprotector {
                calls: 0,
                destination: callback_cwd.clone(),
                plaintext: Some(canonical_mission_bytes()),
            };
            let protected_config = NodeConfig::from_protected_bytes(
                protected_path,
                b"authenticated-provider-envelope",
                valid_options(),
                &mut provider,
            )
            .expect("open protected bytes across cwd-changing callbacks");
            assert_eq!(provider.calls, 1);
            assert_eq!(
                protected_config.state,
                bound_origin.join(&protected_relative)
            );
            assert!(!bound_origin.join(&protected_relative).exists());
            assert!(!callback_cwd.join(&protected_relative).exists());

            std::env::set_current_dir(&origin).expect("restore origin before secret-load case");
            let secret_relative = PathBuf::from("secret-relative-state");
            let secret_path = ChdirPath {
                destination: callback_cwd.clone(),
                relative: secret_relative.clone(),
            };
            let operation = ProvisioningLoadId::new([0x75; 32]);
            let secret_ref =
                ProvisioningSecretRef::from_opaque(b"cwd-bound-secret-reference".to_vec())
                    .expect("cwd test secret reference");
            let mut loader = ChdirSecretLoader {
                calls: 0,
                destination: callback_cwd.clone(),
                plaintext: Some(canonical_mission_bytes()),
            };
            let secret_config = NodeConfig::open_secret_ref(
                secret_path,
                &secret_ref,
                operation,
                valid_options(),
                &mut loader,
            )
            .expect("open secret reference across cwd-changing callbacks");
            assert_eq!(loader.calls, 1);
            assert_eq!(secret_config.state, bound_origin.join(&secret_relative));
            assert!(!bound_origin.join(&secret_relative).exists());
            assert!(!callback_cwd.join(&secret_relative).exists());
        },
    );
}

#[test]
fn invalid_protected_options_do_not_invoke_provider_or_create_state() {
    let root = TestRoot::new("invalid-options");
    let protected = b"authenticated-provider-envelope";

    let zero_state = root.path().join("zero-sync-state");
    let mut zero_provider = RecordingUnprotector::succeeding(canonical_mission_bytes());
    let zero_error = bootstrap_error(NodeConfig::from_protected_bytes(
        &zero_state,
        protected,
        NodeConfigOptions::new(loopback(0), Duration::ZERO),
        &mut zero_provider,
    ));
    assert_eq!(
        zero_error.kind(),
        NodeBootstrapErrorKind::InvalidConfiguration
    );
    assert_eq!(zero_provider.calls, 0);
    assert!(zero_provider.seen_protected.is_none());
    assert!(!zero_state.exists());

    let duration_state = root.path().join("duration-max-state");
    let mut duration_provider = RecordingUnprotector::succeeding(canonical_mission_bytes());
    let duration_error = bootstrap_error(NodeConfig::from_protected_bytes(
        &duration_state,
        protected,
        valid_options().with_run_for(Some(Duration::MAX)),
        &mut duration_provider,
    ));
    assert_eq!(
        duration_error.kind(),
        NodeBootstrapErrorKind::InvalidConfiguration
    );
    assert_eq!(duration_provider.calls, 0);
    assert!(duration_provider.seen_protected.is_none());
    assert!(!duration_state.exists());
}

#[cfg(unix)]
#[test]
fn uninspectable_state_fails_before_provider_invocation() {
    let root = TestRoot::new("uninspectable-state");
    let non_directory = root.path().join("not-a-directory");
    fs::write(&non_directory, b"ordinary file").expect("write non-directory state ancestor");
    let state = non_directory.join("selected-state");
    let mut provider = RecordingUnprotector::succeeding(canonical_mission_bytes());

    let error = bootstrap_error(NodeConfig::from_protected_bytes(
        &state,
        b"authenticated-provider-envelope",
        valid_options(),
        &mut provider,
    ));

    assert_eq!(error.kind(), NodeBootstrapErrorKind::StateUnavailable);
    assert_eq!(provider.calls, 0);
    assert!(provider.seen_protected.is_none());
    assert!(non_directory.is_file());
}

#[test]
fn terminal_state_precedes_protected_provider_and_secret_loader_without_mutation() {
    let root = TestRoot::new("terminal-state");
    let state = root.path().join("selected-state");
    fs::create_dir(&state).expect("create terminal state root");
    let mission_bytes = canonical_mission_bytes();
    let mission = UnprotectedReferenceMission::from_bytes(mission_bytes.clone())
        .expect("parse terminal-state mission");
    let store_path = state.join("mesh.redb");
    let mut store = Store::open_for_mission(&store_path, mission.mission_authority_id())
        .expect("open terminal-state store");
    store
        .begin_zeroization(
            &ZeroizationIntent::new(
                b"protected-runtime-mission-artifact".to_vec(),
                b"protected-runtime-carrier-identity".to_vec(),
            )
            .expect("terminal-state intent"),
        )
        .expect("begin terminal state");
    drop(store);
    let before = fs::read(&store_path).expect("read terminal store before bootstrap attempts");

    let missing_artifact = root.path().join("must-not-be-read.protected");
    let mut provider = RecordingUnprotector::succeeding(mission_bytes.clone());
    let protected_error = bootstrap_error(NodeConfig::open_protected(
        &state,
        &missing_artifact,
        valid_options(),
        &mut provider,
    ));
    assert_eq!(
        protected_error.kind(),
        NodeBootstrapErrorKind::StateUnavailable
    );
    assert_eq!(provider.calls, 0);
    assert!(!missing_artifact.exists());

    let operation = ProvisioningLoadId::new([0x76; 32]);
    let secret_ref = ProvisioningSecretRef::from_opaque(b"terminal-secret-reference".to_vec())
        .expect("terminal secret reference");
    let mut loader = RecordingSecretLoader::new(operation, secret_ref.clone(), mission_bytes);
    let secret_error = bootstrap_error(NodeConfig::open_secret_ref(
        &state,
        &secret_ref,
        operation,
        valid_options(),
        &mut loader,
    ));
    assert_eq!(
        secret_error.kind(),
        NodeBootstrapErrorKind::StateUnavailable
    );
    assert_eq!(loader.calls, 0);
    assert_eq!(
        fs::read(&store_path).expect("read terminal store after bootstrap attempts"),
        before,
        "terminal preflight must not mutate the selected store"
    );
}

#[test]
fn rejected_secret_loader_precedes_repair_required_store_recovery() {
    const CHILD_STORE_ENV: &str = "ASTER_PROTECTED_RUNTIME_REPAIR_STORE";
    if let Some(store_path) = std::env::var_os(CHILD_STORE_ENV) {
        let mission = UnprotectedReferenceMission::from_bytes(canonical_mission_bytes())
            .expect("parse repair-child mission");
        let store = Store::open_for_mission(store_path, mission.mission_authority_id())
            .expect("open repair-child store");
        store
            .apply(
                ItemId::new([0x91; 32]),
                b"committed before abrupt protected bootstrap",
            )
            .expect("commit repair-child row");
        std::process::exit(86);
    }

    let root = TestRoot::new("repair-before-rejection");
    let state = root.path().join("selected-state");
    fs::create_dir(&state).expect("create repair-required state root");
    let store_path = state.join("mesh.redb");
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("--exact")
        .arg("rejected_secret_loader_precedes_repair_required_store_recovery")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_STORE_ENV, &store_path)
        .output()
        .expect("run abrupt protected-runtime store child");
    assert_eq!(
        output.status.code(),
        Some(86),
        "abrupt child failed unexpectedly: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(matches!(
        Store::inspect_zeroization_state(&store_path),
        Err(ref error) if error.is_read_only_repair_required()
    ));
    let before = fs::read(&store_path).expect("read repair-required store before rejection");

    let operation = ProvisioningLoadId::new([0x92; 32]);
    let secret_ref = ProvisioningSecretRef::from_opaque(b"repair-secret-reference".to_vec())
        .expect("repair secret reference");
    let mut loader = RejectingSecretLoader::default();
    let error = bootstrap_error(NodeConfig::open_secret_ref(
        &state,
        &secret_ref,
        operation,
        valid_options(),
        &mut loader,
    ));

    assert_eq!(error.kind(), NodeBootstrapErrorKind::Rejected);
    assert_eq!(loader.calls, 1);
    let after = fs::read(&store_path).expect("read repair-required store after rejection");
    assert!(
        after == before,
        "provider rejection must leave repair-required state byte-for-byte unchanged"
    );
    assert!(matches!(
        Store::inspect_zeroization_state(&store_path),
        Err(ref error) if error.is_read_only_repair_required()
    ));
}

#[test]
fn raw_canonical_bundle_never_reaches_protected_provider() {
    let root = TestRoot::new("raw-canonical");
    let state = root.path().join("selected-state");
    let canonical = canonical_mission_bytes();
    assert!(canonical.starts_with(b"ASTRPB03"));
    let mut provider = RecordingUnprotector::succeeding(canonical.clone());

    let error = bootstrap_error(NodeConfig::from_protected_bytes(
        &state,
        &canonical,
        valid_options(),
        &mut provider,
    ));

    assert_eq!(error.kind(), NodeBootstrapErrorKind::Rejected);
    assert_eq!(provider.calls, 0);
    assert!(provider.seen_protected.is_none());
    assert!(!state.exists());
}

#[test]
fn protected_rejection_is_sanitized_and_source_free() {
    const PROTECTED_CANARY: &str = "protected-envelope-canary-do-not-log";
    const STATE_CANARY: &str = "state-path-canary-do-not-log";

    let root = TestRoot::new("sanitized-rejection");
    let state = root.path().join(STATE_CANARY);
    let mut provider = RecordingUnprotector::rejecting();
    let error = bootstrap_error(NodeConfig::from_protected_bytes(
        &state,
        PROTECTED_CANARY.as_bytes(),
        valid_options(),
        &mut provider,
    ));

    assert_eq!(provider.calls, 1);
    assert_eq!(error.operation(), "open protected mission bytes");
    assert_eq!(error.kind(), NodeBootstrapErrorKind::Rejected);
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert_eq!(
        display,
        "node bootstrap open protected mission bytes: protected provisioning rejected"
    );
    assert_eq!(
        debug,
        "NodeBootstrapError { operation: \"open protected mission bytes\", kind: Rejected }"
    );
    for output in [&display, &debug] {
        assert!(!output.contains(PROTECTED_CANARY));
        assert!(!output.contains(STATE_CANARY));
    }
    assert!(error.source().is_none());
    assert!(!state.exists());
}

#[test]
fn missing_protected_artifact_fails_before_provider_or_state_creation() {
    const ARTIFACT_CANARY: &str = "missing-artifact-canary-do-not-log.protected";

    let root = TestRoot::new("missing-artifact");
    let state = root.path().join("selected-state");
    let artifact = root.path().join(ARTIFACT_CANARY);
    let mut provider = RecordingUnprotector::succeeding(canonical_mission_bytes());
    let error = bootstrap_error(NodeConfig::open_protected(
        &state,
        &artifact,
        valid_options(),
        &mut provider,
    ));

    assert_eq!(error.operation(), "open protected mission");
    assert_eq!(error.kind(), NodeBootstrapErrorKind::ArtifactUnavailable);
    assert_eq!(provider.calls, 0);
    assert!(!error.to_string().contains(ARTIFACT_CANARY));
    assert!(!format!("{error:?}").contains(ARTIFACT_CANARY));
    assert!(error.source().is_none());
    assert!(!artifact.exists());
    assert!(!state.exists());
}

#[test]
fn secret_loader_receives_exact_request_and_preserves_secret_origin() {
    let root = TestRoot::new("exact-secret-load");
    let state = root.path().join("selected-state");
    let operation = ProvisioningLoadId::new([0x71; 32]);
    let secret_ref = ProvisioningSecretRef::from_opaque(b"exact-secret-reference".to_vec())
        .expect("test secret reference");
    let mut loader =
        RecordingSecretLoader::new(operation, secret_ref.clone(), canonical_mission_bytes());

    let config =
        NodeConfig::open_secret_ref(&state, &secret_ref, operation, valid_options(), &mut loader)
            .expect("exact secret-load receipt");

    assert_eq!(loader.calls, 1);
    assert_eq!(loader.seen_operation, Some(operation));
    assert_eq!(loader.seen_secret_ref.as_ref(), Some(&secret_ref));
    assert_eq!(
        config.provisioning_origin(),
        MissionProvisioningOrigin::SecretReference
    );
    assert_eq!(config.mission.persistent_secret_ref(), Some(&secret_ref));
    assert!(!state.exists());
}

#[test]
fn secret_loader_rejects_mismatched_receipt_echoes_without_state_creation() {
    let root = TestRoot::new("mismatched-secret-load");
    let operation = ProvisioningLoadId::new([0x81; 32]);
    let secret_ref = ProvisioningSecretRef::from_opaque(
        b"requested-secret-reference-canary-do-not-log".to_vec(),
    )
    .expect("requested secret reference");
    let other_ref =
        ProvisioningSecretRef::from_opaque(b"returned-secret-reference-canary-do-not-log".to_vec())
            .expect("other secret reference");
    let mismatches = [
        (ProvisioningLoadId::new([0x82; 32]), secret_ref.clone()),
        (operation, other_ref),
    ];

    for (index, (returned_operation, returned_ref)) in mismatches.into_iter().enumerate() {
        let state = root.path().join(format!("selected-state-{index}"));
        let mut loader =
            RecordingSecretLoader::new(returned_operation, returned_ref, canonical_mission_bytes());
        let error = bootstrap_error(NodeConfig::open_secret_ref(
            &state,
            &secret_ref,
            operation,
            valid_options(),
            &mut loader,
        ));

        assert_eq!(loader.calls, 1);
        assert_eq!(loader.seen_operation, Some(operation));
        assert_eq!(loader.seen_secret_ref.as_ref(), Some(&secret_ref));
        assert_eq!(error.kind(), NodeBootstrapErrorKind::Rejected);
        assert!(
            !error
                .to_string()
                .contains("requested-secret-reference-canary-do-not-log")
        );
        assert!(!format!("{error:?}").contains("returned-secret-reference-canary-do-not-log"));
        assert!(error.source().is_none());
        assert!(!state.exists());
    }
}

#[test]
fn protected_state_witness_rejects_mutation_before_state_creation() {
    let root = TestRoot::new("state-witness");
    let checked_state = root.path().join("checked-state");
    let mutated_state = root.path().join("mutated-state");
    let mut provider = RecordingUnprotector::succeeding(canonical_mission_bytes());
    let mut config = NodeConfig::from_protected_bytes(
        &checked_state,
        b"authenticated-provider-envelope",
        valid_options(),
        &mut provider,
    )
    .expect("construct state-bound protected config");
    assert_eq!(provider.calls, 1);
    assert!(!checked_state.exists());
    config.state = mutated_state.clone();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build witness test runtime");
    let error = match runtime.block_on(start_node(config)) {
        Ok(running) => {
            drop(running);
            panic!("mutated protected config unexpectedly started")
        }
        Err(error) => error,
    };

    match error {
        NodeError::Configuration(message) => assert_eq!(
            message,
            "protected mission credentials are bound to another state root"
        ),
        other => panic!("unexpected mutated-state error: {other}"),
    }
    assert!(!checked_state.exists());
    assert!(
        !mutated_state.exists(),
        "state witness must reject before state directory creation"
    );
}
