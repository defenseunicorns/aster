#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use aster_agent::{
    config::{check_config, load_and_validate_config},
    credentials::{load_startup_credentials, open_node_config},
};
use aster_mesh::{
    ProvisioningLoadId, ProvisioningLoadReceipt, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[test]
fn config_check_validates_files_without_a_provider_and_bootstrap_uses_exact_reference() {
    // Break caught: configuration checking that skips credential-file safety
    // accepts an unsafe provider capability; bootstrap that substitutes a
    // reference or operation directs the provider to the wrong secret.
    let fixture = CustomerFixture::new();
    let expected_reference = fixture.reference();
    let expected_operation = ProvisioningLoadId::new([0x11; 32]);
    let mut loader = RecordingLoader::new();

    check_config(fixture.config_path()).expect("valid customer configuration");
    assert_eq!(loader.calls(), 0);

    fixture.chmod_reference(0o640);
    assert!(check_config(fixture.config_path()).is_err());
    assert_eq!(loader.calls(), 0);
    fixture.chmod_reference(0o600);

    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    open_node_config(&config, &credentials, &mut loader).expect("protected node config");
    assert_eq!(loader.calls(), 1);
    assert_eq!(loader.last_reference(), Some(&expected_reference));
    assert_eq!(loader.last_operation(), Some(expected_operation));
}

#[test]
fn bootstrap_failure_redacts_the_provider_reference() {
    // Break caught: forwarding provider detail or the opaque reference from a
    // failed bootstrap would expose a customer credential in diagnostics.
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let mut loader = RejectingLoader;

    let error = open_node_config(&config, &credentials, &mut loader)
        .expect_err("provider rejection must not become a node configuration");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error.kind(), aster_node::NodeBootstrapErrorKind::Rejected);
    assert!(!rendered.contains("customer-provider-capability"));
    assert!(!rendered.contains(&fixture.mission_reference.display().to_string()));
}

struct CustomerFixture {
    root: PathBuf,
    config: PathBuf,
    mission_reference: PathBuf,
    reference: ProvisioningSecretRef,
}

impl CustomerFixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "aster-agent-customer-runtime-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect fixture root");

        let token = root.join("client-token");
        fs::write(&token, b"0123456789abcdef0123456789abcdef\n").expect("write token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("protect token");

        let mission_reference = root.join("mission-reference");
        let reference =
            ProvisioningSecretRef::from_opaque(b"customer-provider-capability".to_vec())
                .expect("valid reference");
        fs::write(&mission_reference, reference.to_bytes()).expect("write reference");
        fs::set_permissions(&mission_reference, fs::Permissions::from_mode(0o600))
            .expect("protect reference");

        let config = root.join("agent.json");
        fs::write(
            &config,
            format!(
                r#"{{"schema_version":1,"state":{{"directory":"{}"}},"application":{{"listen":"127.0.0.1:8181"}},"health":{{"listen":"127.0.0.1:8182"}},"mesh":{{"bind":"127.0.0.1:0","sync_interval_ms":500,"peers":[]}},"credentials":{{"client_token_file":"{}","mission_secret_ref_file":"{}","mission_load_id":"{}"}},"storage":{{"max_items":4161,"max_payload_bytes":17891328}}}}"#,
                root.join("state").display(),
                token.display(),
                mission_reference.display(),
                "11".repeat(32),
            ),
        )
        .expect("write customer configuration");

        Self {
            root,
            config,
            mission_reference,
            reference,
        }
    }

    fn config_path(&self) -> &Path {
        &self.config
    }

    fn reference(&self) -> ProvisioningSecretRef {
        self.reference.clone()
    }

    fn chmod_reference(&self, mode: u32) {
        fs::set_permissions(&self.mission_reference, fs::Permissions::from_mode(mode))
            .expect("change reference permissions");
    }
}

impl Drop for CustomerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RecordingLoader {
    calls: usize,
    operation: Option<ProvisioningLoadId>,
    reference: Option<ProvisioningSecretRef>,
}

impl RecordingLoader {
    fn new() -> Self {
        Self {
            calls: 0,
            operation: None,
            reference: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls
    }

    fn last_operation(&self) -> Option<ProvisioningLoadId> {
        self.operation
    }

    fn last_reference(&self) -> Option<&ProvisioningSecretRef> {
        self.reference.as_ref()
    }
}

impl ProvisioningSecretLoader for RecordingLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        self.operation = Some(operation);
        self.reference = Some(reference.clone());
        let bundle =
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
        Ok(ProvisioningLoadReceipt::new(
            operation,
            reference.clone(),
            UnprotectedProvisioning::new(bundle.to_vec())
                .expect("bounded disposable public test provisioning"),
        ))
    }
}

struct RejectingLoader;

impl ProvisioningSecretLoader for RejectingLoader {
    fn load(
        &mut self,
        _operation: ProvisioningLoadId,
        _reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        Err(ProvisioningSecretStoreError::Rejected)
    }
}
