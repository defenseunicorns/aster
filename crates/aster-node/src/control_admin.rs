//! Typed live and stopped-state administration for selected mission controls.
//!
//! This facade keeps provisioning and control mutation out of the application
//! data handles. It accepts already-issued mission credentials through either
//! the explicit unprotected reference path or a caller-owned protection
//! provider, then delegates exact crash-idempotent control publication to the
//! selected runtime/store composition. It does not issue roots, expose signing
//! keys, or claim persistent provider custody or physical erasure.

use crate::{
    mission::UnprotectedReferenceMission,
    runtime::{
        CONTROL_AUTHORITY_REQUIRED, CONTROL_POLICY_UNSETTLED, CONTROL_PUBLICATION_CONFLICT,
        ControlPublicationReceipt, NodeError, absolute_path_from, absolute_state_path,
        ensure_state_accepts_normal_operation, publish_revocation_control,
        publish_scope_rekey_control,
    },
};
use aster_mesh::{
    NodeId, ProvisioningLoadId, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningUnprotector, Scope, ScopeRekeyRecipient,
};
use aster_redb_store::StoreError;
use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

/// Maximum accepted signed public-registry bytes for selected rekey requests.
pub const MAX_SELECTED_REKEY_REGISTRY_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical recipients in one selected scope-rekey request.
pub const MAX_SELECTED_REKEY_RECIPIENTS: usize = 128;
/// Maximum aggregate readable-topic grants in one selected rekey request.
pub const MAX_SELECTED_REKEY_TOPIC_GRANTS: usize = 256;

/// Stable public failure categories for selected control administration.
///
/// These categories deliberately carry no filesystem path, provider detail,
/// parser diagnostic, key identifier, or internal error source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlAdminErrorKind {
    /// A typed request violated its public bounds or canonical form.
    InvalidRequest,
    /// Protected provisioning could not be loaded or authenticated.
    Provisioning,
    /// Mission authority was absent or a relevant principal was revoked.
    UnauthorizedOrRevoked,
    /// The requested control conflicts with durable authenticated history.
    Conflict,
    /// Durable policy changed or requires bounded migration/retry.
    PolicyUnsettled,
    /// A configured bounded resource limit was reached.
    ResourceLimit,
    /// Authenticated or durable control structure was inconsistent.
    Integrity,
    /// The selected live or stopped state could not safely serve the operation.
    StateUnavailable,
}

/// Sanitized selected-control administration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlAdminError {
    operation: &'static str,
    kind: ControlAdminErrorKind,
}

impl ControlAdminError {
    const fn new(kind: ControlAdminErrorKind, operation: &'static str) -> Self {
        Self { operation, kind }
    }

    /// Stable failure category without provider or local-path detail.
    pub const fn kind(self) -> ControlAdminErrorKind {
        self.kind
    }

    /// Static public operation name associated with the failure.
    pub const fn operation(self) -> &'static str {
        self.operation
    }
}

impl fmt::Display for ControlAdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self.kind {
            ControlAdminErrorKind::InvalidRequest => "invalid request",
            ControlAdminErrorKind::Provisioning => "provisioning unavailable",
            ControlAdminErrorKind::UnauthorizedOrRevoked => "unauthorized or revoked",
            ControlAdminErrorKind::Conflict => "durable control conflict",
            ControlAdminErrorKind::PolicyUnsettled => "control policy unsettled",
            ControlAdminErrorKind::ResourceLimit => "bounded resource limit reached",
            ControlAdminErrorKind::Integrity => "control integrity failure",
            ControlAdminErrorKind::StateUnavailable => "selected state unavailable",
        };
        write!(
            formatter,
            "control administration {}: {category}",
            self.operation
        )
    }
}

impl Error for ControlAdminError {}

pub(crate) fn admin_error(operation: &'static str, error: NodeError) -> ControlAdminError {
    let kind = match error {
        NodeError::Configuration(message) if message == CONTROL_AUTHORITY_REQUIRED => {
            ControlAdminErrorKind::UnauthorizedOrRevoked
        }
        NodeError::Configuration(_) => ControlAdminErrorKind::InvalidRequest,
        NodeError::MissionProvisioning(_) => ControlAdminErrorKind::Provisioning,
        NodeError::Revoked(_) => ControlAdminErrorKind::UnauthorizedOrRevoked,
        NodeError::Protocol(message) if message == CONTROL_PUBLICATION_CONFLICT => {
            ControlAdminErrorKind::Conflict
        }
        NodeError::Protocol(message) if message == CONTROL_POLICY_UNSETTLED => {
            ControlAdminErrorKind::PolicyUnsettled
        }
        NodeError::Store(
            StoreError::ControlSignerRevoked(_)
            | StoreError::ControlAuthorityRevoked(_)
            | StoreError::ControlRecipientRevoked(_),
        ) => ControlAdminErrorKind::UnauthorizedOrRevoked,
        NodeError::Store(
            StoreError::ControlPolicyUnsettled { .. }
            | StoreError::ControlRecipientMetadataMigrationRequired { .. }
            | StoreError::ControlPolicyChanged
            | StoreError::ControlReservationChanged,
        ) => ControlAdminErrorKind::PolicyUnsettled,
        NodeError::Store(
            StoreError::ControlRollback
            | StoreError::ControlPublicationIntentUnknown { .. }
            | StoreError::ControlPublicationIntentConflict { .. },
        ) => ControlAdminErrorKind::Conflict,
        NodeError::Store(
            StoreError::ControlItemLimitExceeded { .. }
            | StoreError::ControlByteLimitExceeded { .. }
            | StoreError::ControlSequenceExhausted,
        ) => ControlAdminErrorKind::ResourceLimit,
        NodeError::SourceEnvelope(_)
        | NodeError::Store(
            StoreError::ControlVerification(_)
            | StoreError::InvalidControl(_)
            | StoreError::ControlFork
            | StoreError::ControlInvariant(_)
            | StoreError::MissingControlPublicationIntent
            | StoreError::TransferNamespaceCollision { .. },
        )
        | NodeError::Protocol(_) => ControlAdminErrorKind::Integrity,
        NodeError::Store(StoreError::InvalidControlPublicationIntent) => {
            ControlAdminErrorKind::InvalidRequest
        }
        NodeError::Identity(_)
        | NodeError::SoftwareErasure(_)
        | NodeError::Mission(_)
        | NodeError::Store(_)
        | NodeError::Reconciliation(_)
        | NodeError::Carrier(_)
        | NodeError::FatalBlobCoherence(_)
        | NodeError::EmissionPolicyChanged
        | NodeError::EmissionPolicyRestartRequired
        | NodeError::CustodySendSkipped
        | NodeError::Io(_)
        | NodeError::Demo(_) => ControlAdminErrorKind::StateUnavailable,
    };
    ControlAdminError::new(kind, operation)
}

/// Independently retained nonzero public-registry generation floor.
///
/// This witness is caller supplied; the selected store cannot prove external
/// rollback resistance by reading its own current database. Exact retries of a
/// previously committed scope/epoch are matched against the durable historical
/// publication intent before this current floor is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryGenerationWitness(NonZeroU64);

impl RegistryGenerationWitness {
    /// Binds one independently retained nonzero generation floor.
    pub const fn new(generation: NonZeroU64) -> Self {
        Self(generation)
    }

    /// Returns the witnessed generation.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for RegistryGenerationWitness {
    type Error = ControlAdminError;

    fn try_from(generation: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(generation).map(Self).ok_or_else(|| {
            ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "bind registry generation witness",
            )
        })
    }
}

/// Typed request for one authority-signed principal revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationRequest {
    subject: NodeId,
    generation: NonZeroU64,
}

impl RevocationRequest {
    /// Constructs one nonzero revocation generation.
    pub const fn new(subject: NodeId, generation: NonZeroU64) -> Self {
        Self {
            subject,
            generation,
        }
    }

    /// Principal whose previously issued authority is revoked.
    pub const fn subject(&self) -> NodeId {
        self.subject
    }

    /// Nonzero monotonic revocation generation.
    pub const fn generation(&self) -> u64 {
        self.generation.get()
    }
}

/// Typed request for one recipient-filtered scope epoch transition.
#[derive(Clone)]
pub struct ScopeRekeyRequest {
    signed_public_registry: Arc<Vec<u8>>,
    minimum_registry_generation: RegistryGenerationWitness,
    scope: Scope,
    epoch: NonZeroU64,
    recipients: Arc<Vec<ScopeRekeyRecipient>>,
}

impl ScopeRekeyRequest {
    /// Validates bounded public input before any provider, store, RNG, or
    /// signing operation is attempted.
    pub fn new(
        signed_public_registry: Vec<u8>,
        minimum_registry_generation: RegistryGenerationWitness,
        scope: Scope,
        epoch: NonZeroU64,
        recipients: Vec<ScopeRekeyRecipient>,
    ) -> Result<Self, ControlAdminError> {
        if signed_public_registry.is_empty() {
            return Err(ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "construct scope rekey request",
            ));
        }
        if signed_public_registry.len() > MAX_SELECTED_REKEY_REGISTRY_BYTES {
            return Err(ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "construct scope rekey request",
            ));
        }
        if recipients.is_empty() || recipients.len() > MAX_SELECTED_REKEY_RECIPIENTS {
            return Err(ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "construct scope rekey request",
            ));
        }
        let total_topic_grants = recipients.iter().try_fold(0usize, |total, recipient| {
            total.checked_add(recipient.readable_topics().len())
        });
        if total_topic_grants.is_none_or(|total| total > MAX_SELECTED_REKEY_TOPIC_GRANTS) {
            return Err(ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "construct scope rekey request",
            ));
        }
        let mut recipient_ids = recipients
            .iter()
            .map(ScopeRekeyRecipient::node)
            .collect::<Vec<_>>();
        recipient_ids.sort_unstable();
        if recipient_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ControlAdminError::new(
                ControlAdminErrorKind::InvalidRequest,
                "construct scope rekey request",
            ));
        }
        Ok(Self {
            signed_public_registry: Arc::new(signed_public_registry),
            minimum_registry_generation,
            scope,
            epoch,
            recipients: Arc::new(recipients),
        })
    }

    /// Exact signed public-registry artifact retained for idempotent retry.
    pub fn signed_public_registry(&self) -> &[u8] {
        self.signed_public_registry.as_slice()
    }

    /// Exact scope whose active epoch will advance.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Nonzero requested scope epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch.get()
    }

    /// Independently retained public-registry generation floor.
    pub const fn minimum_registry_generation(&self) -> RegistryGenerationWitness {
        self.minimum_registry_generation
    }

    /// Number of canonical recipient policies in this request.
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Exact canonical recipient policies retained for idempotent retry.
    pub fn recipients(&self) -> &[ScopeRekeyRecipient] {
        self.recipients.as_slice()
    }

    pub(crate) fn parts(
        &self,
    ) -> (
        &[u8],
        RegistryGenerationWitness,
        &Scope,
        NonZeroU64,
        &[ScopeRekeyRecipient],
    ) {
        (
            self.signed_public_registry.as_slice(),
            self.minimum_registry_generation,
            &self.scope,
            self.epoch,
            self.recipients.as_slice(),
        )
    }
}

impl std::fmt::Debug for ScopeRekeyRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeRekeyRequest")
            .field(
                "signed_public_registry",
                &"[SIGNED PUBLIC REGISTRY REDACTED]",
            )
            .field(
                "signed_public_registry_len",
                &self.signed_public_registry.len(),
            )
            .field(
                "minimum_registry_generation",
                &self.minimum_registry_generation,
            )
            .field("scope", &self.scope)
            .field("epoch", &self.epoch)
            .field("recipient_count", &self.recipients.len())
            .finish()
    }
}

/// Cloneable bounded live authority-control handle.
///
/// The running node owns the sole receiver and serializes these commands with
/// its normal store policy write lease. This handle exposes no application
/// data operation, raw signing primitive, provider capability, or key bytes.
/// Once a command is enqueued, cancelling or dropping the calling future does
/// not cancel the durable operation: it may still commit. Callers that lose a
/// response must retain or clone the request and retry it exactly to recover
/// its idempotent receipt. Cloning a scope-rekey request shares its bounded
/// registry and recipient buffers rather than copying them. A command that
/// revokes this node may commit and then close the live receiver; if that
/// terminal receipt is lost, recovery requires an exact retry through
/// [`SelectedControlAdmin`] after actor teardown with the retained provisioning
/// capability.
#[derive(Clone)]
pub struct SelectedControlHandle {
    commands: mpsc::Sender<SelectedControlCommand>,
    identity: NodeId,
    mission_authority: NodeId,
}

impl SelectedControlHandle {
    pub(crate) const fn new(
        commands: mpsc::Sender<SelectedControlCommand>,
        identity: NodeId,
        mission_authority: NodeId,
    ) -> Self {
        Self {
            commands,
            identity,
            mission_authority,
        }
    }

    /// Authenticated local mission principal retained by the running node.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable mission authority bound to the live store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission_authority
    }

    /// Publishes or recovers one exact crash-idempotent revocation receipt.
    ///
    /// Cancelling this future after enqueue does not cancel the command; retry
    /// the exact request to recover a receipt that may have been committed.
    /// When the request revokes the running node itself, a lost receipt must be
    /// recovered through stopped [`SelectedControlAdmin`] after actor teardown,
    /// because retained live handles close with the actor.
    pub async fn publish_revocation(
        &self,
        request: RevocationRequest,
    ) -> Result<ControlPublicationReceipt, ControlAdminError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedControlCommand::PublishRevocation { request, response },
            received,
            "publish revocation",
        )
        .await
    }

    /// Publishes or recovers one exact crash-idempotent scope-rekey receipt.
    ///
    /// Cancelling this future after enqueue does not cancel the command; retry
    /// the exact request to recover a receipt that may have been committed.
    /// Clone the request before this call when cancellation recovery is needed;
    /// its bounded registry and recipient buffers remain shared.
    pub async fn publish_scope_rekey(
        &self,
        request: ScopeRekeyRequest,
    ) -> Result<ControlPublicationReceipt, ControlAdminError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedControlCommand::PublishScopeRekey { request, response },
            received,
            "publish scope rekey",
        )
        .await
    }

    async fn send(
        &self,
        command: SelectedControlCommand,
        received: oneshot::Receiver<Result<ControlPublicationReceipt, ControlAdminError>>,
        operation: &'static str,
    ) -> Result<ControlPublicationReceipt, ControlAdminError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| control_actor_unavailable(operation))?;
        received
            .await
            .map_err(|_| control_actor_unavailable(operation))?
    }
}

fn control_actor_unavailable(operation: &'static str) -> ControlAdminError {
    ControlAdminError::new(ControlAdminErrorKind::StateUnavailable, operation)
}

pub(crate) enum SelectedControlCommand {
    PublishRevocation {
        request: RevocationRequest,
        response: oneshot::Sender<Result<ControlPublicationReceipt, ControlAdminError>>,
    },
    PublishScopeRekey {
        request: ScopeRekeyRequest,
        response: oneshot::Sender<Result<ControlPublicationReceipt, ControlAdminError>>,
    },
}

impl SelectedControlCommand {
    pub(crate) fn reject(self) {
        match self {
            Self::PublishRevocation { response, .. } => {
                let _ = response.send(Err(control_actor_unavailable("publish revocation")));
            }
            Self::PublishScopeRekey { response, .. } => {
                let _ = response.send(Err(control_actor_unavailable("publish scope rekey")));
            }
        }
    }
}

/// Exclusive stopped-state authority administration facade.
///
/// Construction performs no control mutation. Each publication acquires the
/// same process-exclusive store authority used by the selected runtime and
/// returns only after durable commit plus ordered local activation, or an exact
/// historical receipt. This object deliberately exposes no application-data
/// operation, raw signing primitive, registry issuer, or key bytes.
pub struct SelectedControlAdmin {
    state: PathBuf,
    mission: UnprotectedReferenceMission,
}

impl SelectedControlAdmin {
    /// Opens the explicit owner-only unprotected reference compatibility path.
    /// Relative state and mission paths bind to one current-directory snapshot
    /// before terminal inspection or mission-file access.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ControlAdminError> {
        let operation = "open unprotected reference";
        let path_base =
            std::env::current_dir().map_err(|error| admin_error(operation, error.into()))?;
        let state = absolute_path_from(&path_base, state.as_ref())
            .map_err(|error| admin_error(operation, error))?;
        let mission_bundle = absolute_path_from(&path_base, mission_bundle.as_ref())
            .map_err(|error| admin_error(operation, error))?;
        Self::open_with_mission(&state, operation, || {
            UnprotectedReferenceMission::load(&mission_bundle).map_err(NodeError::from)
        })
    }

    /// Authenticates one bounded protected mission artifact before retaining
    /// the recovered bundle in zeroizing process memory.
    ///
    /// Relative state and protected paths bind to one current-directory
    /// snapshot without reading the artifact.
    ///
    /// Terminal state is checked before file/provider access. The caller owns
    /// the provider identity and any persistent destroyable reference; this
    /// facade does not turn ciphertext deletion into a destruction receipt.
    pub fn open_protected<P>(
        state: impl AsRef<Path>,
        protected_mission: impl AsRef<Path>,
        unprotector: &mut P,
    ) -> Result<Self, ControlAdminError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let operation = "open protected mission";
        let path_base =
            std::env::current_dir().map_err(|error| admin_error(operation, error.into()))?;
        let state = absolute_path_from(&path_base, state.as_ref())
            .map_err(|error| admin_error(operation, error))?;
        let protected_mission = absolute_path_from(&path_base, protected_mission.as_ref())
            .map_err(|error| admin_error(operation, error))?;
        Self::open_with_mission(&state, operation, || {
            UnprotectedReferenceMission::load_protected(&protected_mission, unprotector)
                .map_err(NodeError::from)
        })
    }

    /// Authenticates one in-memory protected mission artifact after checking
    /// that the selected state root is not terminal.
    pub fn from_protected_bytes<P>(
        state: impl AsRef<Path>,
        protected_mission: &[u8],
        unprotector: &mut P,
    ) -> Result<Self, ControlAdminError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let state = state.as_ref();
        Self::open_with_mission(state, "open protected mission bytes", || {
            UnprotectedReferenceMission::from_protected_bytes(protected_mission, unprotector)
                .map_err(NodeError::from)
        })
    }

    /// Loads one provider-persisted opaque provisioning reference after the
    /// selected state root passes its terminal check.
    ///
    /// The caller retains the backend/reference capability needed for a later
    /// coordinated destroy operation. Opening this stopped admin neither
    /// destroys the provider secret nor claims that live sessions were drained.
    pub fn open_secret_ref<L>(
        state: impl AsRef<Path>,
        secret_ref: &ProvisioningSecretRef,
        operation: ProvisioningLoadId,
        loader: &mut L,
    ) -> Result<Self, ControlAdminError>
    where
        L: ProvisioningSecretLoader + ?Sized,
    {
        let state = state.as_ref();
        Self::open_with_mission(state, "open provisioning secret reference", || {
            UnprotectedReferenceMission::load_from_secret_store(secret_ref, operation, loader)
                .map_err(NodeError::from)
        })
    }

    fn open_with_mission<F>(
        state: &Path,
        operation: &'static str,
        load_mission: F,
    ) -> Result<Self, ControlAdminError>
    where
        F: FnOnce() -> Result<UnprotectedReferenceMission, NodeError>,
    {
        let state = absolute_state_path(state).map_err(|error| admin_error(operation, error))?;
        ensure_state_accepts_normal_operation(&state)
            .map_err(|error| admin_error(operation, error))?;
        let mission = load_mission().map_err(|error| admin_error(operation, error))?;
        Ok(Self { state, mission })
    }

    /// Authenticated local mission principal retained by this admin facade.
    pub const fn identity(&self) -> NodeId {
        self.mission.identity()
    }

    /// Stable mission authority bound into the retained credentials.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Publishes or recovers one exact crash-idempotent revocation receipt.
    pub fn publish_revocation(
        &self,
        request: RevocationRequest,
    ) -> Result<ControlPublicationReceipt, ControlAdminError> {
        publish_revocation_control(
            &self.state,
            &self.mission,
            request.subject(),
            request.generation(),
        )
        .map_err(|error| admin_error("publish revocation", error))
    }

    /// Publishes or recovers one exact crash-idempotent scope-rekey receipt.
    pub fn publish_scope_rekey(
        &self,
        request: ScopeRekeyRequest,
    ) -> Result<ControlPublicationReceipt, ControlAdminError> {
        let (signed_public_registry, minimum_registry_generation, scope, epoch, recipients) =
            request.parts();
        publish_scope_rekey_control(
            &self.state,
            &self.mission,
            signed_public_registry,
            minimum_registry_generation.get(),
            scope.clone(),
            epoch.get(),
            recipients.to_vec(),
        )
        .map_err(|error| admin_error("publish scope rekey", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::STORE_FILE;
    use aster_mesh::{
        ProvisioningAccess, ProvisioningLoadReceipt, ProvisioningProtectionError,
        ProvisioningSecretStoreError, ReferenceEnvelopeSealer, ReferenceProvisioner, Topic,
        UnprotectedProvisioning,
    };

    #[test]
    fn emission_policy_restart_requirement_is_closed_as_state_unavailable() {
        let error = admin_error(
            "publish revocation",
            NodeError::EmissionPolicyRestartRequired,
        );

        assert_eq!(error.kind(), ControlAdminErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "publish revocation");
        assert_eq!(
            error.to_string(),
            "control administration publish revocation: selected state unavailable"
        );
        assert!(std::error::Error::source(&error).is_none());
    }

    struct OneShotUnprotector {
        calls: usize,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningUnprotector for OneShotUnprotector {
        fn unprotect(
            &mut self,
            _protected: &[u8],
            maximum_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            let plaintext = self
                .plaintext
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)?;
            assert!(plaintext.len() <= maximum_plaintext_len);
            UnprotectedProvisioning::new(plaintext)
        }
    }

    struct ChdirUnprotector {
        calls: usize,
        destination: PathBuf,
        expected_protected: Vec<u8>,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningUnprotector for ChdirUnprotector {
        fn unprotect(
            &mut self,
            protected: &[u8],
            maximum_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            assert_eq!(protected, self.expected_protected);
            std::env::set_current_dir(&self.destination)
                .expect("provider changes the process current directory");
            let plaintext = self
                .plaintext
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)?;
            assert!(plaintext.len() <= maximum_plaintext_len);
            UnprotectedProvisioning::new(plaintext)
        }
    }

    struct ChdirPath {
        destination: PathBuf,
        relative: PathBuf,
    }

    impl AsRef<Path> for ChdirPath {
        fn as_ref(&self) -> &Path {
            std::env::set_current_dir(&self.destination)
                .expect("path callback changes the process current directory");
            &self.relative
        }
    }

    struct ChdirSecretLoader {
        calls: usize,
        destination: PathBuf,
        expected_operation: ProvisioningLoadId,
        expected_ref: ProvisioningSecretRef,
        plaintext: Option<Vec<u8>>,
    }

    impl ProvisioningSecretLoader for ChdirSecretLoader {
        fn load(
            &mut self,
            operation: ProvisioningLoadId,
            secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            assert_eq!(operation, self.expected_operation);
            assert_eq!(secret_ref, &self.expected_ref);
            std::env::set_current_dir(&self.destination)
                .expect("secret loader changes the process current directory");
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

    fn run_isolated_cwd_test(test_name: &str, body: impl FnOnce()) {
        const CHILD_ENV: &str = "ASTER_CONTROL_ADMIN_CWD_TEST_CHILD";
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
            .expect("run isolated current-directory regression child");
        assert!(
            output.status.success(),
            "isolated current-directory regression failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn authority_bundle_with_seed(seed: [u8; 32]) -> Vec<u8> {
        let scope = Scope::new("test/control-admin").expect("scope");
        let topic = Topic::new("mesh").expect("topic");
        let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed(seed).expect("provisioner");
        provisioner
            .issue_control_authority(1, &[access])
            .expect("issue control authority")
            .to_bytes()
            .expect("encode authority bundle")
    }

    fn authority_bundle() -> Vec<u8> {
        authority_bundle_with_seed([0x68; 32])
    }

    fn assert_live_control_unavailable(error: ControlAdminError, expected_operation: &'static str) {
        assert_eq!(error.kind(), ControlAdminErrorKind::StateUnavailable);
        assert_eq!(error.operation(), expected_operation);
        assert_eq!(
            error.to_string(),
            format!("control administration {expected_operation}: selected state unavailable")
        );
        assert!(error.source().is_none());
    }

    #[test]
    fn live_control_handle_retains_only_stable_identity_accessors() {
        let (sender, _receiver) = mpsc::channel(1);
        let identity = [0x81; 32];
        let mission_authority = [0x82; 32];
        let handle = SelectedControlHandle::new(sender, identity, mission_authority);

        assert_eq!(handle.identity(), identity);
        assert_eq!(handle.mission_authority(), mission_authority);
        let clone = handle.clone();
        assert_eq!(clone.identity(), identity);
        assert_eq!(clone.mission_authority(), mission_authority);
    }

    #[tokio::test]
    async fn closed_live_control_channel_returns_only_sanitized_state_unavailable() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let handle = SelectedControlHandle::new(sender, [0x83; 32], [0x84; 32]);

        let revocation = handle
            .publish_revocation(RevocationRequest::new(
                [0x85; 32],
                NonZeroU64::new(1).expect("nonzero generation"),
            ))
            .await
            .expect_err("closed command receiver must reject revocation");
        assert_live_control_unavailable(revocation, "publish revocation");

        let rekey = ScopeRekeyRequest::new(
            b"signed-registry-live-channel-canary".to_vec(),
            RegistryGenerationWitness::try_from(1).expect("nonzero witness"),
            Scope::new("test/live-control-channel").expect("scope"),
            NonZeroU64::new(1).expect("nonzero epoch"),
            vec![ScopeRekeyRecipient::route_only([0x86; 32])],
        )
        .expect("bounded rekey request");
        let rekey = handle
            .publish_scope_rekey(rekey)
            .await
            .expect_err("closed command receiver must reject scope rekey");
        assert_live_control_unavailable(rekey, "publish scope rekey");
    }

    #[tokio::test]
    async fn runtime_rejection_closes_live_control_call_with_fixed_category() {
        let (sender, mut receiver) = mpsc::channel(1);
        let handle = SelectedControlHandle::new(sender, [0x87; 32], [0x88; 32]);
        let caller = tokio::spawn(async move {
            handle
                .publish_revocation(RevocationRequest::new(
                    [0x89; 32],
                    NonZeroU64::new(1).expect("nonzero generation"),
                ))
                .await
        });

        receiver
            .recv()
            .await
            .expect("queued control command")
            .reject();
        let error = caller
            .await
            .expect("live control caller task")
            .expect_err("runtime rejection must fail closed");
        assert_live_control_unavailable(error, "publish revocation");
    }

    #[test]
    fn relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes() {
        run_isolated_cwd_test(
            "control_admin::tests::relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes",
            || {
                let original_cwd = std::env::current_dir().expect("original current directory");
                let root = std::env::temp_dir().join(format!(
                    "aster-control-admin-cwd-binding-{}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&root);
                let origin = root.join("origin");
                let callback_cwd = root.join("callback-cwd");
                std::fs::create_dir_all(&origin).expect("create original current directory");
                std::fs::create_dir_all(&callback_cwd).expect("create callback current directory");
                std::env::set_current_dir(&origin).expect("select original current directory");
                let bound_origin =
                    std::env::current_dir().expect("resolved original current directory");

                let mission_name = Path::new("mission.unprotected-reference.bundle");
                let origin_mission = authority_bundle_with_seed([0x69; 32]);
                let expected_identity =
                    UnprotectedReferenceMission::from_bytes(origin_mission.clone())
                        .expect("parse original mission fixture")
                        .identity();
                drop(
                    UnprotectedReferenceMission::persist(
                        bound_origin.join(mission_name),
                        origin_mission,
                    )
                    .expect("persist original mission fixture"),
                );
                drop(
                    UnprotectedReferenceMission::persist(
                        callback_cwd.join(mission_name),
                        authority_bundle_with_seed([0x6a; 32]),
                    )
                    .expect("persist decoy mission fixture"),
                );
                let mission = ChdirPath {
                    destination: callback_cwd.clone(),
                    relative: mission_name.to_path_buf(),
                };
                let unprotected_state = Path::new("unprotected-relative-state");
                let admin =
                    SelectedControlAdmin::open_unprotected_reference(unprotected_state, &mission)
                        .expect("open control admin after mission-path cwd change");
                assert_eq!(admin.identity(), expected_identity);
                assert_eq!(admin.state, bound_origin.join(unprotected_state));
                let receipt = admin
                    .publish_revocation(RevocationRequest::new(
                        [0x70; 32],
                        NonZeroU64::new(1).expect("nonzero generation"),
                    ))
                    .expect("publish through cwd-bound unprotected admin");
                assert!(receipt.emitted);
                assert!(
                    bound_origin
                        .join(unprotected_state)
                        .join(STORE_FILE)
                        .is_file()
                );
                assert!(!callback_cwd.join(unprotected_state).exists());
                drop(admin);

                std::env::set_current_dir(&origin)
                    .expect("restore origin before protected-path case");

                let protected_name = Path::new("mission.protected");
                let origin_protected = b"origin-provider-authenticated-envelope";
                std::fs::write(bound_origin.join(protected_name), origin_protected)
                    .expect("write original protected mission fixture");
                std::fs::write(
                    callback_cwd.join(protected_name),
                    b"decoy-provider-authenticated-envelope",
                )
                .expect("write decoy protected mission fixture");
                let protected = ChdirPath {
                    destination: callback_cwd.clone(),
                    relative: protected_name.to_path_buf(),
                };
                let protected_state = Path::new("protected-relative-state");
                let mut unprotector = ChdirUnprotector {
                    calls: 0,
                    destination: callback_cwd.clone(),
                    expected_protected: origin_protected.to_vec(),
                    plaintext: Some(authority_bundle()),
                };
                let admin = SelectedControlAdmin::open_protected(
                    protected_state,
                    &protected,
                    &mut unprotector,
                )
                .expect("open control admin after provider cwd change");
                assert_eq!(unprotector.calls, 1);
                assert_eq!(admin.state, bound_origin.join(protected_state));
                let receipt = admin
                    .publish_revocation(RevocationRequest::new(
                        [0x71; 32],
                        NonZeroU64::new(1).expect("nonzero generation"),
                    ))
                    .expect("publish through cwd-bound protected admin");
                assert!(receipt.emitted);
                assert!(
                    bound_origin
                        .join(protected_state)
                        .join(STORE_FILE)
                        .is_file()
                );
                assert!(!callback_cwd.join(protected_state).exists());
                drop(admin);

                std::env::set_current_dir(&origin)
                    .expect("restore origin before secret-loader case");
                let secret_state = Path::new("secret-relative-state");
                let operation = ProvisioningLoadId::new([0x72; 32]);
                let secret_ref =
                    ProvisioningSecretRef::from_opaque(b"cwd-bound-control-secret".to_vec())
                        .expect("secret reference");
                let mut loader = ChdirSecretLoader {
                    calls: 0,
                    destination: callback_cwd.clone(),
                    expected_operation: operation,
                    expected_ref: secret_ref.clone(),
                    plaintext: Some(authority_bundle()),
                };
                let admin = SelectedControlAdmin::open_secret_ref(
                    secret_state,
                    &secret_ref,
                    operation,
                    &mut loader,
                )
                .expect("open control admin after secret-loader cwd change");
                assert_eq!(loader.calls, 1);
                assert_eq!(admin.state, bound_origin.join(secret_state));
                let receipt = admin
                    .publish_revocation(RevocationRequest::new(
                        [0x73; 32],
                        NonZeroU64::new(1).expect("nonzero generation"),
                    ))
                    .expect("publish through cwd-bound secret admin");
                assert!(receipt.emitted);
                assert!(bound_origin.join(secret_state).join(STORE_FILE).is_file());
                assert!(!callback_cwd.join(secret_state).exists());
                drop(admin);

                std::env::set_current_dir(original_cwd)
                    .expect("restore process current directory after regression");
                std::fs::remove_dir_all(root).expect("cleanup cwd-binding regression root");
            },
        );
    }

    #[test]
    fn protected_admin_bootstrap_is_provider_once_and_state_side_effect_free() {
        let root = std::env::temp_dir().join(format!(
            "aster-protected-control-admin-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut unprotector = OneShotUnprotector {
            calls: 0,
            plaintext: Some(authority_bundle()),
        };

        let admin = SelectedControlAdmin::from_protected_bytes(
            &root,
            b"provider-authenticated-envelope",
            &mut unprotector,
        )
        .expect("open protected admin");
        assert_eq!(unprotector.calls, 1);
        assert_ne!(admin.identity(), [0; 32]);
        assert_ne!(admin.mission_authority(), [0; 32]);
        assert!(!root.exists(), "bootstrap must not create selected state");
    }

    #[test]
    fn typed_control_requests_reject_missing_external_bounds() {
        assert!(RegistryGenerationWitness::try_from(0).is_err());
        let witness = RegistryGenerationWitness::try_from(7).expect("nonzero witness");
        let scope = Scope::new("test/control-admin").expect("scope");
        let epoch = NonZeroU64::new(2).expect("nonzero epoch");
        let recipient = ScopeRekeyRecipient::route_only([0x44; 32]);

        assert!(matches!(
            ScopeRekeyRequest::new(
                Vec::new(),
                witness,
                scope.clone(),
                epoch,
                vec![recipient.clone()],
            ),
            Err(ControlAdminError {
                kind: ControlAdminErrorKind::InvalidRequest,
                ..
            })
        ));

        let maximum_topics = (0..128)
            .map(|index| Topic::new(format!("topic.{index}")).expect("topic"))
            .collect::<Vec<_>>();
        let excessive_topic_grants = vec![
            ScopeRekeyRecipient::member([0x51; 32], maximum_topics.clone()).expect("member"),
            ScopeRekeyRecipient::member([0x52; 32], maximum_topics).expect("member"),
            ScopeRekeyRecipient::member(
                [0x53; 32],
                vec![Topic::new("topic.overflow").expect("topic")],
            )
            .expect("member"),
        ];
        assert!(matches!(
            ScopeRekeyRequest::new(
                b"signed-registry".to_vec(),
                witness,
                scope.clone(),
                epoch,
                excessive_topic_grants,
            ),
            Err(ControlAdminError {
                kind: ControlAdminErrorKind::InvalidRequest,
                ..
            })
        ));
        assert!(matches!(
            ScopeRekeyRequest::new(
                b"signed-registry".to_vec(),
                witness,
                scope.clone(),
                epoch,
                Vec::new(),
            ),
            Err(ControlAdminError {
                kind: ControlAdminErrorKind::InvalidRequest,
                ..
            })
        ));

        let too_many = (0..=MAX_SELECTED_REKEY_RECIPIENTS)
            .map(|index| {
                let mut node = [0u8; 32];
                node[..8].copy_from_slice(&(index as u64).to_be_bytes());
                ScopeRekeyRecipient::route_only(node)
            })
            .collect();
        assert!(matches!(
            ScopeRekeyRequest::new(
                b"signed-registry".to_vec(),
                witness,
                scope.clone(),
                epoch,
                too_many,
            ),
            Err(ControlAdminError {
                kind: ControlAdminErrorKind::InvalidRequest,
                ..
            })
        ));
        assert!(matches!(
            ScopeRekeyRequest::new(
                b"signed-registry".to_vec(),
                witness,
                scope.clone(),
                epoch,
                vec![recipient.clone(), recipient.clone()],
            ),
            Err(ControlAdminError {
                kind: ControlAdminErrorKind::InvalidRequest,
                ..
            })
        ));

        let request = ScopeRekeyRequest::new(
            b"signed-registry-canary".to_vec(),
            witness,
            scope,
            epoch,
            vec![recipient],
        )
        .expect("bounded request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("signed-registry-canary"));
        assert_eq!(request.minimum_registry_generation().get(), 7);
        assert_eq!(request.epoch(), 2);
        assert_eq!(request.recipient_count(), 1);
    }

    #[test]
    fn public_admin_errors_are_fixed_category_and_redact_provisioning_detail() {
        let root = std::env::temp_dir().join(format!(
            "aster-control-admin-secret-path-{}",
            std::process::id()
        ));
        let secret_path = root.join("credential-name-must-not-escape");
        let error = match SelectedControlAdmin::open_unprotected_reference(&root, &secret_path) {
            Ok(_) => panic!("missing provisioning must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ControlAdminErrorKind::Provisioning);
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("credential-name-must-not-escape"));
        assert!(!debug.contains("credential-name-must-not-escape"));
        assert!(error.source().is_none());
    }

    #[test]
    fn protected_issuance_opens_selected_admin_and_replays_exact_revocation() {
        let scope = Scope::new("test/protected-admin-integration").expect("scope");
        let topic = Topic::new("mesh").expect("topic");
        let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x6b; 32]).expect("provisioner");
        let authority = provisioner
            .issue_control_authority(1, std::slice::from_ref(&access))
            .expect("issue authority");
        let member = provisioner.issue_node(2, &[access]).expect("issue member");
        let member_identity = ReferenceEnvelopeSealer::open(member)
            .expect("open member identity")
            .identity();

        let authority_bytes = authority.to_bytes().expect("encode authority bundle");
        let protected = b"provider-authenticated-control-authority";

        let state = std::env::temp_dir().join(format!(
            "aster-protected-control-admin-integration-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state);
        let mut first_unprotector = OneShotUnprotector {
            calls: 0,
            plaintext: Some(authority_bytes.clone()),
        };
        let admin =
            SelectedControlAdmin::from_protected_bytes(&state, protected, &mut first_unprotector)
                .expect("open protected authority admin");
        assert_eq!(first_unprotector.calls, 1);
        let request = RevocationRequest::new(
            member_identity,
            NonZeroU64::new(1).expect("nonzero generation"),
        );
        let first = admin
            .publish_revocation(request)
            .expect("publish protected revocation");
        assert!(first.emitted);
        drop(admin);

        let mut retry_unprotector = OneShotUnprotector {
            calls: 0,
            plaintext: Some(authority_bytes),
        };
        let reopened =
            SelectedControlAdmin::from_protected_bytes(&state, protected, &mut retry_unprotector)
                .expect("reopen protected authority admin");
        assert_eq!(retry_unprotector.calls, 1);
        let retry = reopened
            .publish_revocation(request)
            .expect("recover exact revocation receipt");
        assert!(!retry.emitted);
        assert_eq!(retry.transfer_id, first.transfer_id);
        assert_eq!(retry.sequence, first.sequence);
        drop(reopened);
        std::fs::remove_dir_all(state).expect("cleanup");
    }
}
