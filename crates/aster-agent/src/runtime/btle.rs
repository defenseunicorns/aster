use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
use aster_ble_linux::{
    AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH, AutomaticRosteredSupervisorConfig, ContactLimits,
    ControllerAdmissionPolicy, ControllerProbeLimits, DiscoveryCredential, DiscoveryGeneration,
    DiscoverySecret, LeasedDiscoveryCredentialSet, RING1_MAXIMUM_DEADLINE,
    RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, RosteredDiscoveryConfig,
    ValidatedAutomaticRosteredSupervisorConfig,
};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use aster_ble_linux::{
    BtleOperatorOutput, LinuxRosteredBtleEventSupervisor,
    spawn_automatic_linux_rostered_btle_event_supervisor,
};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use aster_host::{
    ActiveDiscoveryCredentialAuthority, DiscoveryCredentialArtifactProvider,
    DiscoveryCredentialMaterialParts, PreparedDiscoveryCredential, TrustedClock,
};
#[cfg(feature = "sdk-test-support")]
use aster_node::RunningAutomaticEventTransportHandle;
use aster_node::RunningNode;
#[cfg(any(
    feature = "sdk-test-support",
    all(feature = "systemd-provider", target_os = "linux")
))]
use aster_node::{
    EventAdapterControl, EventAdapterSnapshot, EventAdapterState, EventAttemptReceiver,
    EventTransportKind,
};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use aster_node::{EventAdapterRegistration, EventEmissionPolicy, OrderedEventContactHandle};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use futures::FutureExt as _;
use futures::future::BoxFuture;
use tokio::task::JoinHandle;

#[cfg(feature = "sdk-test-support")]
use super::{LifecycleState, emit_lifecycle};
use crate::config::ValidatedBtlePolicy;

/// Fixed failure categories for the BTLE-specific runtime owner.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtleRuntimeOwnerError {
    /// The owner could not be created after node startup.
    #[cfg(any(feature = "systemd-provider", feature = "sdk-test-support", test))]
    Startup,
    /// The active owner could not confirm bounded cleanup.
    Cleanup,
}

impl fmt::Display for BtleRuntimeOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BTLE runtime owner failed")
    }
}

impl Error for BtleRuntimeOwnerError {}

/// Active BTLE-specific lifecycle owned by the agent process.
///
/// Adapter availability is deliberately absent: the owner publishes it
/// through the paired node registration/control contract from
/// [`aster_node::RunningAutomaticEventTransportHandle`].
#[doc(hidden)]
pub trait BtleRuntimeOwner: Send {
    /// Returns the terminal supervisor signal. Recoverable platform and
    /// controller failures must remain in the owner and publish `Unavailable`;
    /// completion while the agent is running means the owner invariant failed.
    fn completion(&self) -> tokio::sync::watch::Receiver<bool>;

    /// Requests idempotent cancellation before joining owned platform work.
    /// This method must only signal owner-owned work and must return without
    /// blocking or performing platform I/O.
    fn cancel(&self);

    /// Consumes the owner and joins its bounded cleanup path.
    fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>>;
}

type BtleRuntimeStart = Box<
    dyn FnOnce(&RunningNode) -> Result<Box<dyn BtleRuntimeOwner>, BtleRuntimeOwnerError> + Send,
>;

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
type AutomaticLinuxSupervisorStart = Box<
    dyn FnOnce(
            ValidatedAutomaticRosteredSupervisorConfig,
            OrderedEventContactHandle,
            EventAdapterRegistration,
        ) -> Result<Box<dyn BtleRuntimeOwner>, BtleRuntimeOwnerError>
        + Send,
>;

#[cfg(feature = "sdk-test-support")]
type PreparedNodeValidation<P> =
    Box<dyn FnOnce(&P, &RunningNode) -> Result<(), BtleRuntimeOwnerError> + Send>;

/// One-shot BTLE preparation retained until the node is running.
///
/// A missing preparation means this composition does not include a BTLE
/// adapter. It is not the production hardware-availability policy: a capable
/// build starts its BTLE owner, which then reports `Unavailable` until its
/// authority, platform, and qualified hardware are all usable.
///
/// Default customer builds do not expose synthetic owner or credential-
/// injected construction:
///
/// ```compile_fail,E0308
/// use aster_agent::{
///     config::ValidatedBtlePolicy,
///     runtime::BtleRuntimeStartup,
/// };
/// use std::path::Path;
///
/// fn cannot_bypass_prepared_authority(policy: ValidatedBtlePolicy) {
///     let _ = BtleRuntimeStartup::radio_inert((), policy, Path::new("/var/lib/aster-agent"));
/// }
/// ```
#[cfg_attr(
    not(feature = "sdk-test-support"),
    doc = r#"```compile_fail
use aster_agent::runtime::BtleRuntimeOwner;
```"#
)]
#[doc(hidden)]
pub struct BtleRuntimeStartup {
    policy: Option<ValidatedBtlePolicy>,
    authority_state_root: Option<PathBuf>,
    start: Option<BtleRuntimeStart>,
    #[cfg(feature = "sdk-test-support")]
    node_shutdown_observer: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "sdk-test-support")]
    cleanup_retired_observer: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl BtleRuntimeStartup {
    /// Creates a composition with no BTLE adapter or platform access.
    pub const fn disabled() -> Self {
        Self {
            policy: None,
            authority_state_root: None,
            start: None,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        }
    }

    /// Retains one move-only prepared value and consumes it exactly once after
    /// successful node startup.
    #[cfg(feature = "sdk-test-support")]
    #[doc(hidden)]
    pub fn prepared<P, F>(policy: ValidatedBtlePolicy, prepared: P, start: F) -> Self
    where
        P: Send + 'static,
        F: FnOnce(
                P,
                RunningAutomaticEventTransportHandle,
            ) -> Result<Box<dyn BtleRuntimeOwner>, BtleRuntimeOwnerError>
            + Send
            + 'static,
    {
        Self {
            policy: Some(policy),
            authority_state_root: None,
            start: Some(Box::new(move |node| {
                start(prepared, node.automatic_event_transports())
            })),
            node_shutdown_observer: None,
            cleanup_retired_observer: None,
        }
    }

    /// Observes test shutdown ordering without adding test concerns to a
    /// transport-specific owner contract.
    #[cfg(feature = "sdk-test-support")]
    #[doc(hidden)]
    pub fn with_node_shutdown_observer(
        mut self,
        observer: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        self.node_shutdown_observer = Some(std::sync::Arc::new(observer));
        self
    }

    /// Observes that the supervisor consumed a completed cleanup task.
    #[cfg(feature = "sdk-test-support")]
    #[doc(hidden)]
    pub fn with_cleanup_retired_observer(
        mut self,
        observer: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        self.cleanup_retired_observer = Some(std::sync::Arc::new(observer));
        self
    }

    /// Composes the production automatic Linux BTLE owner.
    #[cfg(all(feature = "systemd-provider", target_os = "linux"))]
    pub fn automatic_linux<L, C>(
        prepared: PreparedDiscoveryCredential<L, C>,
        policy: ValidatedBtlePolicy,
        state_root: &Path,
    ) -> Result<Self, BtleRuntimeOwnerError>
    where
        L: DiscoveryCredentialArtifactProvider + Send + 'static,
        C: TrustedClock + Send + 'static,
    {
        Self::automatic_linux_inner(
            prepared,
            policy,
            state_root,
            Box::new(|config, contacts, registration| {
                let supervisor = spawn_automatic_linux_rostered_btle_event_supervisor(
                    config,
                    contacts,
                    registration,
                    BtleOperatorOutput::discard(),
                )
                .map_err(|_| BtleRuntimeOwnerError::Startup)?;
                Ok(Box::new(LinuxSupervisorRuntimeOwner(supervisor)))
            }),
            #[cfg(feature = "sdk-test-support")]
            None,
        )
    }

    /// Composes the production boundary with a deterministic test supervisor.
    #[cfg(all(
        feature = "sdk-test-support",
        feature = "systemd-provider",
        target_os = "linux"
    ))]
    #[doc(hidden)]
    pub fn automatic_linux_with_test_supervisor<L, C, F>(
        prepared: PreparedDiscoveryCredential<L, C>,
        policy: ValidatedBtlePolicy,
        state_root: &Path,
        start_supervisor: F,
    ) -> Result<
        (
            Self,
            tokio::sync::oneshot::Receiver<RunningAutomaticEventTransportHandle>,
        ),
        BtleRuntimeOwnerError,
    >
    where
        L: DiscoveryCredentialArtifactProvider + Send + 'static,
        C: TrustedClock + Send + 'static,
        F: FnOnce(
                ValidatedAutomaticRosteredSupervisorConfig,
                OrderedEventContactHandle,
                EventAdapterRegistration,
            ) -> Result<Box<dyn BtleRuntimeOwner>, BtleRuntimeOwnerError>
            + Send
            + 'static,
    {
        let (observe, observed) = tokio::sync::oneshot::channel();
        let startup = Self::automatic_linux_inner(
            prepared,
            policy,
            state_root,
            Box::new(start_supervisor),
            Some(observe),
        )?;
        Ok((startup, observed))
    }

    /// Creates a test-only unavailable owner plus its real selector handle.
    #[cfg(feature = "sdk-test-support")]
    #[doc(hidden)]
    pub fn radio_inert_with_test_observer<P>(
        prepared: P,
        policy: ValidatedBtlePolicy,
    ) -> (
        Self,
        tokio::sync::oneshot::Receiver<RunningAutomaticEventTransportHandle>,
    )
    where
        P: Send + 'static,
    {
        let (observe, observed) = tokio::sync::oneshot::channel();
        (
            Self::radio_inert_inner(prepared, policy, None, None, Some(observe)),
            observed,
        )
    }

    #[cfg(all(target_os = "linux", feature = "systemd-provider"))]
    fn automatic_linux_inner<L, C>(
        prepared: PreparedDiscoveryCredential<L, C>,
        policy: ValidatedBtlePolicy,
        state_root: &Path,
        start_supervisor: AutomaticLinuxSupervisorStart,
        #[cfg(feature = "sdk-test-support")] observer: Option<
            tokio::sync::oneshot::Sender<RunningAutomaticEventTransportHandle>,
        >,
    ) -> Result<Self, BtleRuntimeOwnerError>
    where
        L: DiscoveryCredentialArtifactProvider + Send + 'static,
        C: TrustedClock + Send + 'static,
    {
        let scope = *policy.deployment_scope_id();
        if !prepared
            .matches_binding(scope, state_root)
            .map_err(|_| BtleRuntimeOwnerError::Startup)?
        {
            return Err(BtleRuntimeOwnerError::Startup);
        }
        let configured_priority = policy.configured_priority();
        let authority_state_root = state_root.to_path_buf();
        Ok(Self {
            policy: Some(policy),
            authority_state_root: Some(authority_state_root),
            start: Some(Box::new(move |node| {
                let automatic = node.automatic_event_transports();
                let registration = automatic
                    .register_paired(EventAdapterSnapshot::new(
                        EventTransportKind::BLE_L2CAP_V1,
                        AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH,
                        EventAdapterState::Unavailable,
                        true,
                        configured_priority,
                    ))
                    .ok_or(BtleRuntimeOwnerError::Startup)?;
                if matches!(policy.emission_policy(), EventEmissionPolicy::ReceiveOnly) {
                    let authority = prepared.retire_material();
                    validate_active_authority(&authority, scope, node)?;
                    let (_, adapter, attempts) = registration.into_parts();
                    #[cfg(feature = "sdk-test-support")]
                    if let Some(observer) = observer {
                        let _ = observer.send(automatic);
                    }
                    let (completion_guard, completion) = tokio::sync::watch::channel(false);
                    return Ok(Box::new(UnavailableBtleRuntimeOwner {
                        _adapter_registration: adapter,
                        _attempt_mailbox: attempts,
                        _completion_guard: completion_guard,
                        completion,
                        _policy_authority: policy,
                        _authority_guard: authority,
                    }));
                }

                let (material, authority) = prepared.into_parts();
                validate_active_authority(&authority, scope, node)?;
                let credentials = adopt_discovery_credentials(material)?;
                let config = AutomaticRosteredSupervisorConfig {
                    controller_policy: ControllerAdmissionPolicy::default(),
                    controller_probe_limits: ControllerProbeLimits::new(
                        Duration::from_secs(1),
                        Duration::from_secs(2),
                        Duration::from_secs(8),
                    ),
                    discovery: RosteredDiscoveryConfig { credentials },
                    local_mission_id: node.local_mission_id(),
                    peer_mission_id: policy.peer(),
                    contact_cadence: Duration::from_secs(60),
                    contact_limits: ContactLimits {
                        maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                        maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                        open_timeout: Duration::from_secs(5),
                        operation_timeout: RING1_MAXIMUM_DEADLINE,
                    },
                }
                .validate()
                .map_err(|_| BtleRuntimeOwnerError::Startup)?;
                let supervisor =
                    start_supervisor(config, node.ordered_event_contacts(), registration)?;
                #[cfg(feature = "sdk-test-support")]
                if let Some(observer) = observer {
                    let _ = observer.send(automatic);
                }
                Ok(Box::new(AuthorityBtleRuntimeOwner {
                    supervisor,
                    _policy_authority: policy,
                    _authority_guard: authority,
                }))
            })),
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        })
    }

    #[cfg(feature = "sdk-test-support")]
    fn radio_inert_inner<P>(
        prepared: P,
        policy: ValidatedBtlePolicy,
        authority_state_root: Option<PathBuf>,
        validate: Option<PreparedNodeValidation<P>>,
        #[cfg(feature = "sdk-test-support")] observer: Option<
            tokio::sync::oneshot::Sender<RunningAutomaticEventTransportHandle>,
        >,
    ) -> Self
    where
        P: Send + 'static,
    {
        let configured_priority = policy.configured_priority();
        Self {
            policy: Some(policy),
            authority_state_root,
            start: Some(Box::new(move |node| {
                if let Some(validate) = validate {
                    validate(&prepared, node)?;
                }
                let automatic = node.automatic_event_transports();
                let registration = automatic
                    .register_paired(EventAdapterSnapshot::new(
                        EventTransportKind::BLE_L2CAP_V1,
                        0,
                        EventAdapterState::Unavailable,
                        true,
                        configured_priority,
                    ))
                    .ok_or(BtleRuntimeOwnerError::Startup)?;
                let (_, adapter, attempts) = registration.into_parts();
                #[cfg(feature = "sdk-test-support")]
                if let Some(observer) = observer {
                    let _ = observer.send(automatic);
                }
                let (completion_send, completion) = tokio::sync::watch::channel(false);
                emit_lifecycle(
                    LifecycleState::Starting,
                    "btle_availability",
                    "unqualified_package",
                    false,
                    503,
                );
                Ok(Box::new(UnavailableBtleRuntimeOwner {
                    _adapter_registration: adapter,
                    _attempt_mailbox: attempts,
                    _completion_guard: completion_send,
                    completion,
                    _policy_authority: policy,
                    _authority_guard: prepared,
                }))
            })),
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        }
    }

    pub(super) fn matches_config(
        &self,
        policy: Option<&ValidatedBtlePolicy>,
        state_root: &Path,
    ) -> bool {
        self.policy.as_ref() == policy
            && self
                .authority_state_root
                .as_deref()
                .is_none_or(|bound| bound == state_root)
    }

    #[cfg(feature = "sdk-test-support")]
    #[doc(hidden)]
    pub fn with_authority_state_root_for_test(mut self, state_root: &Path) -> Self {
        self.authority_state_root = Some(state_root.to_path_buf());
        self
    }

    pub(super) fn start(
        self,
        node: &RunningNode,
    ) -> Result<ActiveBtleRuntime, BtleRuntimeOwnerError> {
        let Self {
            policy: _,
            authority_state_root: _,
            start,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        } = self;
        let owner = start.map(|start| start(node)).transpose()?;
        Ok(ActiveBtleRuntime::new(
            owner,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        ))
    }
}

/// Running BTLE owner and its terminal signal, kept together so orchestration
/// cannot cancel, join, or observe one without the other.
pub(super) struct ActiveBtleRuntime {
    owner: Option<Box<dyn BtleRuntimeOwner>>,
    completion: Option<tokio::sync::watch::Receiver<bool>>,
    #[cfg(feature = "sdk-test-support")]
    node_shutdown_observer: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "sdk-test-support")]
    cleanup_retired_observer: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl ActiveBtleRuntime {
    pub(super) const fn absent() -> Self {
        Self {
            owner: None,
            completion: None,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        }
    }

    fn new(
        owner: Option<Box<dyn BtleRuntimeOwner>>,
        #[cfg(feature = "sdk-test-support")] node_shutdown_observer: Option<
            std::sync::Arc<dyn Fn() + Send + Sync>,
        >,
        #[cfg(feature = "sdk-test-support")] cleanup_retired_observer: Option<
            std::sync::Arc<dyn Fn() + Send + Sync>,
        >,
    ) -> Self {
        let completion = owner.as_ref().map(|owner| owner.completion());
        Self {
            owner,
            completion,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        }
    }

    pub(super) const fn is_present(&self) -> bool {
        self.completion.is_some()
    }

    pub(super) fn is_terminal(&mut self) -> bool {
        completion_is_terminal_after_read(&mut self.completion, || {})
    }

    pub(super) async fn wait_terminal(&mut self) {
        let Some(completion) = self.completion.as_mut() else {
            std::future::pending::<()>().await;
            return;
        };
        loop {
            if *completion.borrow_and_update() || completion.changed().await.is_err() {
                return;
            }
        }
    }

    pub(super) fn begin_cleanup(
        &mut self,
    ) -> Option<JoinHandle<Result<(), BtleRuntimeOwnerError>>> {
        let owner = self.owner.take()?;
        owner.cancel();
        let custody = tokio::spawn(async move { owner.join().await });
        // The inner task owns custody; the returned task is only an abortable result waiter.
        Some(tokio::spawn(async move {
            match custody.await {
                Ok(result) => result,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => Err(BtleRuntimeOwnerError::Cleanup),
            }
        }))
    }

    #[cfg(feature = "sdk-test-support")]
    pub(super) fn node_shutdown_observer(&self) -> Option<std::sync::Arc<dyn Fn() + Send + Sync>> {
        self.node_shutdown_observer.clone()
    }

    #[cfg(feature = "sdk-test-support")]
    pub(super) fn cleanup_retired_observer(
        &self,
    ) -> Option<std::sync::Arc<dyn Fn() + Send + Sync>> {
        self.cleanup_retired_observer.clone()
    }
}

pub(super) fn completion_is_terminal_after_read(
    completion: &mut Option<tokio::sync::watch::Receiver<bool>>,
    after_read: impl FnOnce(),
) -> bool {
    let Some(completion) = completion.as_mut() else {
        return false;
    };
    if *completion.borrow_and_update() {
        return true;
    }
    after_read();
    loop {
        match completion.has_changed() {
            Err(_) => return true,
            Ok(false) => return false,
            Ok(true) if *completion.borrow_and_update() => return true,
            Ok(true) => {}
        }
    }
}

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
fn validate_active_authority<L, C>(
    authority: &ActiveDiscoveryCredentialAuthority<L, C>,
    scope: [u8; 32],
    node: &RunningNode,
) -> Result<(), BtleRuntimeOwnerError>
where
    L: DiscoveryCredentialArtifactProvider,
    C: TrustedClock,
{
    if authority
        .matches_pinned_binding(scope, node.state_root())
        .map_err(|_| BtleRuntimeOwnerError::Startup)?
    {
        Ok(())
    } else {
        Err(BtleRuntimeOwnerError::Startup)
    }
}

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
fn adopt_discovery_credentials(
    material: DiscoveryCredentialMaterialParts,
) -> Result<LeasedDiscoveryCredentialSet, BtleRuntimeOwnerError> {
    let (emitting, overlap, expires_at) = material.into_adapter_parts();
    let emitting = adopt_discovery_credential(emitting)?;
    let overlap = overlap.map(adopt_discovery_credential).transpose()?;
    LeasedDiscoveryCredentialSet::new(emitting, overlap, expires_at)
        .map_err(|_| BtleRuntimeOwnerError::Startup)
}

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
fn adopt_discovery_credential(
    (generation, secret): (u32, zeroize::Zeroizing<[u8; 32]>),
) -> Result<DiscoveryCredential, BtleRuntimeOwnerError> {
    let generation =
        DiscoveryGeneration::new(generation).map_err(|_| BtleRuntimeOwnerError::Startup)?;
    let secret =
        DiscoverySecret::from_zeroizing(secret).map_err(|_| BtleRuntimeOwnerError::Startup)?;
    Ok(DiscoveryCredential::new(generation, secret))
}

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
struct AuthorityBtleRuntimeOwner<A> {
    supervisor: Box<dyn BtleRuntimeOwner>,
    _policy_authority: ValidatedBtlePolicy,
    _authority_guard: A,
}

#[cfg(all(target_os = "linux", feature = "systemd-provider"))]
impl<A> BtleRuntimeOwner for AuthorityBtleRuntimeOwner<A>
where
    A: Send + 'static,
{
    fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
        self.supervisor.completion()
    }

    fn cancel(&self) {
        self.supervisor.cancel();
    }

    fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
        Box::pin(async move {
            let Self {
                supervisor,
                _policy_authority,
                _authority_guard,
            } = *self;
            let mut completion = supervisor.completion();
            let result = std::panic::AssertUnwindSafe(supervisor.join())
                .catch_unwind()
                .await;
            if !matches!(result, Ok(Ok(()))) {
                while !*completion.borrow_and_update() {
                    if completion.changed().await.is_err() {
                        break;
                    }
                }
            }
            drop((_policy_authority, _authority_guard));
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) | Err(_) => Err(BtleRuntimeOwnerError::Cleanup),
            }
        })
    }
}

#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
struct LinuxSupervisorRuntimeOwner(LinuxRosteredBtleEventSupervisor);

#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
impl BtleRuntimeOwner for LinuxSupervisorRuntimeOwner {
    fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
        self.0.completion()
    }

    fn cancel(&self) {
        self.0.cancel();
    }

    fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
        Box::pin(async move {
            self.0
                .shutdown()
                .await
                .map_err(|_| BtleRuntimeOwnerError::Cleanup)
        })
    }
}

#[cfg(any(
    feature = "sdk-test-support",
    all(feature = "systemd-provider", target_os = "linux")
))]
struct UnavailableBtleRuntimeOwner<P> {
    _adapter_registration: EventAdapterControl,
    _attempt_mailbox: EventAttemptReceiver,
    _completion_guard: tokio::sync::watch::Sender<bool>,
    completion: tokio::sync::watch::Receiver<bool>,
    _policy_authority: ValidatedBtlePolicy,
    _authority_guard: P,
}

#[cfg(any(
    feature = "sdk-test-support",
    all(feature = "systemd-provider", target_os = "linux")
))]
impl<P> BtleRuntimeOwner for UnavailableBtleRuntimeOwner<P>
where
    P: Send + 'static,
{
    fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
        self.completion.clone()
    }

    fn cancel(&self) {}

    fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
        Box::pin(async move {
            drop(self);
            Ok(())
        })
    }
}

impl fmt::Debug for BtleRuntimeStartup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BtleRuntimeStartup")
            .field("enabled", &self.start.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", feature = "systemd-provider"))]
    #[test]
    fn automatic_btle_credential_adapter_rejects_invalid_material() {
        // Break caught: forwarding an invalid generation or all-zero secret
        // into the Linux driver would bypass fail-closed host composition.
        assert_eq!(
            adopt_discovery_credential((0, zeroize::Zeroizing::new([0x11; 32]))).unwrap_err(),
            BtleRuntimeOwnerError::Startup
        );
        assert_eq!(
            adopt_discovery_credential((7, zeroize::Zeroizing::new([0; 32]))).unwrap_err(),
            BtleRuntimeOwnerError::Startup
        );
    }

    #[test]
    fn startup_debug_does_not_expose_prepared_authority() {
        let prepared = "prepared-secret-canary".to_owned();
        let startup = BtleRuntimeStartup {
            policy: None,
            authority_state_root: None,
            start: Some(Box::new(move |_| {
                drop(prepared);
                Err(BtleRuntimeOwnerError::Startup)
            })),
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        };

        let rendered = format!("{startup:?}");
        assert_eq!(rendered, "BtleRuntimeStartup { enabled: true, .. }");
        assert!(!rendered.contains("prepared-secret-canary"));
    }

    struct StalledCleanupOwner {
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
        completion: tokio::sync::watch::Receiver<bool>,
    }

    impl Drop for StalledCleanupOwner {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl BtleRuntimeOwner for StalledCleanupOwner {
        fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
            self.completion.clone()
        }

        fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }

        fn join(mut self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
            let release = self.release.take().expect("single cleanup join");
            Box::pin(async move {
                let _owner = self;
                let _ = release.await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn cleanup_cancels_synchronously_and_waiter_abort_retains_owner() {
        // Break caught: an immediate force can abort an unpolled cleanup task,
        // skipping cancellation and dropping authority while RF work is live.
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (release_send, release_receive) = tokio::sync::oneshot::channel();
        let (_completion_send, completion) = tokio::sync::watch::channel(false);
        let owner = StalledCleanupOwner {
            cancelled: cancelled.clone(),
            dropped: dropped.clone(),
            release: Some(release_receive),
            completion,
        };
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );

        let mut waiter = active.begin_cleanup().expect("cleanup owner");
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        waiter.abort();
        let _ = (&mut waiter).await;
        assert!(!dropped.load(std::sync::atomic::Ordering::Acquire));

        release_send.send(()).expect("release actual cleanup");
        for _ in 0..16 {
            if dropped.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("owner custody was not released after actual cleanup terminated");
    }

    struct PanickingCleanupOwner {
        completion: tokio::sync::watch::Receiver<bool>,
    }

    impl BtleRuntimeOwner for PanickingCleanupOwner {
        fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
            self.completion.clone()
        }

        fn cancel(&self) {}

        fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
            Box::pin(async { panic!("fixed test cleanup panic") })
        }
    }

    #[tokio::test]
    async fn cleanup_join_panic_remains_a_task_failure() {
        // Break caught: losing the detached custody task must not convert a
        // cleanup panic into an ordinary fixed owner error.
        let (_completion_send, completion) = tokio::sync::watch::channel(false);
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(PanickingCleanupOwner { completion })),
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );

        let result = active
            .begin_cleanup()
            .expect("cleanup owner")
            .await
            .expect_err("cleanup panic must remain a task failure");
        assert!(result.is_panic());
    }
}
