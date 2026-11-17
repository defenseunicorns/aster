use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

#[cfg(any(feature = "systemd-provider", test))]
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
    spawn_resolving_linux_rostered_btle_event_supervisor,
};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use aster_host::DiscoveryCredentialMaterialParts;
#[cfg(feature = "systemd-provider")]
use aster_host::{
    ActiveDiscoveryCredentialAuthority, DiscoveryCredentialArtifactProvider,
    PreparedDiscoveryCredential, TrustedClock,
};
#[cfg(feature = "sdk-test-support")]
use aster_node::RunningAutomaticEventTransportHandle;
#[cfg(any(feature = "sdk-test-support", feature = "systemd-provider"))]
use aster_node::{
    EventAdapterControl, EventAdapterSnapshot, EventAdapterState, EventAttemptReceiver,
};
#[cfg(all(feature = "systemd-provider", target_os = "linux"))]
use aster_node::{EventAdapterRegistration, EventEmissionPolicy, OrderedEventContactHandle};
use aster_node::{EventPeerEligibility, EventTransportKind, RunningNode};
#[cfg(feature = "systemd-provider")]
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

    /// Fences and publishes the adapter unavailable before authority cleanup.
    /// Owners without an availability publisher are already unavailable.
    fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        Ok(())
    }

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
    installs_peer_eligibility: bool,
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
            installs_peer_eligibility: false,
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
            installs_peer_eligibility: false,
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

    /// Retains the validated authority in an unavailable, RF-inert owner.
    #[cfg(feature = "systemd-provider")]
    pub fn radio_inert<L, C>(
        prepared: PreparedDiscoveryCredential<L, C>,
        policy: ValidatedBtlePolicy,
        state_root: &Path,
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
        let authority = prepared.retire_material();
        Ok(Self {
            policy: Some(policy),
            authority_state_root: Some(authority_state_root),
            start: Some(Box::new(move |node| {
                validate_active_authority(&authority, scope, node)?;
                let registration = node
                    .automatic_event_transports()
                    .register_paired(EventAdapterSnapshot::new(
                        EventTransportKind::BLE_L2CAP_V1,
                        0,
                        EventAdapterState::Unavailable,
                        true,
                        configured_priority,
                    ))
                    .ok_or(BtleRuntimeOwnerError::Startup)?;
                let (_, adapter, attempts) = registration.into_parts();
                let owner = unavailable_owner(adapter, attempts, ());
                Ok(Box::new(AuthorityBtleRuntimeOwner::start(
                    owner, policy, authority,
                )))
            })),
            installs_peer_eligibility: false,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        })
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
                let supervisor = spawn_resolving_linux_rostered_btle_event_supervisor(
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
                    let owner = unavailable_owner(adapter, attempts, ());
                    return Ok(Box::new(AuthorityBtleRuntimeOwner::start(
                        owner, policy, authority,
                    )));
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
                Ok(Box::new(AuthorityBtleRuntimeOwner::start(
                    supervisor, policy, authority,
                )))
            })),
            installs_peer_eligibility: true,
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
                emit_lifecycle(
                    LifecycleState::Starting,
                    "btle_availability",
                    "unqualified_package",
                    false,
                    503,
                );
                Ok(unavailable_owner(adapter, attempts, (policy, prepared)))
            })),
            installs_peer_eligibility: false,
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
            policy,
            authority_state_root: _,
            start,
            installs_peer_eligibility,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        } = self;
        let owner = start.map(|start| start(node)).transpose()?;
        let eligibility =
            policy
                .filter(|_| installs_peer_eligibility)
                .map(|policy| PendingBtleEligibility {
                    automatic: node.automatic_event_transports(),
                    entry: EventPeerEligibility::provisioned_exact_peer(
                        node.selected_events().mission_authority(),
                        policy.peer(),
                        EventTransportKind::BLE_L2CAP_V1,
                        true,
                        1,
                        0,
                        None,
                    ),
                });
        Ok(ActiveBtleRuntime::new(
            owner,
            eligibility,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        ))
    }
}

struct PendingBtleEligibility {
    automatic: aster_node::RunningAutomaticEventTransportHandle,
    entry: EventPeerEligibility,
}

impl PendingBtleEligibility {
    fn install(self) -> Result<(), BtleRuntimeOwnerError> {
        self.automatic
            .replace_eligibility(vec![self.entry])
            .map(|_| ())
            .ok_or(BtleRuntimeOwnerError::Startup)
    }
}

/// Running BTLE owner and its terminal signal, kept together so orchestration
/// cannot cancel, join, or observe one without the other.
pub(super) struct ActiveBtleRuntime {
    owner: Option<Box<dyn BtleRuntimeOwner>>,
    completion: Option<tokio::sync::watch::Receiver<bool>>,
    eligibility: Option<PendingBtleEligibility>,
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
            eligibility: None,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer: None,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer: None,
        }
    }

    fn new(
        owner: Option<Box<dyn BtleRuntimeOwner>>,
        eligibility: Option<PendingBtleEligibility>,
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
            eligibility,
            #[cfg(feature = "sdk-test-support")]
            node_shutdown_observer,
            #[cfg(feature = "sdk-test-support")]
            cleanup_retired_observer,
        }
    }

    pub(super) const fn is_present(&self) -> bool {
        self.completion.is_some()
    }

    pub(super) fn install_eligibility(&mut self) -> Result<(), BtleRuntimeOwnerError> {
        self.eligibility
            .take()
            .map(PendingBtleEligibility::install)
            .transpose()
            .map(|_| ())
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

impl Drop for ActiveBtleRuntime {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        let _ = owner.park_unavailable();
        owner.cancel();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = owner.join().await;
            });
        } else {
            std::mem::forget(owner);
        }
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

#[cfg(feature = "systemd-provider")]
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

#[cfg(feature = "systemd-provider")]
// A one-minute sample bounds detection well inside the authority's five-minute
// wall/monotonic divergence allowance without making clock reads a hot path.
const BTLE_CLOCK_CONTINUITY_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(feature = "systemd-provider")]
trait DiscoveryAuthorityContinuity: Send {
    fn resample_clock(&mut self) -> Result<(), ()>;
}

#[cfg(feature = "systemd-provider")]
impl<L, C> DiscoveryAuthorityContinuity for ActiveDiscoveryCredentialAuthority<L, C>
where
    L: DiscoveryCredentialArtifactProvider + Send,
    C: TrustedClock + Send,
{
    fn resample_clock(&mut self) -> Result<(), ()> {
        ActiveDiscoveryCredentialAuthority::resample_clock(self).map_err(|_| ())
    }
}

#[cfg(feature = "systemd-provider")]
struct AuthorityBtleRuntimeOwner {
    cancellation: tokio::sync::watch::Sender<bool>,
    completion: tokio::sync::watch::Receiver<bool>,
    supervisor: std::sync::Arc<RuntimeOwnerCustody>,
    task: Option<JoinHandle<Result<(), BtleRuntimeOwnerError>>>,
}

#[cfg(feature = "systemd-provider")]
struct RuntimeOwnerCustody(std::sync::Mutex<Option<Box<dyn BtleRuntimeOwner>>>);

#[cfg(feature = "systemd-provider")]
impl AuthorityBtleRuntimeOwner {
    fn start<A>(
        supervisor: Box<dyn BtleRuntimeOwner>,
        policy: ValidatedBtlePolicy,
        authority: A,
    ) -> Self
    where
        A: DiscoveryAuthorityContinuity + 'static,
    {
        Self::start_with_interval(
            supervisor,
            policy,
            Box::new(authority),
            BTLE_CLOCK_CONTINUITY_INTERVAL,
        )
    }

    fn start_with_interval<P>(
        supervisor: Box<dyn BtleRuntimeOwner>,
        policy: P,
        mut authority: Box<dyn DiscoveryAuthorityContinuity>,
        interval: Duration,
    ) -> Self
    where
        P: Send + 'static,
    {
        let (cancellation, mut cancellation_observer) = tokio::sync::watch::channel(false);
        let (completion_guard, completion) = tokio::sync::watch::channel(false);
        let mut supervisor_completion = supervisor.completion();
        let supervisor =
            std::sync::Arc::new(RuntimeOwnerCustody(std::sync::Mutex::new(Some(supervisor))));
        let task_supervisor = supervisor.clone();
        let task = tokio::spawn(async move {
            let _completion = RuntimeCompletionOnDrop(completion_guard);
            loop {
                tokio::select! {
                    biased;
                    () = wait_for_runtime_cancellation(&mut cancellation_observer) => {
                        let supervisor = task_supervisor.take();
                        supervisor.cancel();
                        let result = join_runtime_owner(supervisor).await;
                        drop((policy, authority));
                        return result;
                    }
                    () = wait_for_runtime_completion(&mut supervisor_completion) => {
                        let supervisor = task_supervisor.take();
                        supervisor.cancel();
                        let _ = join_runtime_owner(supervisor).await;
                        drop((policy, authority));
                        return Err(BtleRuntimeOwnerError::Cleanup);
                    }
                    () = tokio::time::sleep(interval) => {
                        if authority.resample_clock().is_ok() {
                            continue;
                        }
                        let supervisor = task_supervisor.take();
                        let publication = supervisor.park_unavailable();
                        supervisor.cancel();
                        let cleanup = join_runtime_owner(supervisor).await;
                        let parked_result = publication.and(cleanup);
                        wait_for_runtime_cancellation(&mut cancellation_observer).await;
                        drop((policy, authority));
                        return parked_result;
                    }
                }
            }
        });
        Self {
            cancellation,
            completion,
            supervisor,
            task: Some(task),
        }
    }
}

#[cfg(feature = "systemd-provider")]
impl BtleRuntimeOwner for AuthorityBtleRuntimeOwner {
    fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
        self.completion.clone()
    }

    fn cancel(&self) {
        self.supervisor.cancel();
        self.cancellation.send_replace(true);
    }

    fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        self.supervisor.park_unavailable()
    }

    fn join(mut self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
        self.cancel();
        let task = self.task.take().expect("authority monitor task retained");
        Box::pin(async move {
            drop(self);
            match task.await {
                Ok(result) => result,
                Err(_) => Err(BtleRuntimeOwnerError::Cleanup),
            }
        })
    }
}

#[cfg(feature = "systemd-provider")]
impl Drop for AuthorityBtleRuntimeOwner {
    fn drop(&mut self) {
        self.supervisor.cancel();
        self.cancellation.send_replace(true);
        if let Some(task) = self.task.take() {
            retain_runtime_task(task);
        }
    }
}

#[cfg(feature = "systemd-provider")]
impl RuntimeOwnerCustody {
    fn cancel(&self) {
        if let Some(supervisor) = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            supervisor.cancel();
        }
    }

    fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(Ok(()), |supervisor| supervisor.park_unavailable())
    }

    fn take(&self) -> Box<dyn BtleRuntimeOwner> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("authority supervisor retained")
    }
}

#[cfg(feature = "systemd-provider")]
async fn join_runtime_owner(
    supervisor: Box<dyn BtleRuntimeOwner>,
) -> Result<(), BtleRuntimeOwnerError> {
    let mut completion = supervisor.completion();
    let result = std::panic::AssertUnwindSafe(supervisor.join())
        .catch_unwind()
        .await;
    if !matches!(result, Ok(Ok(()))) {
        wait_for_runtime_completion(&mut completion).await;
    }
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(BtleRuntimeOwnerError::Cleanup),
    }
}

#[cfg(feature = "systemd-provider")]
async fn wait_for_runtime_cancellation(cancellation: &mut tokio::sync::watch::Receiver<bool>) {
    while !*cancellation.borrow_and_update() && cancellation.changed().await.is_ok() {}
}

#[cfg(feature = "systemd-provider")]
async fn wait_for_runtime_completion(completion: &mut tokio::sync::watch::Receiver<bool>) {
    while !*completion.borrow_and_update() && completion.changed().await.is_ok() {}
}

#[cfg(feature = "systemd-provider")]
struct RuntimeCompletionOnDrop(tokio::sync::watch::Sender<bool>);

#[cfg(feature = "systemd-provider")]
impl Drop for RuntimeCompletionOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

#[cfg(feature = "systemd-provider")]
fn retain_runtime_task(task: JoinHandle<Result<(), BtleRuntimeOwnerError>>) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            let _ = task.await;
        });
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

    fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        self.0
            .park_unavailable()
            .map_err(|_| BtleRuntimeOwnerError::Cleanup)
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

#[cfg(any(feature = "sdk-test-support", feature = "systemd-provider"))]
struct UnavailableBtleRuntimeOwner<P> {
    _adapter_registration: EventAdapterControl,
    _attempt_mailbox: EventAttemptReceiver,
    _completion_guard: tokio::sync::watch::Sender<bool>,
    completion: tokio::sync::watch::Receiver<bool>,
    _custody: P,
}

#[cfg(any(feature = "sdk-test-support", feature = "systemd-provider"))]
fn unavailable_owner<P>(
    adapter: EventAdapterControl,
    attempts: EventAttemptReceiver,
    custody: P,
) -> Box<dyn BtleRuntimeOwner>
where
    P: Send + 'static,
{
    let (completion_guard, completion) = tokio::sync::watch::channel(false);
    Box::new(UnavailableBtleRuntimeOwner {
        _adapter_registration: adapter,
        _attempt_mailbox: attempts,
        _completion_guard: completion_guard,
        completion,
        _custody: custody,
    })
}

#[cfg(any(feature = "sdk-test-support", feature = "systemd-provider"))]
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
            None,
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

    #[tokio::test]
    async fn dropping_active_runtime_cancels_and_retains_owner_until_cleanup_finishes() {
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
        let active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );

        drop(active);
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        assert!(!dropped.load(std::sync::atomic::Ordering::Acquire));

        release_send.send(()).expect("release actual cleanup");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop custody must retain the owner until cleanup finishes");
    }

    #[cfg(feature = "systemd-provider")]
    struct FailingContinuity {
        resampled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(feature = "systemd-provider")]
    impl DiscoveryAuthorityContinuity for FailingContinuity {
        fn resample_clock(&mut self) -> Result<(), ()> {
            self.resampled
                .store(true, std::sync::atomic::Ordering::Release);
            Err(())
        }
    }

    #[cfg(feature = "systemd-provider")]
    impl Drop for FailingContinuity {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[cfg(feature = "systemd-provider")]
    struct ImmediateRuntimeOwner {
        parked: std::sync::Arc<std::sync::atomic::AtomicBool>,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        _completion_guard: tokio::sync::watch::Sender<bool>,
        completion: tokio::sync::watch::Receiver<bool>,
    }

    #[cfg(feature = "systemd-provider")]
    impl Drop for ImmediateRuntimeOwner {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[cfg(feature = "systemd-provider")]
    impl BtleRuntimeOwner for ImmediateRuntimeOwner {
        fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
            self.completion.clone()
        }

        fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }

        fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
            self.parked
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }

        fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
            Box::pin(async move {
                drop(self);
                Ok(())
            })
        }
    }

    #[cfg(feature = "systemd-provider")]
    #[tokio::test(start_paused = true)]
    async fn clock_discontinuity_parks_unavailable_and_retains_authority_until_shutdown() {
        let resampled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let authority_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let supervisor_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (completion_guard, completion) = tokio::sync::watch::channel(false);
        let supervisor = ImmediateRuntimeOwner {
            parked: parked.clone(),
            cancelled: cancelled.clone(),
            dropped: supervisor_dropped.clone(),
            _completion_guard: completion_guard,
            completion,
        };
        let owner = AuthorityBtleRuntimeOwner::start_with_interval(
            Box::new(supervisor),
            (),
            Box::new(FailingContinuity {
                resampled: resampled.clone(),
                dropped: authority_dropped.clone(),
            }),
            BTLE_CLOCK_CONTINUITY_INTERVAL,
        );
        let mut owner_completion = owner.completion();
        tokio::task::yield_now().await;

        tokio::time::advance(BTLE_CLOCK_CONTINUITY_INTERVAL - Duration::from_secs(1)).await;
        assert!(!resampled.load(std::sync::atomic::Ordering::Acquire));
        tokio::time::advance(Duration::from_secs(1)).await;
        while !supervisor_dropped.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        assert!(resampled.load(std::sync::atomic::Ordering::Acquire));
        assert!(parked.load(std::sync::atomic::Ordering::Acquire));
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        assert!(!authority_dropped.load(std::sync::atomic::Ordering::Acquire));
        assert!(!*owner_completion.borrow_and_update());

        owner.cancel();
        Box::new(owner)
            .join()
            .await
            .expect("parked authority shutdown");
        assert!(authority_dropped.load(std::sync::atomic::Ordering::Acquire));
        assert!(*owner_completion.borrow_and_update());
    }

    #[cfg(feature = "systemd-provider")]
    #[tokio::test]
    async fn dropping_authority_wrapper_retains_authority_until_supervisor_cleanup_finishes() {
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let supervisor_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let authority_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (release_send, release_receive) = tokio::sync::oneshot::channel();
        let (_completion_send, completion) = tokio::sync::watch::channel(false);
        let supervisor = StalledCleanupOwner {
            cancelled: cancelled.clone(),
            dropped: supervisor_dropped.clone(),
            release: Some(release_receive),
            completion,
        };
        let owner = AuthorityBtleRuntimeOwner::start_with_interval(
            Box::new(supervisor),
            (),
            Box::new(FailingContinuity {
                resampled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                dropped: authority_dropped.clone(),
            }),
            BTLE_CLOCK_CONTINUITY_INTERVAL,
        );

        drop(owner);
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        assert!(!supervisor_dropped.load(std::sync::atomic::Ordering::Acquire));
        assert!(!authority_dropped.load(std::sync::atomic::Ordering::Acquire));

        release_send.send(()).expect("release supervisor cleanup");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !authority_dropped.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authority must remain in cleanup custody until supervisor exits");
        assert!(supervisor_dropped.load(std::sync::atomic::Ordering::Acquire));
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
            None,
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
