use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

#[cfg(feature = "systemd-provider")]
use aster_host::{
    ActiveDiscoveryCredentialAuthority, DiscoveryCredentialArtifactProvider,
    PreparedDiscoveryCredential, TrustedClock,
};
#[cfg(feature = "sdk-test-support")]
use aster_node::RunningAutomaticEventTransportHandle;
use aster_node::RunningNode;
#[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
use aster_node::{
    EventAdapterControl, EventAdapterSnapshot, EventAdapterState, EventAttemptReceiver,
    EventTransportKind,
};
use futures::future::BoxFuture;
use tokio::task::JoinHandle;

#[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
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
    #[cfg(any(feature = "sdk-test-support", test))]
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

#[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
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

    /// Validates the prepared credential's policy/state binding, immediately
    /// retires its unused key material, and retains exclusive authority custody
    /// in a radio-inert owner. This is the only enabled profile until qualified
    /// automatic controller selection and confinement are composed.
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
        if !prepared
            .matches_binding(*policy.deployment_scope_id(), state_root)
            .map_err(|_| BtleRuntimeOwnerError::Startup)?
        {
            return Err(BtleRuntimeOwnerError::Startup);
        }
        let scope = *policy.deployment_scope_id();
        let authority = prepared.retire_material();
        let validate: PreparedNodeValidation<ActiveDiscoveryCredentialAuthority<L, C>> =
            Box::new(move |authority, node| {
                if authority
                    .matches_pinned_binding(scope, node.state_root())
                    .map_err(|_| BtleRuntimeOwnerError::Startup)?
                {
                    Ok(())
                } else {
                    Err(BtleRuntimeOwnerError::Startup)
                }
            });
        Ok(Self::radio_inert_inner(
            authority,
            policy,
            Some(state_root.to_path_buf()),
            Some(validate),
            #[cfg(feature = "sdk-test-support")]
            None,
        ))
    }

    /// Creates the exact production radio-inert owner plus its real selector
    /// handle for integration observation.
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

    #[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
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
                Ok(Box::new(RadioInertBtleRuntimeOwner {
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
        Some(tokio::spawn(async move {
            owner.cancel();
            owner.join().await
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

#[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
struct RadioInertBtleRuntimeOwner<P> {
    _adapter_registration: EventAdapterControl,
    _attempt_mailbox: EventAttemptReceiver,
    _completion_guard: tokio::sync::watch::Sender<bool>,
    completion: tokio::sync::watch::Receiver<bool>,
    _policy_authority: ValidatedBtlePolicy,
    _authority_guard: P,
}

#[cfg(any(feature = "systemd-provider", feature = "sdk-test-support"))]
impl<P> BtleRuntimeOwner for RadioInertBtleRuntimeOwner<P>
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
}
