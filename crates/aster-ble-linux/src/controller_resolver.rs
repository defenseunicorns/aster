use crate::{
    BtleOperatorEvent, BtleOperatorOutput, ControllerAdmissionPolicy, ControllerCandidate,
    ControllerFingerprint, ControllerProbeLimits, ControllerSnapshot, DriverError, DriverErrorKind,
    LifecycleCancellation, ProbeDisposition, ProbeReason, SupportTag,
    controller::{
        AdapterSignal, BluezBackend, BluezFailure, BluezSession, ProductionBluez, SessionSignal,
        SessionStream,
    },
    controller_probe::{BluezControllerProbeBackend, probe_controller},
    controller_selection::{MAX_CONTROLLER_CANDIDATES, normalize_controller_inventory},
    policy::{CappedBackoff, LifecycleCancellationObserver},
};
use bluer::{Address, AddressType};
use futures::{FutureExt, Stream, StreamExt, stream::SelectAll};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout},
};

pub(crate) const INITIAL_RESOLVER_RETRY: Duration = Duration::from_millis(250);
const MAXIMUM_RESOLVER_RETRY: Duration = Duration::from_secs(30);
const MAX_EVENTS_PER_BATCH: usize = 128;

type ResolverFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ResolverFailure>> + Send + 'a>>;
type ResolverEventFuture<'a> = Pin<Box<dyn Future<Output = Option<ResolverEvent>> + Send + 'a>>;
type ResolverProbeFuture<'a> = Pin<Box<dyn Future<Output = ProbeDisposition> + Send + 'a>>;
type NamedAdapterStream = Pin<Box<dyn Stream<Item = (String, Option<AdapterSignal>)> + Send>>;
pub(crate) type OperationalEpochFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Borrowed exact controller epoch offered synchronously to operational activation.
pub(crate) struct ControllerEpochView<'a> {
    adapter_name: &'a str,
    address: Address,
    address_type: AddressType,
    inventory_generation: u64,
    cancellation: LifecycleCancellationObserver,
}

impl ControllerEpochView<'_> {
    pub(crate) const fn adapter_name(&self) -> &str {
        self.adapter_name
    }

    pub(crate) const fn address(&self) -> Address {
        self.address
    }

    pub(crate) const fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub(crate) const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub(crate) fn cancellation(&self) -> LifecycleCancellationObserver {
        self.cancellation.clone()
    }
}

/// Capacity-one operational state reported by one selected controller epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationalEpochState {
    Starting,
    Available,
    Unavailable,
}

pub(crate) trait OperationalControllerEpoch: Send {
    fn status(&self) -> watch::Receiver<OperationalEpochState>;
    fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>>;
    fn cancel(&self);
    fn join(self: Box<Self>) -> OperationalEpochFuture<'static, Result<(), DriverError>>;
}

pub(crate) trait ControllerEpochActivator: Send + Sync {
    fn activate(
        &self,
        epoch: ControllerEpochView<'_>,
    ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError>;
}

/// Runtime state of automatic Linux controller resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAvailability {
    /// No controller epoch is currently usable.
    Unavailable,
    /// The selected epoch's listener, advertisement, and scan owners are running;
    /// adapter availability was accepted before this resolver state was published.
    Available,
}

/// Redacted automatic-controller status safe for selector and operator surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerResolutionSnapshot {
    availability: RuntimeAvailability,
    disposition: ProbeDisposition,
    support: Option<SupportTag>,
}

impl ControllerResolutionSnapshot {
    const fn initial() -> Self {
        Self {
            availability: RuntimeAvailability::Unavailable,
            disposition: ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable),
            support: None,
        }
    }

    const fn unavailable(disposition: ProbeDisposition, support: Option<SupportTag>) -> Self {
        Self {
            availability: RuntimeAvailability::Unavailable,
            disposition,
            support,
        }
    }

    const fn available(support: SupportTag) -> Self {
        Self {
            availability: RuntimeAvailability::Available,
            disposition: ProbeDisposition::Compatible,
            support: Some(support),
        }
    }

    /// Coarse runtime availability without controller identity.
    pub const fn availability(self) -> RuntimeAvailability {
        self.availability
    }

    /// Last closed compatibility or policy result.
    pub const fn disposition(self) -> ProbeDisposition {
        self.disposition
    }

    /// Support evidence tag when one candidate was evaluated.
    pub const fn support(self) -> Option<SupportTag> {
        self.support
    }
}

/// Single-owner controller epoch authority retained only by the resolver actor.
pub(crate) struct ControllerEpochOwner {
    candidate: ControllerCandidate,
    fingerprint: ControllerFingerprint,
    support: SupportTag,
    inventory_generation: u64,
    cancellation: LifecycleCancellation,
}

impl ControllerEpochOwner {
    fn new(controller: ObservedController, support: SupportTag, inventory_generation: u64) -> Self {
        Self {
            candidate: controller.candidate,
            fingerprint: controller.fingerprint,
            support,
            inventory_generation,
            cancellation: LifecycleCancellation::new(),
        }
    }

    fn matches(&self, controller: &ObservedController) -> bool {
        self.candidate == controller.candidate && self.fingerprint == controller.fingerprint
    }

    fn name(&self) -> &str {
        self.candidate.name()
    }

    fn view(&self) -> Result<ControllerEpochView<'_>, DriverError> {
        let address = self.candidate.address().ok_or_else(|| {
            DriverError::new(
                DriverErrorKind::Unavailable,
                "selected controller has no exact address snapshot",
            )
        })?;
        let address_type = self.candidate.address_type().ok_or_else(|| {
            DriverError::new(
                DriverErrorKind::Unavailable,
                "selected controller has no exact address type snapshot",
            )
        })?;
        Ok(ControllerEpochView {
            adapter_name: self.candidate.name(),
            address,
            address_type,
            inventory_generation: self.inventory_generation,
            cancellation: self.cancellation.observer(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn candidate(&self) -> &ControllerCandidate {
        &self.candidate
    }

    #[allow(dead_code)]
    pub(crate) fn fingerprint(&self) -> &ControllerFingerprint {
        &self.fingerprint
    }

    #[allow(dead_code)]
    pub(crate) const fn support(&self) -> SupportTag {
        self.support
    }

    #[allow(dead_code)]
    pub(crate) const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    #[allow(dead_code)]
    pub(crate) fn cancellation(&self) -> &LifecycleCancellation {
        &self.cancellation
    }
}

impl Drop for ControllerEpochOwner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Owned automatic Linux controller resolver lifecycle.
pub struct LinuxControllerResolver {
    status: watch::Receiver<ControllerResolutionSnapshot>,
    cancellation: LifecycleCancellation,
    output: BtleOperatorOutput,
    task: Option<JoinHandle<Result<(), DriverError>>>,
}

impl LinuxControllerResolver {
    /// Returns a redacted receiver for automatic controller status.
    pub fn status(&self) -> watch::Receiver<ControllerResolutionSnapshot> {
        self.status.clone()
    }

    /// Requests idempotent cancellation of all resolver work.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Cancels and joins the serialized probe actor and its controller epoch.
    pub async fn shutdown(self) -> Result<(), DriverError> {
        self.shutdown_with_stop_event(true).await
    }

    pub(crate) async fn shutdown_for_supervisor(self) -> Result<(), DriverError> {
        self.shutdown_with_stop_event(false).await
    }

    async fn shutdown_with_stop_event(mut self, emit_stop: bool) -> Result<(), DriverError> {
        self.cancel();
        let task_result = self.task.as_mut().expect("resolver task retained").await;
        let _ = self.task.take();
        task_result.map_err(|_| {
            DriverError::new(
                DriverErrorKind::Transport,
                "automatic controller resolver task stopped",
            )
        })??;
        if emit_stop {
            self.output.emit(BtleOperatorEvent::Stopped);
        }
        Ok(())
    }
}

impl Drop for LinuxControllerResolver {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Starts the production automatic Linux controller resolver.
pub fn spawn_linux_controller_resolver(
    policy: ControllerAdmissionPolicy,
    limits: ControllerProbeLimits,
    output: BtleOperatorOutput,
) -> LinuxControllerResolver {
    spawn_resolver(
        policy,
        limits,
        output,
        Arc::new(BluezResolverPlatform::new(Arc::new(ProductionBluez))),
        Arc::new(ProductionResolverProbe),
        None,
        None,
    )
}

pub(crate) fn spawn_linux_controller_resolver_with_activation(
    policy: ControllerAdmissionPolicy,
    limits: ControllerProbeLimits,
    output: BtleOperatorOutput,
    activator: Arc<dyn ControllerEpochActivator>,
) -> LinuxControllerResolver {
    spawn_resolver(
        policy,
        limits,
        output,
        Arc::new(BluezResolverPlatform::new(Arc::new(ProductionBluez))),
        Arc::new(ProductionResolverProbe),
        Some(activator),
        None,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolverFailure {
    BluezUnavailable,
    ControllerUnauthorized,
    DeadlineExceeded,
    Cancelled,
}

impl ResolverFailure {
    const fn disposition(self) -> ProbeDisposition {
        let reason = match self {
            Self::BluezUnavailable => ProbeReason::BluezUnavailable,
            Self::ControllerUnauthorized => ProbeReason::PermissionDenied,
            Self::DeadlineExceeded => ProbeReason::DeadlineExceeded,
            Self::Cancelled => ProbeReason::Cancelled,
        };
        ProbeDisposition::Indeterminate(reason)
    }
}

impl From<BluezFailure> for ResolverFailure {
    fn from(failure: BluezFailure) -> Self {
        match failure {
            BluezFailure::ControllerUnauthorized => Self::ControllerUnauthorized,
            BluezFailure::BluezUnavailable | BluezFailure::ControllerAbsent => {
                Self::BluezUnavailable
            }
        }
    }
}

trait ResolverPlatform: Send + Sync {
    fn open_session(&self) -> ResolverFuture<'_, Box<dyn ResolverSession>>;
}

trait ResolverSession: Send {
    fn observe<'a>(
        &'a mut self,
        selected: Option<&'a str>,
    ) -> ResolverFuture<'a, ObservedInventory>;
    fn next_event(&mut self) -> ResolverEventFuture<'_>;
}

trait ResolverProbe: Send + Sync {
    fn probe<'a>(
        &'a self,
        candidate: &'a ControllerCandidate,
        fingerprint: &'a ControllerFingerprint,
        policy: &'a ControllerAdmissionPolicy,
        cancellation: &'a LifecycleCancellation,
        limits: ControllerProbeLimits,
    ) -> ResolverProbeFuture<'a>;
}

#[derive(Clone)]
struct ObservedController {
    candidate: ControllerCandidate,
    fingerprint: ControllerFingerprint,
}

impl ObservedController {
    fn new(candidate: ControllerCandidate, fingerprint: ControllerFingerprint) -> Self {
        Self {
            candidate,
            fingerprint,
        }
    }
}

struct ObservedInventory {
    controllers: Vec<ObservedController>,
}

impl ObservedInventory {
    fn bounded(controllers: Vec<ObservedController>) -> Self {
        let mut controllers: Vec<_> = controllers
            .into_iter()
            .take(MAX_CONTROLLER_CANDIDATES)
            .collect();
        controllers.sort_by(|left, right| left.candidate.name().cmp(right.candidate.name()));
        Self { controllers }
    }
}

enum ResolverEvent {
    InventoryChanged { removed: Option<String> },
    ControllerChanged(String),
}

struct BluezResolverPlatform {
    backend: Arc<dyn BluezBackend>,
}

impl BluezResolverPlatform {
    fn new(backend: Arc<dyn BluezBackend>) -> Self {
        Self { backend }
    }
}

impl ResolverPlatform for BluezResolverPlatform {
    fn open_session(&self) -> ResolverFuture<'_, Box<dyn ResolverSession>> {
        Box::pin(async move {
            let session = self.backend.open_session().await?;
            let session_events = session.subscribe().await?;
            Ok(Box::new(BluezResolverSession {
                session,
                session_events,
                adapter_events: SelectAll::new(),
            }) as Box<dyn ResolverSession>)
        })
    }
}

struct BluezResolverSession {
    session: Box<dyn BluezSession>,
    session_events: SessionStream,
    adapter_events: SelectAll<NamedAdapterStream>,
}

impl ResolverSession for BluezResolverSession {
    fn observe<'a>(
        &'a mut self,
        selected: Option<&'a str>,
    ) -> ResolverFuture<'a, ObservedInventory> {
        Box::pin(async move {
            let names = self.session.adapter_names().await?;
            let inventory = normalize_controller_inventory(names, selected, None);
            let mut controllers = Vec::with_capacity(inventory.candidates().len());
            let mut adapter_events = SelectAll::new();

            for named in inventory.candidates() {
                let adapter = match self.session.adapter(named.name()).await {
                    Ok(adapter) => adapter,
                    Err(BluezFailure::ControllerAbsent) => continue,
                    Err(failure) => return Err(failure.into()),
                };
                let events = match adapter.subscribe().await {
                    Ok(events) => events,
                    Err(BluezFailure::ControllerAbsent) => continue,
                    Err(failure) => return Err(failure.into()),
                };
                let snapshot = match adapter.snapshot().await {
                    Ok(snapshot) => snapshot,
                    Err(BluezFailure::ControllerAbsent) => continue,
                    Err(failure) => return Err(failure.into()),
                };
                let name = named.name().to_owned();
                let event_name = name.clone();
                adapter_events.push(
                    events
                        .map(move |event| (event_name.clone(), Some(event)))
                        .chain(futures::stream::once(async move { (name.clone(), None) }))
                        .boxed(),
                );
                controllers.push(ObservedController::new(
                    ControllerCandidate::from_snapshot(
                        named.name().to_owned(),
                        ControllerSnapshot::new(
                            snapshot.powered,
                            snapshot.address,
                            snapshot.address_type,
                        ),
                    ),
                    platform_fingerprint(),
                ));
            }

            self.adapter_events = adapter_events;
            Ok(ObservedInventory::bounded(controllers))
        })
    }

    fn next_event(&mut self) -> ResolverEventFuture<'_> {
        Box::pin(async move {
            for _ in 0..MAX_EVENTS_PER_BATCH {
                tokio::select! {
                    event = self.session_events.next() => {
                        return match event {
                            Some(SessionSignal::AdapterAdded(_)) => {
                                Some(ResolverEvent::InventoryChanged { removed: None })
                            }
                            Some(SessionSignal::AdapterRemoved(name)) => {
                                Some(ResolverEvent::InventoryChanged { removed: Some(name) })
                            }
                            None => None,
                        };
                    }
                    event = next_adapter_event(&mut self.adapter_events) => {
                        match event {
                            (name, Some(AdapterSignal::PropertiesChanged)) | (name, None) => {
                                return Some(ResolverEvent::ControllerChanged(name));
                            }
                            (_, Some(AdapterSignal::Unrelated)) => {}
                        }
                    }
                }
            }
            Some(ResolverEvent::InventoryChanged { removed: None })
        })
    }
}

async fn next_adapter_event(
    events: &mut SelectAll<NamedAdapterStream>,
) -> (String, Option<AdapterSignal>) {
    if events.is_empty() {
        std::future::pending().await
    } else {
        events
            .next()
            .await
            .expect("non-empty adapter stream set yields an end marker")
    }
}

fn platform_fingerprint() -> ControllerFingerprint {
    ControllerFingerprint::new(
        Some(std::env::consts::OS),
        Some(std::env::consts::ARCH),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

struct ProductionResolverProbe;

static PRODUCTION_PROBE_BACKEND: BluezControllerProbeBackend = BluezControllerProbeBackend;

impl ResolverProbe for ProductionResolverProbe {
    fn probe<'a>(
        &'a self,
        candidate: &'a ControllerCandidate,
        fingerprint: &'a ControllerFingerprint,
        policy: &'a ControllerAdmissionPolicy,
        cancellation: &'a LifecycleCancellation,
        limits: ControllerProbeLimits,
    ) -> ResolverProbeFuture<'a> {
        Box::pin(probe_controller(
            &PRODUCTION_PROBE_BACKEND,
            candidate,
            fingerprint,
            policy,
            cancellation,
            limits,
        ))
    }
}

struct ResolverActor {
    policy: ControllerAdmissionPolicy,
    limits: ControllerProbeLimits,
    platform: Arc<dyn ResolverPlatform>,
    probe: Arc<dyn ResolverProbe>,
    activator: Option<Arc<dyn ControllerEpochActivator>>,
    output: BtleOperatorOutput,
    updates: watch::Sender<ControllerResolutionSnapshot>,
    cancellation: LifecycleCancellation,
    owner: Option<ControllerEpochOwner>,
    operational: Option<Box<dyn OperationalControllerEpoch>>,
    operational_status: Option<watch::Receiver<OperationalEpochState>>,
    nonterminal_publication: NonterminalPublication,
    cursor: Option<String>,
    inventory_generation: u64,
    backoff: CappedBackoff,
    operational_backoff: CappedBackoff,
    #[cfg(test)]
    epoch_updates: Option<tokio::sync::mpsc::Sender<LifecycleCancellationObserver>>,
}

enum SessionAction {
    Sweep,
    OperationalRetry,
    Lost,
    Cancelled,
    Terminal(DriverError),
}

enum SweepOutcome {
    Selected,
    Stable,
    Retryable,
    Cancelled,
}

enum EventDrain {
    Idle,
    Exhausted,
    Saturated,
    Action(SessionAction),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NonterminalPublication {
    Settled,
    Pending,
}

impl ResolverActor {
    async fn run(mut self) -> Result<(), DriverError> {
        self.output.emit(BtleOperatorEvent::AdapterUnavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        loop {
            if self.cancellation.is_cancelled() {
                break;
            }
            let session = wait_platform(
                &self.cancellation,
                self.limits.operation(),
                self.platform.open_session(),
            )
            .await;
            let mut session = match session {
                Ok(session) => session,
                Err(ResolverFailure::Cancelled) => break,
                Err(failure) => {
                    self.invalidate_owner(failure.disposition()).await?;
                    if wait_delay(&self.cancellation, self.backoff.next_delay()).await {
                        break;
                    }
                    continue;
                }
            };

            match self.run_session(session.as_mut()).await {
                SessionAction::Cancelled => break,
                SessionAction::Terminal(error) => return Err(error),
                SessionAction::Lost => {
                    self.invalidate_owner(ProbeDisposition::Indeterminate(
                        ProbeReason::BluezUnavailable,
                    ))
                    .await?;
                    if wait_delay(&self.cancellation, self.backoff.next_delay()).await {
                        break;
                    }
                }
                SessionAction::Sweep | SessionAction::OperationalRetry => {
                    unreachable!("session runner consumes retry actions")
                }
            }
        }
        self.invalidate_owner(ProbeDisposition::Indeterminate(ProbeReason::Cancelled))
            .await
    }

    async fn run_session(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        loop {
            let selected = self.owner.as_ref().map(|owner| owner.name().to_owned());
            let observed = wait_platform(
                &self.cancellation,
                self.limits.operation(),
                session.observe(selected.as_deref()),
            )
            .await;
            let observed = match observed {
                Ok(observed) => observed,
                Err(ResolverFailure::Cancelled) => return SessionAction::Cancelled,
                Err(_) => return SessionAction::Lost,
            };
            self.inventory_generation = self.inventory_generation.saturating_add(1);

            if let Some(owner) = &self.owner {
                if observed
                    .controllers
                    .iter()
                    .any(|controller| owner.matches(controller))
                {
                    self.backoff.reset();
                    match self.wait_healthy_event(session).await {
                        SessionAction::Sweep => continue,
                        SessionAction::OperationalRetry => {
                            match self.wait_operational_retry(session).await {
                                SessionAction::Sweep => continue,
                                outcome => return outcome,
                            }
                        }
                        outcome => return outcome,
                    }
                }
                if let Err(error) = self
                    .invalidate_owner(ProbeDisposition::Indeterminate(
                        ProbeReason::BluezUnavailable,
                    ))
                    .await
                {
                    return SessionAction::Terminal(error);
                }
            }

            match self.probe_sweep(observed).await {
                SweepOutcome::Selected => {
                    self.backoff.reset();
                    match self.wait_healthy_event(session).await {
                        SessionAction::Sweep => continue,
                        SessionAction::OperationalRetry => {
                            match self.wait_operational_retry(session).await {
                                SessionAction::Sweep => continue,
                                outcome => return outcome,
                            }
                        }
                        outcome => return outcome,
                    }
                }
                SweepOutcome::Retryable => match self.wait_passive_retry(session).await {
                    SessionAction::Sweep => {}
                    outcome => return outcome,
                },
                SweepOutcome::Stable => match self.wait_pending_sweep(session).await {
                    SessionAction::Sweep => {}
                    outcome => return outcome,
                },
                SweepOutcome::Cancelled => return SessionAction::Cancelled,
            }
        }
    }

    async fn probe_sweep(&mut self, observed: ObservedInventory) -> SweepOutcome {
        if observed.controllers.is_empty() {
            self.cursor = None;
            self.publish(ControllerResolutionSnapshot::unavailable(
                ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable),
                None,
            ));
            return SweepOutcome::Stable;
        }

        let admissions: Vec<_> = observed
            .controllers
            .iter()
            .map(|controller| self.policy.admit(&controller.fingerprint))
            .collect();
        let mut order: Vec<_> = (0..observed.controllers.len()).collect();
        let resumed = self.cursor.as_deref().and_then(|cursor| {
            order
                .iter()
                .position(|index| observed.controllers[*index].candidate.name() == cursor)
        });
        if let Some(position) = resumed {
            let next = (position + 1) % order.len();
            order.rotate_left(next);
        } else {
            self.cursor = None;
            order.sort_by_key(|index| {
                if admissions[*index].support() == SupportTag::Qualified {
                    0
                } else {
                    1
                }
            });
        }

        let deadline = Instant::now() + self.limits.sweep();
        let mut last = ControllerResolutionSnapshot::unavailable(
            ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable),
            None,
        );
        let mut sweep_unfinished = false;
        let mut retryable = false;

        for index in order.iter().copied() {
            let controller = &observed.controllers[index];
            let admission = admissions[index];
            if admission.disposition() != ProbeDisposition::Compatible {
                last = ControllerResolutionSnapshot::unavailable(
                    admission.disposition(),
                    Some(admission.support()),
                );
                continue;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                sweep_unfinished = true;
                break;
            }
            let candidate_limit = remaining.min(self.limits.candidate());
            self.cursor = Some(controller.candidate.name().to_owned());
            let disposition = tokio::select! {
                biased;
                () = self.cancellation.cancelled() => return SweepOutcome::Cancelled,
                result = timeout(candidate_limit, self.probe.probe(
                    &controller.candidate,
                    &controller.fingerprint,
                    &self.policy,
                    &self.cancellation,
                    self.limits,
                )) => result.unwrap_or(ProbeDisposition::Indeterminate(ProbeReason::DeadlineExceeded)),
            };
            if disposition == ProbeDisposition::Compatible {
                let support = admission.support();
                if self.select(controller.clone(), support).await {
                    return SweepOutcome::Selected;
                }
                retryable = true;
                last = ControllerResolutionSnapshot::unavailable(
                    ProbeDisposition::Indeterminate(ProbeReason::UnknownPlatformError),
                    Some(support),
                );
                continue;
            }

            last =
                ControllerResolutionSnapshot::unavailable(disposition, Some(admission.support()));
            retryable |= matches!(disposition, ProbeDisposition::Indeterminate(_));
            if Instant::now() >= deadline {
                sweep_unfinished = true;
                break;
            }
        }

        retryable |= sweep_unfinished;
        if !retryable {
            self.cursor = None;
        }
        self.publish(last);
        if retryable {
            SweepOutcome::Retryable
        } else {
            SweepOutcome::Stable
        }
    }

    async fn select(&mut self, controller: ObservedController, support: SupportTag) -> bool {
        let owner = ControllerEpochOwner::new(controller, support, self.inventory_generation);
        #[cfg(test)]
        if let Some(updates) = &self.epoch_updates {
            let _ = updates.try_send(owner.cancellation.observer());
        }
        let operational = match &self.activator {
            Some(activator) => match owner.view().and_then(|view| activator.activate(view)) {
                Ok(operational) => Some(operational),
                Err(_) => {
                    self.publish(ControllerResolutionSnapshot::unavailable(
                        ProbeDisposition::Indeterminate(ProbeReason::UnknownPlatformError),
                        Some(support),
                    ));
                    return false;
                }
            },
            None => None,
        };
        self.operational_status = operational.as_ref().map(|owner| owner.status());
        self.operational = operational;
        self.owner = Some(owner);
        self.nonterminal_publication = NonterminalPublication::Settled;
        self.publish(ControllerResolutionSnapshot::unavailable(
            ProbeDisposition::Compatible,
            Some(support),
        ));
        true
    }

    async fn invalidate_owner(&mut self, disposition: ProbeDisposition) -> Result<(), DriverError> {
        self.nonterminal_publication = NonterminalPublication::Settled;
        self.publish(ControllerResolutionSnapshot::unavailable(disposition, None));
        let mut cleanup_error = None;
        if let Some(operational) = self.operational.as_mut()
            && let Err(error) = operational.quiesce().await
        {
            cleanup_error = Some(error);
        }
        if let Some(owner) = self.owner.as_ref() {
            owner.cancellation.cancel();
        }
        if let Some(operational) = self.operational.take() {
            operational.cancel();
            if let Err(error) = operational.join().await
                && cleanup_error.is_none()
            {
                cleanup_error = Some(error);
            }
        }
        self.operational_status.take();
        self.owner.take();
        cleanup_error.map_or(Ok(()), Err)
    }

    async fn wait_healthy_event(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        loop {
            if self.nonterminal_publication == NonterminalPublication::Pending {
                if let Some(outcome) = self.finish_pending_operational_change(session).await {
                    return outcome;
                }
                continue;
            }

            enum HealthyEvent {
                Cancelled,
                Platform(Option<ResolverEvent>),
                Operational(Result<(), watch::error::RecvError>),
            }

            let event = if let Some(status) = self.operational_status.as_mut() {
                tokio::select! {
                    biased;
                    () = self.cancellation.cancelled() => HealthyEvent::Cancelled,
                    changed = status.changed() => HealthyEvent::Operational(changed),
                    event = session.next_event() => HealthyEvent::Platform(event),
                }
            } else {
                tokio::select! {
                    biased;
                    () = self.cancellation.cancelled() => HealthyEvent::Cancelled,
                    event = session.next_event() => HealthyEvent::Platform(event),
                }
            };

            match event {
                HealthyEvent::Cancelled => return SessionAction::Cancelled,
                HealthyEvent::Platform(Some(event)) => {
                    let events = match self.consume_event_batch(session, event).await {
                        EventDrain::Action(outcome) => return outcome,
                        events => events,
                    };
                    if self.cancellation.is_cancelled() {
                        return SessionAction::Cancelled;
                    }
                    if self.operational_change_is_ready()
                        && let Some(outcome) = self.finish_nonterminal_publication(events).await
                    {
                        return outcome;
                    }
                    return SessionAction::Sweep;
                }
                HealthyEvent::Platform(None) => return SessionAction::Lost,
                HealthyEvent::Operational(changed) => {
                    if changed.is_err() {
                        return self.invalidate_failed_operational_epoch().await;
                    }
                    if let Some(outcome) = self.finish_pending_operational_change(session).await {
                        return outcome;
                    }
                }
            }
        }
    }

    fn operational_change_is_ready(&mut self) -> bool {
        let Some(status) = self.operational_status.as_mut() else {
            return false;
        };
        status.has_changed().unwrap_or(true)
    }

    async fn finish_pending_operational_change(
        &mut self,
        session: &mut dyn ResolverSession,
    ) -> Option<SessionAction> {
        if let Some(outcome) = self.urgent_operational_action().await {
            return Some(outcome);
        }
        let events = self.consume_ready_event_batch(session).await;
        self.finish_nonterminal_publication(events).await
    }

    async fn urgent_operational_action(&mut self) -> Option<SessionAction> {
        if self.cancellation.is_cancelled() {
            return Some(SessionAction::Cancelled);
        }
        if self
            .operational_status
            .as_mut()
            .expect("selected owner retains operational status")
            .has_changed()
            .is_err()
        {
            return Some(self.invalidate_failed_operational_epoch().await);
        }
        let latest_state = *self
            .operational_status
            .as_ref()
            .expect("selected owner retains operational status")
            .borrow();
        if latest_state == OperationalEpochState::Unavailable {
            self.operational_status
                .as_mut()
                .expect("selected owner retains operational status")
                .borrow_and_update();
            return Some(self.invalidate_failed_operational_epoch().await);
        }
        None
    }

    async fn finish_nonterminal_publication(
        &mut self,
        events: EventDrain,
    ) -> Option<SessionAction> {
        if let EventDrain::Action(outcome) = events {
            return Some(outcome);
        }
        if let Some(outcome) = self.urgent_operational_action().await {
            return Some(outcome);
        }
        if matches!(events, EventDrain::Saturated) {
            self.nonterminal_publication = NonterminalPublication::Pending;
            return Some(SessionAction::Sweep);
        }
        self.nonterminal_publication = NonterminalPublication::Settled;
        let state = *self
            .operational_status
            .as_mut()
            .expect("selected owner retains operational status")
            .borrow_and_update();
        match state {
            OperationalEpochState::Starting => {}
            OperationalEpochState::Available => {
                self.cursor = None;
                self.operational_backoff.reset();
                let support = self
                    .owner
                    .as_ref()
                    .expect("operational state has a controller owner")
                    .support();
                self.publish(ControllerResolutionSnapshot::available(support));
            }
            OperationalEpochState::Unavailable => {
                return Some(self.invalidate_failed_operational_epoch().await);
            }
        }
        match events {
            EventDrain::Idle => None,
            EventDrain::Exhausted => Some(SessionAction::Sweep),
            EventDrain::Saturated | EventDrain::Action(_) => {
                unreachable!("saturated batches and actions return before publication")
            }
        }
    }

    async fn consume_ready_event_batch(&mut self, session: &mut dyn ResolverSession) -> EventDrain {
        match session.next_event().now_or_never() {
            None => EventDrain::Idle,
            Some(Some(event)) => self.consume_event_batch(session, event).await,
            Some(None) => EventDrain::Action(SessionAction::Lost),
        }
    }

    async fn invalidate_failed_operational_epoch(&mut self) -> SessionAction {
        match self
            .invalidate_owner(ProbeDisposition::Indeterminate(
                ProbeReason::BluezUnavailable,
            ))
            .await
        {
            Ok(()) => SessionAction::OperationalRetry,
            Err(error) => SessionAction::Terminal(error),
        }
    }

    async fn consume_event_batch(
        &mut self,
        session: &mut dyn ResolverSession,
        first: ResolverEvent,
    ) -> EventDrain {
        if self.cancellation.is_cancelled() {
            return EventDrain::Action(SessionAction::Cancelled);
        }
        let mut invalidated = self.apply_event(first);
        let mut completed = EventDrain::Saturated;
        for _ in 1..MAX_EVENTS_PER_BATCH {
            if self.cancellation.is_cancelled() {
                return EventDrain::Action(SessionAction::Cancelled);
            }
            match session.next_event().now_or_never() {
                Some(Some(event)) => {
                    invalidated |= self.apply_event(event);
                }
                Some(None) => return EventDrain::Action(SessionAction::Lost),
                None => {
                    completed = EventDrain::Exhausted;
                    break;
                }
            }
        }
        tokio::task::yield_now().await;
        if self.cancellation.is_cancelled() {
            return EventDrain::Action(SessionAction::Cancelled);
        }
        if matches!(completed, EventDrain::Exhausted) {
            // A ready source may return Pending when the task's cooperative budget is spent.
            // One fresh-budget probe distinguishes that from an actually idle ready queue.
            match session.next_event().now_or_never() {
                Some(Some(event)) => {
                    invalidated |= self.apply_event(event);
                    completed = EventDrain::Saturated;
                }
                Some(None) => return EventDrain::Action(SessionAction::Lost),
                None => {}
            }
        }
        if self.cancellation.is_cancelled() {
            return EventDrain::Action(SessionAction::Cancelled);
        }
        if invalidated
            && let Err(error) = self
                .invalidate_owner(ProbeDisposition::Indeterminate(
                    ProbeReason::BluezUnavailable,
                ))
                .await
        {
            return EventDrain::Action(SessionAction::Terminal(error));
        }
        if invalidated {
            return EventDrain::Action(SessionAction::Sweep);
        }
        completed
    }

    fn apply_event(&self, event: ResolverEvent) -> bool {
        let selected = self.owner.as_ref().map(|owner| owner.name());
        match &event {
            ResolverEvent::InventoryChanged {
                removed: Some(name),
            } => selected == Some(name.as_str()),
            ResolverEvent::ControllerChanged(name) => selected == Some(name.as_str()),
            ResolverEvent::InventoryChanged { removed: None } => false,
        }
    }

    async fn wait_pending_sweep(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        let event = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return SessionAction::Cancelled,
            event = session.next_event() => event,
        };
        let Some(event) = event else {
            return SessionAction::Lost;
        };
        match self.consume_event_batch(session, event).await {
            EventDrain::Action(outcome) => outcome,
            EventDrain::Idle | EventDrain::Exhausted | EventDrain::Saturated => {
                SessionAction::Sweep
            }
        }
    }

    async fn wait_operational_retry(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        let delay = self.operational_backoff.next_delay();
        self.wait_retry(session, delay).await
    }

    async fn wait_passive_retry(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        let delay = self.backoff.next_delay();
        self.wait_retry(session, delay).await
    }

    async fn wait_retry(
        &mut self,
        session: &mut dyn ResolverSession,
        delay: Duration,
    ) -> SessionAction {
        let deadline = Instant::now() + delay;
        loop {
            if self.cancellation.is_cancelled() {
                return SessionAction::Cancelled;
            }
            if Instant::now() >= deadline {
                return SessionAction::Sweep;
            }
            let event = tokio::select! {
                biased;
                () = self.cancellation.cancelled() => return SessionAction::Cancelled,
                () = tokio::time::sleep_until(deadline) => return SessionAction::Sweep,
                event = session.next_event() => event,
            };
            let Some(event) = event else {
                return SessionAction::Lost;
            };
            match self.consume_event_batch(session, event).await {
                EventDrain::Action(outcome) => return outcome,
                EventDrain::Idle | EventDrain::Exhausted | EventDrain::Saturated => {}
            }
        }
    }

    fn publish(&self, snapshot: ControllerResolutionSnapshot) {
        let changed = self.updates.send_if_modified(|current| {
            if *current == snapshot {
                false
            } else {
                *current = snapshot;
                true
            }
        });
        if changed {
            self.output.emit(operator_event(snapshot));
        }
    }
}

fn operator_event(snapshot: ControllerResolutionSnapshot) -> BtleOperatorEvent {
    if snapshot.availability == RuntimeAvailability::Available {
        return BtleOperatorEvent::AdapterAvailable;
    }
    let reason = match snapshot.disposition {
        ProbeDisposition::Indeterminate(ProbeReason::ControllerUnpowered) => {
            crate::AvailabilityReason::ControllerUnpowered
        }
        ProbeDisposition::Indeterminate(ProbeReason::PermissionDenied) => {
            crate::AvailabilityReason::ControllerUnauthorized
        }
        ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable) => {
            crate::AvailabilityReason::BluezUnavailable
        }
        _ => crate::AvailabilityReason::ControllerIdentityMismatch,
    };
    BtleOperatorEvent::AdapterUnavailable(reason)
}

async fn wait_platform<T>(
    cancellation: &LifecycleCancellation,
    limit: Duration,
    operation: ResolverFuture<'_, T>,
) -> Result<T, ResolverFailure> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(ResolverFailure::Cancelled),
        result = timeout(limit, operation) => {
            result.unwrap_or(Err(ResolverFailure::DeadlineExceeded))
        }
    }
}

async fn wait_delay(cancellation: &LifecycleCancellation, delay: Duration) -> bool {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

fn spawn_resolver(
    policy: ControllerAdmissionPolicy,
    limits: ControllerProbeLimits,
    output: BtleOperatorOutput,
    platform: Arc<dyn ResolverPlatform>,
    probe: Arc<dyn ResolverProbe>,
    activator: Option<Arc<dyn ControllerEpochActivator>>,
    #[cfg(test)] epoch_updates: Option<tokio::sync::mpsc::Sender<LifecycleCancellationObserver>>,
    #[cfg(not(test))] _epoch_updates: Option<()>,
) -> LinuxControllerResolver {
    let cancellation = LifecycleCancellation::new();
    let (updates, status) = watch::channel(ControllerResolutionSnapshot::initial());
    let actor = ResolverActor {
        policy,
        limits,
        platform,
        probe,
        activator,
        output: output.clone(),
        updates,
        cancellation: cancellation.clone(),
        owner: None,
        operational: None,
        operational_status: None,
        nonterminal_publication: NonterminalPublication::Settled,
        cursor: None,
        inventory_generation: 0,
        backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
        operational_backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
        #[cfg(test)]
        epoch_updates,
    };
    let task = tokio::spawn(actor.run());
    LinuxControllerResolver {
        status,
        cancellation,
        output,
        task: Some(task),
    }
}

#[cfg(test)]
struct TestOperationalActivator;

#[cfg(test)]
impl ControllerEpochActivator for TestOperationalActivator {
    fn activate(
        &self,
        _epoch: ControllerEpochView<'_>,
    ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
        let (updates, status) = watch::channel(OperationalEpochState::Starting);
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_updates = updates.clone();
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            task_updates.send_replace(OperationalEpochState::Available);
            task_cancellation.cancelled().await;
            Ok(())
        });
        Ok(Box::new(TestOperationalEpoch {
            updates,
            status,
            cancellation,
            task,
        }))
    }
}

#[cfg(test)]
struct TestOperationalEpoch {
    updates: watch::Sender<OperationalEpochState>,
    status: watch::Receiver<OperationalEpochState>,
    cancellation: LifecycleCancellation,
    task: JoinHandle<Result<(), DriverError>>,
}

#[cfg(test)]
impl OperationalControllerEpoch for TestOperationalEpoch {
    fn status(&self) -> watch::Receiver<OperationalEpochState> {
        self.status.clone()
    }

    fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>> {
        self.updates
            .send_replace(OperationalEpochState::Unavailable);
        Box::pin(async { Ok(()) })
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn join(self: Box<Self>) -> OperationalEpochFuture<'static, Result<(), DriverError>> {
        Box::pin(async move {
            self.task.await.map_err(|_| {
                DriverError::new(
                    DriverErrorKind::Transport,
                    "test operational controller epoch stopped",
                )
            })?
        })
    }
}

#[cfg(test)]
fn spawn_linux_controller_resolver_with(
    policy: ControllerAdmissionPolicy,
    limits: ControllerProbeLimits,
    output: BtleOperatorOutput,
    platform: Arc<dyn ResolverPlatform>,
    probe: Arc<dyn ResolverProbe>,
) -> (
    LinuxControllerResolver,
    tokio::sync::mpsc::Receiver<LifecycleCancellationObserver>,
) {
    let (epoch_updates, epochs) = tokio::sync::mpsc::channel(8);
    (
        spawn_resolver(
            policy,
            limits,
            output,
            platform,
            probe,
            Some(Arc::new(TestOperationalActivator)),
            Some(epoch_updates),
        ),
        epochs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BtleOperatorEvent, BtleOperatorOutput, ControllerAdmissionPolicy, ControllerCandidate,
        ControllerFingerprint, ControllerProbeLimits, ControllerSnapshot, LifecycleCancellation,
        ProbeDisposition, ProbeReason, RuntimeAvailability, SupportRow, SupportTag, UnsafeRule,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::{HashMap, VecDeque},
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{Notify, mpsc};

    struct FakePlatform {
        sessions: Mutex<VecDeque<Result<Box<dyn ResolverSession>, ResolverFailure>>>,
        opens: AtomicUsize,
    }

    impl FakePlatform {
        fn new(
            sessions: impl IntoIterator<Item = Result<Box<dyn ResolverSession>, ResolverFailure>>,
        ) -> Self {
            Self {
                sessions: Mutex::new(sessions.into_iter().collect()),
                opens: AtomicUsize::new(0),
            }
        }

        fn open_count(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
    }

    impl ResolverPlatform for FakePlatform {
        fn open_session(&self) -> ResolverFuture<'_, Box<dyn ResolverSession>> {
            Box::pin(async move {
                self.opens.fetch_add(1, Ordering::SeqCst);
                self.sessions
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Err(ResolverFailure::BluezUnavailable))
            })
        }
    }

    struct FakeSession {
        controllers: Arc<Mutex<Vec<ObservedController>>>,
        events: mpsc::UnboundedReceiver<ResolverEvent>,
        observations: Arc<AtomicUsize>,
    }

    struct PendingBluezSession;

    impl BluezSession for PendingBluezSession {
        fn subscribe(&self) -> crate::controller::BluezFuture<'_, SessionStream> {
            Box::pin(std::future::pending())
        }

        fn adapter_names(&self) -> crate::controller::BluezFuture<'_, Vec<String>> {
            Box::pin(std::future::pending())
        }

        fn adapter<'a>(
            &'a self,
            _name: &'a str,
        ) -> crate::controller::BluezFuture<'a, Box<dyn crate::controller::BluezAdapter>> {
            Box::pin(std::future::pending())
        }
    }

    struct CancellationStormSession {
        cancellation: LifecycleCancellation,
        events: Arc<AtomicUsize>,
    }

    struct AlwaysReadySession {
        observations: Arc<AtomicUsize>,
    }

    struct OperationalRetryFloodSession {
        events: Arc<AtomicUsize>,
    }

    struct HealthyEventFloodSession {
        controller: ObservedController,
        flooding: watch::Receiver<bool>,
        events: Arc<AtomicUsize>,
    }

    struct SaturationGateSession {
        controller: ObservedController,
        events: mpsc::UnboundedReceiver<ResolverEvent>,
        observations: Arc<AtomicUsize>,
        saturated_sweep_started: Arc<Notify>,
        allow_saturated_sweep: Arc<Notify>,
    }

    impl ResolverSession for CancellationStormSession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            Box::pin(async { Ok(ObservedInventory::bounded(Vec::new())) })
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            Box::pin(async move {
                let event = self.events.fetch_add(1, Ordering::SeqCst);
                if event == 0 {
                    self.cancellation.cancel();
                }
                if event < 1_024 {
                    Some(ResolverEvent::InventoryChanged { removed: None })
                } else {
                    std::future::pending().await
                }
            })
        }
    }

    impl ResolverSession for AlwaysReadySession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            self.observations.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(ObservedInventory::bounded(Vec::new())) })
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            Box::pin(async { Some(ResolverEvent::InventoryChanged { removed: None }) })
        }
    }

    impl ResolverSession for OperationalRetryFloodSession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            unreachable!("operational retry does not poll healthy inventory")
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            self.events.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Some(ResolverEvent::InventoryChanged { removed: None }) })
        }
    }

    impl ResolverSession for HealthyEventFloodSession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            let controller = self.controller.clone();
            Box::pin(async move { Ok(ObservedInventory::bounded(vec![controller])) })
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            Box::pin(async move {
                while !*self.flooding.borrow_and_update() {
                    if self.flooding.changed().await.is_err() {
                        return None;
                    }
                }
                self.events.fetch_add(1, Ordering::SeqCst);
                Some(ResolverEvent::InventoryChanged { removed: None })
            })
        }
    }

    impl ResolverSession for SaturationGateSession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            let controller = self.controller.clone();
            let observation = self.observations.fetch_add(1, Ordering::SeqCst);
            let saturated_sweep_started = self.saturated_sweep_started.clone();
            let allow_saturated_sweep = self.allow_saturated_sweep.clone();
            Box::pin(async move {
                if observation == 1 {
                    saturated_sweep_started.notify_one();
                    allow_saturated_sweep.notified().await;
                }
                Ok(ObservedInventory::bounded(vec![controller]))
            })
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            Box::pin(self.events.recv())
        }
    }

    impl ResolverSession for FakeSession {
        fn observe<'a>(
            &'a mut self,
            _selected: Option<&'a str>,
        ) -> ResolverFuture<'a, ObservedInventory> {
            Box::pin(async move {
                self.observations.fetch_add(1, Ordering::SeqCst);
                Ok(ObservedInventory::bounded(
                    self.controllers.lock().unwrap().clone(),
                ))
            })
        }

        fn next_event(&mut self) -> ResolverEventFuture<'_> {
            Box::pin(self.events.recv())
        }
    }

    #[derive(Clone)]
    enum ProbeBehavior {
        Immediate(ProbeDisposition),
        Pending,
        Gated(Arc<Notify>),
    }

    struct ActiveProbe<'a>(&'a AtomicUsize);

    impl Drop for ActiveProbe<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct FakeProbe {
        behaviors: Mutex<HashMap<String, ProbeBehavior>>,
        calls: Mutex<Vec<String>>,
        active: AtomicUsize,
        maximum_active: AtomicUsize,
        started: Notify,
    }

    impl FakeProbe {
        fn compatible() -> Self {
            Self {
                behaviors: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                active: AtomicUsize::new(0),
                maximum_active: AtomicUsize::new(0),
                started: Notify::new(),
            }
        }

        fn with(name: &str, behavior: ProbeBehavior) -> Self {
            let probe = Self::compatible();
            probe
                .behaviors
                .lock()
                .unwrap()
                .insert(name.to_owned(), behavior);
            probe
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        async fn wait_for_calls(&self, count: usize) {
            loop {
                let notified = self.started.notified();
                if self.calls.lock().unwrap().len() >= count {
                    return;
                }
                notified.await;
            }
        }
    }

    impl ResolverProbe for FakeProbe {
        fn probe<'a>(
            &'a self,
            candidate: &'a ControllerCandidate,
            _fingerprint: &'a ControllerFingerprint,
            _policy: &'a ControllerAdmissionPolicy,
            cancellation: &'a LifecycleCancellation,
            _limits: ControllerProbeLimits,
        ) -> ResolverProbeFuture<'a> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(candidate.name().to_owned());
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum_active.fetch_max(active, Ordering::SeqCst);
                let _active = ActiveProbe(&self.active);
                self.started.notify_waiters();
                let behavior = self
                    .behaviors
                    .lock()
                    .unwrap()
                    .get(candidate.name())
                    .cloned()
                    .unwrap_or(ProbeBehavior::Immediate(ProbeDisposition::Compatible));
                match behavior {
                    ProbeBehavior::Immediate(disposition) => disposition,
                    ProbeBehavior::Pending => {
                        cancellation.cancelled().await;
                        ProbeDisposition::Indeterminate(ProbeReason::Cancelled)
                    }
                    ProbeBehavior::Gated(gate) => {
                        tokio::select! {
                            () = cancellation.cancelled() => {
                                ProbeDisposition::Indeterminate(ProbeReason::Cancelled)
                            }
                            () = gate.notified() => ProbeDisposition::Compatible,
                        }
                    }
                }
            })
        }
    }

    #[derive(Default)]
    struct RecordingActivator {
        states: Mutex<Vec<watch::Sender<OperationalEpochState>>>,
        selected: Mutex<Vec<String>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        quiesce_gate: Mutex<Option<Arc<Notify>>>,
        fail_join: Arc<std::sync::atomic::AtomicBool>,
    }

    impl RecordingActivator {
        fn latest_state(&self, state: OperationalEpochState) {
            self.states
                .lock()
                .unwrap()
                .last()
                .expect("one selected controller epoch")
                .send_replace(state);
        }

        fn activation_count(&self) -> usize {
            self.states.lock().unwrap().len()
        }

        fn selected(&self) -> Vec<String> {
            self.selected.lock().unwrap().clone()
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }

        fn block_quiesce(&self, gate: Arc<Notify>) {
            *self.quiesce_gate.lock().unwrap() = Some(gate);
        }

        fn allow_future_quiesce(&self) {
            *self.quiesce_gate.lock().unwrap() = None;
        }

        fn fail_join(&self) {
            self.fail_join.store(true, Ordering::Release);
        }

        fn flood_nonterminal_states(&self, updates: usize) -> JoinHandle<()> {
            let status = self
                .states
                .lock()
                .unwrap()
                .last()
                .expect("one selected controller epoch")
                .clone();
            status.send_replace(OperationalEpochState::Starting);
            tokio::spawn(async move {
                for update in 1..updates {
                    let state = if update % 2 == 0 {
                        OperationalEpochState::Starting
                    } else {
                        OperationalEpochState::Available
                    };
                    status.send_replace(state);
                    tokio::task::yield_now().await;
                }
            })
        }
    }

    impl ControllerEpochActivator for RecordingActivator {
        fn activate(
            &self,
            epoch: ControllerEpochView<'_>,
        ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
            let (updates, status) = watch::channel(OperationalEpochState::Starting);
            self.selected
                .lock()
                .unwrap()
                .push(epoch.adapter_name().to_owned());
            self.states.lock().unwrap().push(updates.clone());
            Ok(Box::new(RecordingOperationalEpoch {
                updates,
                status,
                events: self.events.clone(),
                quiesce_gate: self.quiesce_gate.lock().unwrap().clone(),
                fail_join: self.fail_join.clone(),
            }))
        }
    }

    #[derive(Default)]
    struct FailFirstActivator {
        attempts: AtomicUsize,
    }

    impl ControllerEpochActivator for FailFirstActivator {
        fn activate(
            &self,
            epoch: ControllerEpochView<'_>,
        ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(DriverError::new(
                    DriverErrorKind::Unavailable,
                    "first test controller activation failed",
                ));
            }
            TestOperationalActivator.activate(epoch)
        }
    }

    struct RecordingOperationalEpoch {
        updates: watch::Sender<OperationalEpochState>,
        status: watch::Receiver<OperationalEpochState>,
        events: Arc<Mutex<Vec<&'static str>>>,
        quiesce_gate: Option<Arc<Notify>>,
        fail_join: Arc<std::sync::atomic::AtomicBool>,
    }

    #[derive(Default)]
    struct ClosingStatusActivator {
        status: Mutex<Option<watch::Sender<OperationalEpochState>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        activations: AtomicUsize,
        forced: Arc<AtomicBool>,
    }

    impl ClosingStatusActivator {
        fn publish(&self, state: OperationalEpochState) {
            self.status
                .lock()
                .unwrap()
                .as_ref()
                .expect("one live operational status")
                .send_replace(state);
        }

        fn close_status(&self) {
            self.status.lock().unwrap().take();
        }
    }

    impl ControllerEpochActivator for ClosingStatusActivator {
        fn activate(
            &self,
            _epoch: ControllerEpochView<'_>,
        ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
            self.activations.fetch_add(1, Ordering::SeqCst);
            let (updates, status) = watch::channel(OperationalEpochState::Starting);
            *self.status.lock().unwrap() = Some(updates);
            Ok(Box::new(ClosingStatusOperationalEpoch {
                status,
                events: self.events.clone(),
                forced: self.forced.clone(),
            }))
        }
    }

    struct ClosingStatusOperationalEpoch {
        status: watch::Receiver<OperationalEpochState>,
        events: Arc<Mutex<Vec<&'static str>>>,
        forced: Arc<AtomicBool>,
    }

    impl OperationalControllerEpoch for ClosingStatusOperationalEpoch {
        fn status(&self) -> watch::Receiver<OperationalEpochState> {
            self.status.clone()
        }

        fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>> {
            self.events.lock().unwrap().push("unavailable");
            Box::pin(async { Ok(()) })
        }

        fn cancel(&self) {
            self.events.lock().unwrap().push("cancel");
        }

        fn join(self: Box<Self>) -> OperationalEpochFuture<'static, Result<(), DriverError>> {
            self.events.lock().unwrap().push("join");
            self.events.lock().unwrap().push("force");
            self.forced.store(true, Ordering::Release);
            Box::pin(async {
                Err(DriverError::new(
                    DriverErrorKind::Transport,
                    "test operational cleanup unconfirmed",
                ))
            })
        }
    }

    impl OperationalControllerEpoch for RecordingOperationalEpoch {
        fn status(&self) -> watch::Receiver<OperationalEpochState> {
            self.status.clone()
        }

        fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>> {
            self.events.lock().unwrap().push("quiesce");
            self.updates
                .send_replace(OperationalEpochState::Unavailable);
            let gate = self.quiesce_gate.clone();
            Box::pin(async move {
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                Ok(())
            })
        }

        fn cancel(&self) {
            self.events.lock().unwrap().push("cancel");
        }

        fn join(self: Box<Self>) -> OperationalEpochFuture<'static, Result<(), DriverError>> {
            self.events.lock().unwrap().push("join");
            if self.fail_join.load(Ordering::Acquire) {
                self.events.lock().unwrap().push("force");
                Box::pin(async {
                    Err(DriverError::new(
                        DriverErrorKind::Transport,
                        "test operational cleanup unconfirmed",
                    ))
                })
            } else {
                Box::pin(async { Ok(()) })
            }
        }
    }

    struct Harness {
        controllers: Arc<Mutex<Vec<ObservedController>>>,
        events: Option<mpsc::UnboundedSender<ResolverEvent>>,
        observations: Arc<AtomicUsize>,
    }

    impl Harness {
        fn session(controllers: Vec<ObservedController>) -> (Self, Box<dyn ResolverSession>) {
            let controllers = Arc::new(Mutex::new(controllers));
            let observations = Arc::new(AtomicUsize::new(0));
            let (events, receiver) = mpsc::unbounded_channel();
            (
                Self {
                    controllers: controllers.clone(),
                    events: Some(events),
                    observations: observations.clone(),
                },
                Box::new(FakeSession {
                    controllers,
                    events: receiver,
                    observations,
                }),
            )
        }

        fn replace(&self, controllers: Vec<ObservedController>, event: ResolverEvent) {
            *self.controllers.lock().unwrap() = controllers;
            self.events.as_ref().unwrap().send(event).unwrap();
        }

        fn event(&self, event: ResolverEvent) {
            self.events.as_ref().unwrap().send(event).unwrap();
        }

        fn lose_owner(&mut self) {
            self.events.take();
        }

        fn observation_count(&self) -> usize {
            self.observations.load(Ordering::SeqCst)
        }
    }

    fn address(last: u8) -> Address {
        Address::from_str(&format!("02:00:00:00:00:{last:02X}")).unwrap()
    }

    fn fingerprint(label: &str) -> ControllerFingerprint {
        ControllerFingerprint::new(
            Some("linux"),
            Some("x86_64"),
            Some("6.18"),
            Some("5.79"),
            Some(label),
            Some("product"),
            Some("revision"),
            Some(&format!("firmware-{label}")),
            Some("driver"),
        )
    }

    fn controller(name: &str, last: u8, fingerprint: ControllerFingerprint) -> ObservedController {
        ObservedController::new(
            ControllerCandidate::from_snapshot(
                name.to_owned(),
                ControllerSnapshot::new(true, address(last), AddressType::LeRandom),
            ),
            fingerprint,
        )
    }

    fn limits() -> ControllerProbeLimits {
        ControllerProbeLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(3),
        )
    }

    fn spawn(
        policy: ControllerAdmissionPolicy,
        limits: ControllerProbeLimits,
        platform: Arc<FakePlatform>,
        probe: Arc<FakeProbe>,
    ) -> (
        LinuxControllerResolver,
        mpsc::Receiver<LifecycleCancellationObserver>,
    ) {
        spawn_linux_controller_resolver_with(
            policy,
            limits,
            BtleOperatorOutput::discard(),
            platform,
            probe,
        )
    }

    fn spawn_with_activator(
        policy: ControllerAdmissionPolicy,
        limits: ControllerProbeLimits,
        platform: Arc<FakePlatform>,
        probe: Arc<FakeProbe>,
        activator: Option<Arc<dyn ControllerEpochActivator>>,
    ) -> (
        LinuxControllerResolver,
        mpsc::Receiver<LifecycleCancellationObserver>,
    ) {
        let (epoch_updates, epochs) = mpsc::channel(8);
        (
            spawn_resolver(
                policy,
                limits,
                BtleOperatorOutput::discard(),
                platform,
                probe,
                activator,
                Some(epoch_updates),
            ),
            epochs,
        )
    }

    fn spawn_with_output(
        session: Box<dyn ResolverSession>,
        activator: Arc<dyn ControllerEpochActivator>,
    ) -> (
        LinuxControllerResolver,
        mpsc::Receiver<BtleOperatorEvent>,
        mpsc::Receiver<LifecycleCancellationObserver>,
    ) {
        let (output, events) = BtleOperatorOutput::bounded();
        let (epoch_updates, epochs) = mpsc::channel(8);
        let resolver = spawn_resolver(
            ControllerAdmissionPolicy::default(),
            limits(),
            output,
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator),
            Some(epoch_updates),
        );
        (resolver, events, epochs)
    }

    fn drain_operator_events(
        events: &mut mpsc::Receiver<BtleOperatorEvent>,
    ) -> Vec<BtleOperatorEvent> {
        let mut drained = Vec::new();
        while let Ok(event) = events.try_recv() {
            drained.push(event);
        }
        drained
    }

    async fn wait_for_events(activator: &RecordingActivator, count: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while activator.events().len() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operational lifecycle events must make progress");
    }

    async fn wait_for_status(
        status: &mut tokio::sync::watch::Receiver<ControllerResolutionSnapshot>,
        availability: RuntimeAvailability,
    ) -> ControllerResolutionSnapshot {
        loop {
            let current = *status.borrow_and_update();
            if current.availability() == availability {
                return current;
            }
            status.changed().await.expect("resolver still running");
        }
    }

    async fn wait_for_disposition(
        status: &mut tokio::sync::watch::Receiver<ControllerResolutionSnapshot>,
        disposition: ProbeDisposition,
    ) -> ControllerResolutionSnapshot {
        loop {
            let current = *status.borrow_and_update();
            if current.disposition() == disposition {
                return current;
            }
            status.changed().await.expect("resolver still running");
        }
    }

    async fn stop(resolver: LinuxControllerResolver) {
        resolver.shutdown().await.unwrap();
    }

    fn test_actor(cancellation: LifecycleCancellation) -> ResolverActor {
        let (updates, _) = tokio::sync::watch::channel(ControllerResolutionSnapshot::initial());
        ResolverActor {
            policy: ControllerAdmissionPolicy::default(),
            limits: limits(),
            platform: Arc::new(FakePlatform::new([])),
            probe: Arc::new(FakeProbe::compatible()),
            activator: Some(Arc::new(TestOperationalActivator)),
            output: BtleOperatorOutput::discard(),
            updates,
            cancellation,
            owner: None,
            operational: None,
            operational_status: None,
            nonterminal_publication: NonterminalPublication::Settled,
            cursor: None,
            inventory_generation: 0,
            backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
            operational_backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
            epoch_updates: None,
        }
    }

    #[tokio::test]
    async fn automatic_controller_passive_selection_stays_unavailable() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let (resolver, mut epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            None,
        );
        let mut status = resolver.status();

        let selected = wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;

        assert_eq!(selected.availability(), RuntimeAvailability::Unavailable);
        assert_eq!(selected.support(), Some(SupportTag::Unqualified));
        assert!(!epochs.recv().await.unwrap().is_cancelled());
        stop(resolver).await;
    }

    #[tokio::test]
    async fn automatic_controller_operational_start_transitions_to_available() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        let selected = wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        assert_eq!(selected.availability(), RuntimeAvailability::Unavailable);

        activator.latest_state(OperationalEpochState::Available);
        let available = wait_for_status(&mut status, RuntimeAvailability::Available).await;

        assert_eq!(available.disposition(), ProbeDisposition::Compatible);
        assert_eq!(activator.activation_count(), 1);
        stop(resolver).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simultaneous_available_and_selected_removal_never_publishes_available() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (harness, session) = Harness::session(vec![selected]);
        let activator = Arc::new(RecordingActivator::default());
        let drain_gate = Arc::new(Notify::new());
        activator.block_quiesce(drain_gate.clone());
        let (resolver, mut operator_events, mut epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();
        drain_operator_events(&mut operator_events);

        activator.latest_state(OperationalEpochState::Available);
        harness.replace(
            Vec::new(),
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );

        wait_for_events(&activator, 1).await;
        let unavailable_before_cleanup =
            status.borrow().availability() == RuntimeAvailability::Unavailable;
        let not_cancelled_before_cleanup = !epoch.is_cancelled();
        let lifecycle_before_cleanup = activator.events();
        let emitted_before_cleanup = drain_operator_events(&mut operator_events);
        let unavailable_emitted_before_cleanup = emitted_before_cleanup
            .iter()
            .any(|event| matches!(event, BtleOperatorEvent::AdapterUnavailable(_)));
        drain_gate.notify_waiters();
        wait_for_events(&activator, 3).await;
        let cancelled_after_cleanup = epoch.is_cancelled();
        let lifecycle = activator.events();
        stop(resolver).await;

        let mut emitted = emitted_before_cleanup;
        emitted.extend(drain_operator_events(&mut operator_events));
        assert!(
            !emitted.contains(&BtleOperatorEvent::AdapterAvailable),
            "selected removal already ready with Available must suppress availability: {emitted:?}"
        );
        assert!(unavailable_before_cleanup);
        assert!(unavailable_emitted_before_cleanup);
        assert_eq!(lifecycle_before_cleanup, ["quiesce"]);
        assert!(not_cancelled_before_cleanup);
        assert_eq!(&lifecycle[..3], ["quiesce", "cancel", "join"]);
        assert!(cancelled_after_cleanup);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn saturated_batch_defers_available_until_queued_selected_removal() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (harness, session) = Harness::session(vec![selected]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, mut operator_events, mut epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();
        drain_operator_events(&mut operator_events);

        activator.latest_state(OperationalEpochState::Available);
        for _ in 0..MAX_EVENTS_PER_BATCH {
            harness.event(ResolverEvent::InventoryChanged { removed: None });
        }
        harness.replace(
            Vec::new(),
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );

        wait_for_events(&activator, 3).await;
        let lifecycle = activator.events();
        let epoch_cancelled = epoch.is_cancelled();
        stop(resolver).await;
        let emitted = drain_operator_events(&mut operator_events);

        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Unavailable
        );
        assert!(
            !emitted.contains(&BtleOperatorEvent::AdapterAvailable),
            "a selected removal queued after a saturated batch must suppress availability: {emitted:?}"
        );
        assert_eq!(&lifecycle[..3], ["quiesce", "cancel", "join"]);
        assert!(epoch_cancelled);
        assert_eq!(activator.activation_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn saturated_batch_retains_available_until_idle_queue_is_proven() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let observations = Arc::new(AtomicUsize::new(0));
        let saturated_sweep_started = Arc::new(Notify::new());
        let allow_saturated_sweep = Arc::new(Notify::new());
        let (events, receiver) = mpsc::unbounded_channel();
        let session: Box<dyn ResolverSession> = Box::new(SaturationGateSession {
            controller: selected,
            events: receiver,
            observations: observations.clone(),
            saturated_sweep_started: saturated_sweep_started.clone(),
            allow_saturated_sweep: allow_saturated_sweep.clone(),
        });
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, mut operator_events, _epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        drain_operator_events(&mut operator_events);

        activator.latest_state(OperationalEpochState::Available);
        for _ in 0..MAX_EVENTS_PER_BATCH {
            events
                .send(ResolverEvent::InventoryChanged { removed: None })
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), saturated_sweep_started.notified())
            .await
            .expect("a saturated batch must start a later bounded sweep");
        let emitted_before_exhaustion = drain_operator_events(&mut operator_events);
        assert!(
            !emitted_before_exhaustion.contains(&BtleOperatorEvent::AdapterAvailable),
            "hitting the cap does not prove the ready queue exhausted: {emitted_before_exhaustion:?}"
        );

        allow_saturated_sweep.notify_one();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        let mut emitted = emitted_before_exhaustion;
        emitted.extend(drain_operator_events(&mut operator_events));
        stop(resolver).await;

        assert_eq!(observations.load(Ordering::SeqCst), 2);
        assert_eq!(
            emitted
                .iter()
                .filter(|event| **event == BtleOperatorEvent::AdapterAvailable)
                .count(),
            1,
            "the retained state must publish once after an idle queue is proven: {emitted:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selected_removal_preempts_continuous_nonterminal_status_flood() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (harness, session) = Harness::session(vec![selected]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, mut operator_events, mut epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();
        drain_operator_events(&mut operator_events);

        harness.replace(
            Vec::new(),
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );
        let flood = activator.flood_nonterminal_states(MAX_EVENTS_PER_BATCH + 1);

        wait_for_events(&activator, 3).await;
        let lifecycle = activator.events();
        let epoch_cancelled = epoch.is_cancelled();
        flood.abort();
        let _ = flood.await;
        resolver.cancel();
        tokio::time::timeout(Duration::from_secs(1), resolver.shutdown())
            .await
            .expect("cancellation must join after removal during a status flood")
            .unwrap();
        let emitted = drain_operator_events(&mut operator_events);

        assert!(
            !emitted.contains(&BtleOperatorEvent::AdapterAvailable),
            "status flood must not flap availability before selected removal: {emitted:?}"
        );
        assert_eq!(&lifecycle[..3], ["quiesce", "cancel", "join"]);
        assert!(epoch_cancelled);
        assert_eq!(activator.activation_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_controller_persistent_operational_denial_uses_capped_retry() {
        let (harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let activator = Arc::new(RecordingActivator::default());
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;

        activator.latest_state(OperationalEpochState::Unavailable);
        wait_for_events(&activator, 3).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(activator.activation_count(), 1);
        assert_eq!(probe.calls(), ["hci0"]);

        tokio::time::advance(Duration::from_millis(100)).await;
        harness.event(ResolverEvent::InventoryChanged { removed: None });
        tokio::task::yield_now().await;
        assert_eq!(activator.activation_count(), 1);
        tokio::time::advance(INITIAL_RESOLVER_RETRY - Duration::from_millis(101)).await;
        tokio::task::yield_now().await;
        assert_eq!(activator.activation_count(), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        while activator.activation_count() < 2 {
            tokio::task::yield_now().await;
        }

        activator.latest_state(OperationalEpochState::Unavailable);
        wait_for_events(&activator, 6).await;
        tokio::time::advance(INITIAL_RESOLVER_RETRY * 2 - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(activator.activation_count(), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        while activator.activation_count() < 3 {
            tokio::task::yield_now().await;
        }

        assert_eq!(probe.calls(), ["hci0", "hci0", "hci0"]);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_controller_join_failure_is_terminal_and_forces_after_unavailable() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let activator = Arc::new(RecordingActivator::default());
        let quiesce = Arc::new(Notify::new());
        activator.block_quiesce(quiesce.clone());
        activator.fail_join();
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        activator.latest_state(OperationalEpochState::Available);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        activator.latest_state(OperationalEpochState::Unavailable);
        wait_for_status(&mut status, RuntimeAvailability::Unavailable).await;
        wait_for_events(&activator, 1).await;
        assert_eq!(activator.events(), ["quiesce"]);
        quiesce.notify_one();
        wait_for_events(&activator, 4).await;
        assert_eq!(activator.events(), ["quiesce", "cancel", "join", "force"]);

        tokio::time::advance(INITIAL_RESOLVER_RETRY * 4).await;
        tokio::task::yield_now().await;
        assert_eq!(activator.activation_count(), 1);
        assert!(resolver.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn operational_status_closure_preempts_continuously_ready_unrelated_inventory() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (flood_updates, flooding) = watch::channel(false);
        let inventory_events = Arc::new(AtomicUsize::new(0));
        let session: Box<dyn ResolverSession> = Box::new(HealthyEventFloodSession {
            controller: selected,
            flooding,
            events: inventory_events.clone(),
        });
        let activator = Arc::new(ClosingStatusActivator::default());
        let (resolver, mut operator_events, _epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        let mut terminal_status = resolver.status();
        let (completion_updates, mut completion) = watch::channel(false);
        let outer = tokio::spawn(async move {
            while terminal_status.changed().await.is_ok() {}
            let result = resolver.shutdown_for_supervisor().await;
            completion_updates.send_replace(true);
            result
        });

        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        activator.publish(OperationalEpochState::Available);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        flood_updates.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), async {
            while inventory_events.load(Ordering::SeqCst) < MAX_EVENTS_PER_BATCH {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unrelated inventory flood must become continuously ready");
        let events_before_close = inventory_events.load(Ordering::SeqCst);

        activator.close_status();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !*completion.borrow_and_update() {
                completion
                    .changed()
                    .await
                    .expect("outer owner still running");
            }
        })
        .await
        .expect("operational status closure must wake outer completion");
        assert!(outer.await.unwrap().is_err());
        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Unavailable
        );
        assert!(activator.forced.load(Ordering::Acquire));
        assert_eq!(
            *activator.events.lock().unwrap(),
            ["unavailable", "cancel", "join", "force"]
        );
        assert_eq!(activator.activations.load(Ordering::SeqCst), 1);
        assert!(
            inventory_events.load(Ordering::SeqCst) - events_before_close <= MAX_EVENTS_PER_BATCH,
            "operational closure must be observed within one bounded inventory batch"
        );
        let emitted = drain_operator_events(&mut operator_events);
        let available = emitted
            .iter()
            .position(|event| *event == BtleOperatorEvent::AdapterAvailable)
            .expect("host must first publish Available");
        assert!(
            emitted[available + 1..]
                .iter()
                .any(|event| { matches!(event, BtleOperatorEvent::AdapterUnavailable(_)) })
        );
    }

    #[tokio::test]
    async fn saturated_pending_available_yields_to_operational_status_closure() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (flood_updates, flooding) = watch::channel(false);
        let inventory_events = Arc::new(AtomicUsize::new(0));
        let session: Box<dyn ResolverSession> = Box::new(HealthyEventFloodSession {
            controller: selected,
            flooding,
            events: inventory_events.clone(),
        });
        let activator = Arc::new(ClosingStatusActivator::default());
        let (resolver, mut operator_events, _epochs) =
            spawn_with_output(session, activator.clone());
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        drain_operator_events(&mut operator_events);

        flood_updates.send_replace(true);
        activator.publish(OperationalEpochState::Available);
        tokio::time::timeout(Duration::from_secs(1), async {
            while inventory_events.load(Ordering::SeqCst) <= MAX_EVENTS_PER_BATCH {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending availability must remain retained into a later bounded batch");
        let emitted_before_close = drain_operator_events(&mut operator_events);
        assert!(
            !emitted_before_close.contains(&BtleOperatorEvent::AdapterAvailable),
            "continuous unrelated inventory may defer but never prematurely publish availability: {emitted_before_close:?}"
        );
        let events_before_close = inventory_events.load(Ordering::SeqCst);

        activator.close_status();
        tokio::time::timeout(Duration::from_secs(1), async {
            while status.changed().await.is_ok() {}
        })
        .await
        .expect("operational status closure must terminate a saturated pending state");
        let result = resolver.shutdown_for_supervisor().await;
        let mut emitted = emitted_before_close;
        emitted.extend(drain_operator_events(&mut operator_events));

        assert!(result.is_err());
        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Unavailable
        );
        assert!(activator.forced.load(Ordering::Acquire));
        assert_eq!(
            *activator.events.lock().unwrap(),
            ["unavailable", "cancel", "join", "force"]
        );
        assert_eq!(activator.activations.load(Ordering::SeqCst), 1);
        assert!(
            inventory_events.load(Ordering::SeqCst) - events_before_close <= MAX_EVENTS_PER_BATCH,
            "operational closure must win within one bounded saturated batch"
        );
        assert!(
            !emitted.contains(&BtleOperatorEvent::AdapterAvailable),
            "closure must suppress the retained availability state: {emitted:?}"
        );
    }

    #[tokio::test]
    async fn automatic_controller_unrelated_event_retains_operational_handle() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (harness, session) = Harness::session(vec![selected.clone()]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        activator.latest_state(OperationalEpochState::Available);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        harness.replace(
            vec![selected, controller("hci1", 2, fingerprint("b"))],
            ResolverEvent::InventoryChanged { removed: None },
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while harness.observation_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unrelated inventory change must be observed");

        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Available
        );
        assert_eq!(activator.activation_count(), 1);
        assert!(activator.events().is_empty());
        stop(resolver).await;
    }

    #[tokio::test]
    async fn automatic_controller_selected_loss_is_unavailable_before_child_drain() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let replacement = controller("hci1", 2, fingerprint("b"));
        let (harness, session) = Harness::session(vec![selected]);
        let activator = Arc::new(RecordingActivator::default());
        let drain_gate = Arc::new(Notify::new());
        activator.block_quiesce(drain_gate.clone());
        let (resolver, mut epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();
        activator.latest_state(OperationalEpochState::Available);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        harness.replace(
            vec![replacement],
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );
        wait_for_status(&mut status, RuntimeAvailability::Unavailable).await;
        wait_for_events(&activator, 1).await;

        assert_eq!(activator.events(), vec!["quiesce"]);
        assert!(!epoch.is_cancelled());

        activator.allow_future_quiesce();
        drain_gate.notify_waiters();
        wait_for_events(&activator, 3).await;
        assert_eq!(&activator.events()[..3], ["quiesce", "cancel", "join"]);
        assert!(epoch.is_cancelled());
        stop(resolver).await;
    }

    #[tokio::test]
    async fn automatic_controller_child_loss_is_unavailable_before_epoch_cancel() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let activator = Arc::new(RecordingActivator::default());
        let drain_gate = Arc::new(Notify::new());
        activator.block_quiesce(drain_gate.clone());
        let (resolver, mut epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();
        activator.latest_state(OperationalEpochState::Available);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        activator.latest_state(OperationalEpochState::Unavailable);
        wait_for_status(&mut status, RuntimeAvailability::Unavailable).await;
        wait_for_events(&activator, 1).await;

        assert_eq!(activator.events(), vec!["quiesce"]);
        assert!(!epoch.is_cancelled());

        activator.allow_future_quiesce();
        drain_gate.notify_waiters();
        wait_for_events(&activator, 3).await;
        assert!(epoch.is_cancelled());
        stop(resolver).await;
    }

    #[tokio::test]
    async fn automatic_controller_shutdown_joins_operational_epoch() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, mut epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        let mut status = resolver.status();
        wait_for_disposition(&mut status, ProbeDisposition::Compatible).await;
        let epoch = epochs.recv().await.unwrap();

        resolver.shutdown().await.unwrap();

        assert!(epoch.is_cancelled());
        assert_eq!(activator.events(), vec!["quiesce", "cancel", "join"]);
    }

    #[tokio::test]
    async fn unknown_compatible_controller_is_selected_unqualified() {
        let (harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let platform = Arc::new(FakePlatform::new([Ok(session)]));
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            platform,
            probe,
        );
        let mut status = resolver.status();

        let selected = wait_for_status(&mut status, RuntimeAvailability::Available).await;

        assert_eq!(selected.disposition(), ProbeDisposition::Compatible);
        assert_eq!(selected.support(), Some(SupportTag::Unqualified));
        assert_eq!(harness.observation_count(), 1);
        stop(resolver).await;
    }

    #[tokio::test]
    async fn qualified_is_tie_breaker_not_gate() {
        let qualified = fingerprint("qualified");
        let (harness, session) = Harness::session(vec![
            controller("hci0", 1, fingerprint("unknown")),
            controller("hci1", 2, qualified.clone()),
        ]);
        let policy = ControllerAdmissionPolicy::with_rows(
            false,
            vec![SupportRow::exact(qualified)],
            Vec::new(),
        );
        let platform = Arc::new(FakePlatform::new([Ok(session)]));
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn(policy, limits(), platform, probe.clone());
        let mut status = resolver.status();

        let selected = wait_for_status(&mut status, RuntimeAvailability::Available).await;

        assert_eq!(selected.support(), Some(SupportTag::Qualified));
        assert_eq!(probe.calls().first().map(String::as_str), Some("hci1"));
        assert_eq!(harness.observation_count(), 1);
        stop(resolver).await;
    }

    #[tokio::test]
    async fn qualified_only_rejects_unknown() {
        let (_harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let platform = Arc::new(FakePlatform::new([Ok(session)]));
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::with_qualified_only(true),
            limits(),
            platform,
            probe.clone(),
        );
        let mut status = resolver.status();

        let rejected = wait_for_disposition(
            &mut status,
            ProbeDisposition::Blocked(ProbeReason::QualifiedOnly),
        )
        .await;

        assert_eq!(rejected.support(), Some(SupportTag::Unqualified));
        assert_eq!(
            rejected.disposition(),
            ProbeDisposition::Blocked(ProbeReason::QualifiedOnly)
        );
        assert!(probe.calls().is_empty());
        stop(resolver).await;
    }

    #[tokio::test]
    async fn blocked_and_incompatible_are_distinct() {
        let blocked_fingerprint = fingerprint("blocked");
        let (_blocked_harness, blocked_session) =
            Harness::session(vec![controller("hci0", 1, blocked_fingerprint.clone())]);
        let blocked_policy = ControllerAdmissionPolicy::with_rows(
            false,
            Vec::new(),
            vec![UnsafeRule::exact(blocked_fingerprint)],
        );
        let (blocked, _epochs) = spawn(
            blocked_policy,
            limits(),
            Arc::new(FakePlatform::new([Ok(blocked_session)])),
            Arc::new(FakeProbe::compatible()),
        );
        let mut blocked_status = blocked.status();
        let blocked_snapshot = wait_for_disposition(
            &mut blocked_status,
            ProbeDisposition::Blocked(ProbeReason::KnownUnsafe),
        )
        .await;

        let (_incompatible_harness, incompatible_session) =
            Harness::session(vec![controller("hci0", 1, fingerprint("other"))]);
        let incompatible_probe = Arc::new(FakeProbe::with(
            "hci0",
            ProbeBehavior::Immediate(ProbeDisposition::Incompatible(
                ProbeReason::UnsupportedLeCoc,
            )),
        ));
        let (incompatible, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(incompatible_session)])),
            incompatible_probe,
        );
        let mut incompatible_status = incompatible.status();
        let incompatible_snapshot = wait_for_disposition(
            &mut incompatible_status,
            ProbeDisposition::Incompatible(ProbeReason::UnsupportedLeCoc),
        )
        .await;

        assert_eq!(
            blocked_snapshot.disposition(),
            ProbeDisposition::Blocked(ProbeReason::KnownUnsafe)
        );
        assert_eq!(
            incompatible_snapshot.disposition(),
            ProbeDisposition::Incompatible(ProbeReason::UnsupportedLeCoc)
        );
        stop(blocked).await;
        stop(incompatible).await;
    }

    #[tokio::test]
    async fn selector_snapshot_never_contains_address_name_or_firmware_text() {
        let secret_fingerprint = fingerprint("secret-marker");
        let (_harness, session) =
            Harness::session(vec![controller("hci7654321", 0xA5, secret_fingerprint)]);
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
        );
        let mut status = resolver.status();

        let selected = wait_for_status(&mut status, RuntimeAvailability::Available).await;
        let debug = format!("{selected:?}");

        assert!(!debug.contains("hci7654321"));
        assert!(!debug.contains("02:00:00:00:00:A5"));
        assert!(!debug.contains("secret-marker"));
        stop(resolver).await;
    }

    #[tokio::test]
    async fn healthy_selection_survives_unrelated_addition() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let (harness, session) = Harness::session(vec![selected.clone()]);
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        let mut status = resolver.status();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        harness.replace(
            vec![selected, controller("hci1", 2, fingerprint("b"))],
            ResolverEvent::InventoryChanged { removed: None },
        );
        for _ in 1..100 {
            harness.event(ResolverEvent::InventoryChanged { removed: None });
        }
        while harness.observation_count() < 2 {
            tokio::task::yield_now().await;
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Available
        );
        assert_eq!(probe.calls(), vec!["hci0"]);
        assert_eq!(harness.observation_count(), 2);
        stop(resolver).await;
    }

    #[tokio::test]
    async fn selected_loss_cancels_epoch_before_replacement() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let replacement = controller("hci1", 2, fingerprint("b"));
        let (harness, session) = Harness::session(vec![selected]);
        let gate = Arc::new(Notify::new());
        let probe = Arc::new(FakeProbe::with("hci1", ProbeBehavior::Gated(gate.clone())));
        let (resolver, mut epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        let mut status = resolver.status();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        let epoch = epochs.recv().await.unwrap();

        harness.replace(
            vec![replacement],
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );
        probe.wait_for_calls(2).await;

        assert!(epoch.is_cancelled());
        assert_eq!(
            status.borrow().availability(),
            RuntimeAvailability::Unavailable
        );
        gate.notify_waiters();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn early_timeout_does_not_starve_later_candidate() {
        let (_harness, session) = Harness::session(vec![
            controller("hci0", 1, fingerprint("a")),
            controller("hci1", 2, fingerprint("b")),
        ]);
        let probe = Arc::new(FakeProbe::with("hci0", ProbeBehavior::Pending));
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        let mut status = resolver.status();
        probe.wait_for_calls(1).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        assert_eq!(probe.calls(), vec!["hci0", "hci1"]);
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn unfinished_candidates_rotate_to_next_sweep() {
        let qualified = fingerprint("qualified");
        let (_harness, session) = Harness::session(vec![
            controller("hci0", 1, fingerprint("a")),
            controller("hci1", 2, qualified.clone()),
        ]);
        let probe = Arc::new(FakeProbe::with("hci1", ProbeBehavior::Pending));
        let tight = ControllerProbeLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(1),
        );
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::with_rows(
                false,
                vec![SupportRow::exact(qualified)],
                Vec::new(),
            ),
            tight,
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        let mut status = resolver.status();
        probe.wait_for_calls(1).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(INITIAL_RESOLVER_RETRY).await;
        tokio::time::timeout(Duration::from_secs(1), probe.wait_for_calls(2))
            .await
            .expect("unfinished sweep retries without a platform event");

        assert_eq!(probe.calls(), vec!["hci1", "hci0"]);
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn change_storm_coalesces_into_one_pending_sweep() {
        let (harness, session) = Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let probe = Arc::new(FakeProbe::with(
            "hci0",
            ProbeBehavior::Immediate(ProbeDisposition::Incompatible(
                ProbeReason::UnsupportedLeCoc,
            )),
        ));
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        probe.wait_for_calls(1).await;

        for _ in 0..100 {
            harness.event(ResolverEvent::ControllerChanged("hci0".to_owned()));
        }
        probe.wait_for_calls(2).await;
        tokio::task::yield_now().await;
        assert_eq!(probe.calls().len(), 2);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stable_empty_inventory_waits_for_an_event() {
        let (empty_harness, empty_session) = Harness::session(Vec::new());
        let (empty, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(empty_session)])),
            Arc::new(FakeProbe::compatible()),
        );
        while empty_harness.observation_count() < 1 {
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(300)).await;
        tokio::task::yield_now().await;
        assert_eq!(empty_harness.observation_count(), 1);
        empty_harness.event(ResolverEvent::InventoryChanged { removed: None });
        while empty_harness.observation_count() < 2 {
            tokio::task::yield_now().await;
        }
        stop(empty).await;
    }

    #[tokio::test(start_paused = true)]
    async fn transient_indeterminate_probe_recovers_without_an_event() {
        let (indeterminate_harness, indeterminate_session) =
            Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let probe = Arc::new(FakeProbe::with(
            "hci0",
            ProbeBehavior::Immediate(ProbeDisposition::Indeterminate(
                ProbeReason::ResourceExhausted,
            )),
        ));
        let (indeterminate, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(indeterminate_session)])),
            probe.clone(),
        );
        probe.wait_for_calls(1).await;

        probe.behaviors.lock().unwrap().insert(
            "hci0".to_owned(),
            ProbeBehavior::Immediate(ProbeDisposition::Compatible),
        );
        tokio::time::advance(INITIAL_RESOLVER_RETRY).await;
        tokio::time::timeout(Duration::from_secs(1), probe.wait_for_calls(2))
            .await
            .expect("indeterminate probe retries without a platform event");
        let mut status = indeterminate.status();
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_status(&mut status, RuntimeAvailability::Available),
        )
        .await
        .expect("recovered controller becomes available");
        assert_eq!(indeterminate_harness.observation_count(), 2);
        stop(indeterminate).await;
    }

    #[tokio::test(start_paused = true)]
    async fn activation_failure_falls_through_to_the_next_controller() {
        let (_harness, session) = Harness::session(vec![
            controller("hci0", 1, fingerprint("a")),
            controller("hci1", 2, fingerprint("b")),
        ]);
        let probe = Arc::new(FakeProbe::compatible());
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
            Some(Arc::new(FailFirstActivator::default())),
        );
        let mut status = resolver.status();

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_status(&mut status, RuntimeAvailability::Available),
        )
        .await
        .expect("later controller becomes available after activation failure");

        assert_eq!(probe.calls(), vec!["hci0", "hci1"]);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn failed_operational_epoch_rotates_to_the_next_controller() {
        let (_harness, session) = Harness::session(vec![
            controller("hci0", 1, fingerprint("a")),
            controller("hci1", 2, fingerprint("b")),
        ]);
        let activator = Arc::new(RecordingActivator::default());
        let (resolver, _epochs) = spawn_with_activator(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            Arc::new(FakeProbe::compatible()),
            Some(activator.clone()),
        );
        while activator.activation_count() < 1 {
            tokio::task::yield_now().await;
        }

        activator.latest_state(OperationalEpochState::Unavailable);
        wait_for_events(&activator, 3).await;
        tokio::time::advance(INITIAL_RESOLVER_RETRY).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while activator.activation_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operational failure rotates without a platform event");

        assert_eq!(activator.selected(), vec!["hci0", "hci1"]);
        activator.latest_state(OperationalEpochState::Available);
        let mut status = resolver.status();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        stop(resolver).await;
    }

    #[tokio::test]
    async fn production_unrelated_event_batch_is_bounded() {
        let mut adapter_events = SelectAll::new();
        adapter_events.push(
            futures::stream::iter(
                std::iter::repeat_n(AdapterSignal::Unrelated, 1_024)
                    .map(|event| ("hci0".to_owned(), Some(event))),
            )
            .chain(futures::stream::pending())
            .boxed(),
        );
        let mut session = BluezResolverSession {
            session: Box::new(PendingBluezSession),
            session_events: Box::pin(futures::stream::pending()),
            adapter_events,
        };

        let event = tokio::time::timeout(Duration::from_millis(20), session.next_event()).await;

        assert!(
            event.is_ok(),
            "one call must yield after bounded ready work"
        );
        assert!(event.unwrap().is_some());
    }

    #[tokio::test]
    async fn continuously_ready_events_preserve_cancel_and_shutdown_progress() {
        let cancellation = LifecycleCancellation::new();
        let events = Arc::new(AtomicUsize::new(0));
        let mut session = CancellationStormSession {
            cancellation: cancellation.clone(),
            events: events.clone(),
        };
        let mut actor = test_actor(cancellation);

        let outcome = actor.wait_healthy_event(&mut session).await;

        assert!(matches!(outcome, SessionAction::Cancelled));
        assert!(events.load(Ordering::SeqCst) <= 32);
    }

    #[tokio::test]
    async fn continuously_ready_batches_yield_for_sweeps_and_external_cancellation() {
        let cancellation = LifecycleCancellation::new();
        let observations = Arc::new(AtomicUsize::new(0));
        let mut actor = test_actor(cancellation.clone());
        let session_observations = observations.clone();
        let actor_task = tokio::spawn(async move {
            let mut session = AlwaysReadySession {
                observations: session_observations,
            };
            actor.run_session(&mut session).await
        });

        tokio::time::timeout(Duration::from_millis(100), async {
            while observations.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded ready batches must yield after making sweep progress");
        cancellation.cancel();
        let outcome = tokio::time::timeout(Duration::from_millis(100), actor_task)
            .await
            .expect("cancellation must join a continuously-ready session")
            .expect("actor task must not panic");

        assert!(matches!(outcome, SessionAction::Cancelled));
    }

    #[tokio::test(start_paused = true)]
    async fn operational_retry_deadline_wins_over_continuously_ready_unrelated_events() {
        let cancellation = LifecycleCancellation::new();
        let events = Arc::new(AtomicUsize::new(0));
        let mut actor = test_actor(cancellation);
        let task_events = events.clone();
        let retry = tokio::spawn(async move {
            let mut session = OperationalRetryFloodSession {
                events: task_events,
            };
            actor.wait_operational_retry(&mut session).await
        });

        while events.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        tokio::time::advance(INITIAL_RESOLVER_RETRY - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!retry.is_finished());
        let before_deadline = events.load(Ordering::SeqCst);

        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            retry.is_finished(),
            "expired retry must not lose to event flood"
        );
        let outcome = retry.await.unwrap();
        assert!(matches!(outcome, SessionAction::Sweep));
        assert!(
            events.load(Ordering::SeqCst) - before_deadline <= MAX_EVENTS_PER_BATCH,
            "deadline check must bound post-expiry event drainage"
        );
    }

    #[tokio::test]
    async fn operational_retry_cancellation_wins_over_continuously_ready_events() {
        let cancellation = LifecycleCancellation::new();
        let events = Arc::new(AtomicUsize::new(0));
        let mut session = CancellationStormSession {
            cancellation: cancellation.clone(),
            events: events.clone(),
        };
        let mut actor = test_actor(cancellation);

        let outcome = actor.wait_operational_retry(&mut session).await;

        assert!(matches!(outcome, SessionAction::Cancelled));
        assert!(events.load(Ordering::SeqCst) <= MAX_EVENTS_PER_BATCH);
    }

    #[tokio::test(start_paused = true)]
    async fn fairness_cursor_tracks_identity_across_reorder_and_addition() {
        let qualified = fingerprint("qualified-hci1");
        let (harness, session) = Harness::session(vec![
            controller("hci1", 1, qualified.clone()),
            controller("hci2", 2, fingerprint("compatible")),
        ]);
        let probe = Arc::new(FakeProbe::with("hci1", ProbeBehavior::Pending));
        let tight = ControllerProbeLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(1),
        );
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::with_rows(
                false,
                vec![SupportRow::exact(qualified.clone())],
                Vec::new(),
            ),
            tight,
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        probe.wait_for_calls(1).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        harness.replace(
            vec![
                controller("hci0", 3, fingerprint("new")),
                controller("hci1", 1, qualified),
                controller("hci2", 2, fingerprint("compatible")),
            ],
            ResolverEvent::InventoryChanged { removed: None },
        );
        probe.wait_for_calls(2).await;

        assert_eq!(probe.calls(), vec!["hci1", "hci2"]);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn disappeared_fairness_cursor_restores_qualified_first_order() {
        let removed = fingerprint("qualified-removed");
        let new_qualified = fingerprint("qualified-new");
        let (harness, session) = Harness::session(vec![
            controller("hci1", 1, removed.clone()),
            controller("hci2", 2, fingerprint("compatible")),
        ]);
        let probe = Arc::new(FakeProbe::with("hci1", ProbeBehavior::Pending));
        probe
            .behaviors
            .lock()
            .unwrap()
            .insert("hci0".to_owned(), ProbeBehavior::Pending);
        let tight = ControllerProbeLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(1),
        );
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::with_rows(
                false,
                vec![
                    SupportRow::exact(removed),
                    SupportRow::exact(new_qualified.clone()),
                ],
                Vec::new(),
            ),
            tight,
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        probe.wait_for_calls(1).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        harness.replace(
            vec![
                controller("hci0", 3, new_qualified),
                controller("hci2", 2, fingerprint("compatible")),
            ],
            ResolverEvent::InventoryChanged {
                removed: Some("hci1".to_owned()),
            },
        );
        probe.wait_for_calls(2).await;

        assert_eq!(probe.calls(), vec!["hci1", "hci0"]);
        stop(resolver).await;
    }

    #[tokio::test(start_paused = true)]
    async fn bluez_owner_loss_publishes_unavailable_before_retry() {
        let (mut first, first_session) =
            Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let (_second, second_session) =
            Harness::session(vec![controller("hci0", 1, fingerprint("a"))]);
        let platform = Arc::new(FakePlatform::new([Ok(first_session), Ok(second_session)]));
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            platform.clone(),
            Arc::new(FakeProbe::compatible()),
        );
        let mut status = resolver.status();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;

        first.lose_owner();
        wait_for_status(&mut status, RuntimeAvailability::Unavailable).await;

        assert_eq!(platform.open_count(), 1);
        tokio::time::advance(INITIAL_RESOLVER_RETRY).await;
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        assert_eq!(platform.open_count(), 2);
        stop(resolver).await;
    }

    #[tokio::test]
    async fn shutdown_joins_probe_and_epoch_cleanup() {
        let selected = controller("hci0", 1, fingerprint("a"));
        let replacement = controller("hci1", 2, fingerprint("b"));
        let (harness, session) = Harness::session(vec![selected]);
        let probe = Arc::new(FakeProbe::with("hci1", ProbeBehavior::Pending));
        let (resolver, mut epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        let mut status = resolver.status();
        wait_for_status(&mut status, RuntimeAvailability::Available).await;
        let epoch = epochs.recv().await.unwrap();
        harness.replace(
            vec![replacement],
            ResolverEvent::InventoryChanged {
                removed: Some("hci0".to_owned()),
            },
        );
        probe.wait_for_calls(2).await;

        resolver.shutdown().await.unwrap();

        assert!(epoch.is_cancelled());
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dropping_resolver_releases_active_probe_custody() {
        let (_harness, session) =
            Harness::session(vec![controller("hci0", 1, fingerprint("pending-probe"))]);
        let probe = Arc::new(FakeProbe::with("hci0", ProbeBehavior::Pending));
        let (resolver, _epochs) = spawn(
            ControllerAdmissionPolicy::default(),
            limits(),
            Arc::new(FakePlatform::new([Ok(session)])),
            probe.clone(),
        );
        probe.wait_for_calls(1).await;
        assert_eq!(probe.active.load(Ordering::SeqCst), 1);

        drop(resolver);
        tokio::time::timeout(Duration::from_secs(1), async {
            while probe.active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping resolver releases active probe custody");
    }
}
