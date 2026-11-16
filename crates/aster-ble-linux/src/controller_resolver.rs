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
    policy::CappedBackoff,
};
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

/// Runtime state of automatic Linux controller resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAvailability {
    /// No controller epoch is currently usable.
    Unavailable,
    /// One compatible controller epoch is selected.
    Available,
    /// Operator-only degraded state; not selected as available unless the full path is usable.
    Degraded,
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
pub struct ControllerEpochOwner {
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
    task: JoinHandle<()>,
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
        self.cancel();
        self.task.await.map_err(|_| {
            DriverError::new(
                DriverErrorKind::Transport,
                "automatic controller resolver task stopped",
            )
        })?;
        self.output.emit(BtleOperatorEvent::Stopped);
        Ok(())
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
    output: BtleOperatorOutput,
    updates: watch::Sender<ControllerResolutionSnapshot>,
    cancellation: LifecycleCancellation,
    owner: Option<ControllerEpochOwner>,
    cursor: Option<String>,
    inventory_generation: u64,
    backoff: CappedBackoff,
    #[cfg(test)]
    epoch_updates: Option<tokio::sync::mpsc::UnboundedSender<LifecycleCancellation>>,
}

enum SessionAction {
    Sweep,
    Lost,
    Cancelled,
}

impl ResolverActor {
    async fn run(mut self) {
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
                    self.invalidate_owner(failure.disposition());
                    if wait_delay(&self.cancellation, self.backoff.next_delay()).await {
                        break;
                    }
                    continue;
                }
            };

            match self.run_session(session.as_mut()).await {
                SessionAction::Cancelled => break,
                SessionAction::Lost => {
                    self.invalidate_owner(ProbeDisposition::Indeterminate(
                        ProbeReason::BluezUnavailable,
                    ));
                    if wait_delay(&self.cancellation, self.backoff.next_delay()).await {
                        break;
                    }
                }
                SessionAction::Sweep => unreachable!("session runner consumes sweep actions"),
            }
        }
        self.owner.take();
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
                        outcome => return outcome,
                    }
                }
                self.invalidate_owner(ProbeDisposition::Indeterminate(
                    ProbeReason::BluezUnavailable,
                ));
            }

            match self.probe_sweep(observed).await {
                Some(()) => {}
                None => return SessionAction::Cancelled,
            }
            if self.owner.is_some() {
                self.backoff.reset();
                match self.wait_healthy_event(session).await {
                    SessionAction::Sweep => continue,
                    outcome => return outcome,
                }
            }

            match self.wait_pending_sweep(session).await {
                SessionAction::Sweep => {}
                outcome => return outcome,
            }
        }
    }

    async fn probe_sweep(&mut self, observed: ObservedInventory) -> Option<()> {
        if observed.controllers.is_empty() {
            self.cursor = None;
            self.publish(ControllerResolutionSnapshot::unavailable(
                ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable),
                None,
            ));
            return Some(());
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
                () = self.cancellation.cancelled() => return None,
                result = timeout(candidate_limit, self.probe.probe(
                    &controller.candidate,
                    &controller.fingerprint,
                    &self.policy,
                    &self.cancellation,
                    self.limits,
                )) => result.unwrap_or(ProbeDisposition::Indeterminate(ProbeReason::DeadlineExceeded)),
            };
            if disposition == ProbeDisposition::Compatible {
                self.cursor = None;
                let support = admission.support();
                self.select(controller.clone(), support);
                return Some(());
            }

            last =
                ControllerResolutionSnapshot::unavailable(disposition, Some(admission.support()));
            if Instant::now() >= deadline {
                sweep_unfinished = true;
                break;
            }
        }

        if !sweep_unfinished {
            self.cursor = None;
        }
        self.publish(last);
        Some(())
    }

    fn select(&mut self, controller: ObservedController, support: SupportTag) {
        let owner = ControllerEpochOwner::new(controller, support, self.inventory_generation);
        #[cfg(test)]
        if let Some(updates) = &self.epoch_updates {
            let _ = updates.send(owner.cancellation.clone());
        }
        self.owner = Some(owner);
        self.publish(ControllerResolutionSnapshot::available(support));
    }

    fn invalidate_owner(&mut self, disposition: ProbeDisposition) {
        self.owner.take();
        self.publish(ControllerResolutionSnapshot::unavailable(disposition, None));
    }

    async fn wait_healthy_event(&mut self, session: &mut dyn ResolverSession) -> SessionAction {
        let event = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return SessionAction::Cancelled,
            event = session.next_event() => event,
        };
        let Some(event) = event else {
            return SessionAction::Lost;
        };
        self.consume_event_batch(session, event).await
    }

    async fn consume_event_batch(
        &mut self,
        session: &mut dyn ResolverSession,
        first: ResolverEvent,
    ) -> SessionAction {
        if self.cancellation.is_cancelled() {
            return SessionAction::Cancelled;
        }
        self.apply_event(first);
        for _ in 1..MAX_EVENTS_PER_BATCH {
            if self.cancellation.is_cancelled() {
                return SessionAction::Cancelled;
            }
            match session.next_event().now_or_never() {
                Some(Some(event)) => self.apply_event(event),
                Some(None) => return SessionAction::Lost,
                None => return SessionAction::Sweep,
            }
        }
        tokio::task::yield_now().await;
        if self.cancellation.is_cancelled() {
            return SessionAction::Cancelled;
        }
        SessionAction::Sweep
    }

    fn apply_event(&mut self, event: ResolverEvent) {
        let selected = self.owner.as_ref().map(|owner| owner.name());
        let invalidates = match &event {
            ResolverEvent::InventoryChanged {
                removed: Some(name),
            } => selected == Some(name.as_str()),
            ResolverEvent::ControllerChanged(name) => selected == Some(name.as_str()),
            ResolverEvent::InventoryChanged { removed: None } => false,
        };
        if invalidates {
            self.invalidate_owner(ProbeDisposition::Indeterminate(
                ProbeReason::BluezUnavailable,
            ));
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
        self.consume_event_batch(session, event).await
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
    #[cfg(test)] epoch_updates: Option<tokio::sync::mpsc::UnboundedSender<LifecycleCancellation>>,
    #[cfg(not(test))] _epoch_updates: Option<()>,
) -> LinuxControllerResolver {
    let cancellation = LifecycleCancellation::new();
    let (updates, status) = watch::channel(ControllerResolutionSnapshot::initial());
    let actor = ResolverActor {
        policy,
        limits,
        platform,
        probe,
        output: output.clone(),
        updates,
        cancellation: cancellation.clone(),
        owner: None,
        cursor: None,
        inventory_generation: 0,
        backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
        #[cfg(test)]
        epoch_updates,
    };
    let task = tokio::spawn(actor.run());
    LinuxControllerResolver {
        status,
        cancellation,
        output,
        task,
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
    tokio::sync::mpsc::UnboundedReceiver<LifecycleCancellation>,
) {
    let (epoch_updates, epochs) = tokio::sync::mpsc::unbounded_channel();
    (
        spawn_resolver(policy, limits, output, platform, probe, Some(epoch_updates)),
        epochs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BtleOperatorOutput, ControllerAdmissionPolicy, ControllerCandidate, ControllerFingerprint,
        ControllerProbeLimits, ControllerSnapshot, LifecycleCancellation, ProbeDisposition,
        ProbeReason, RuntimeAvailability, SupportRow, SupportTag, UnsafeRule,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::{HashMap, VecDeque},
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
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
        mpsc::UnboundedReceiver<LifecycleCancellation>,
    ) {
        spawn_linux_controller_resolver_with(
            policy,
            limits,
            BtleOperatorOutput::discard(),
            platform,
            probe,
        )
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
            output: BtleOperatorOutput::discard(),
            updates,
            cancellation,
            owner: None,
            cursor: None,
            inventory_generation: 0,
            backoff: CappedBackoff::new(INITIAL_RESOLVER_RETRY, MAXIMUM_RESOLVER_RETRY),
            epoch_updates: None,
        }
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
        let (harness, session) = Harness::session(vec![
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
        harness.event(ResolverEvent::ControllerChanged("hci1".to_owned()));
        probe.wait_for_calls(2).await;

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
    async fn healthy_event_stream_never_polls_empty_or_indeterminate_state() {
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

        tokio::time::advance(Duration::from_secs(300)).await;
        tokio::task::yield_now().await;
        assert_eq!(probe.calls().len(), 1);
        assert_eq!(indeterminate_harness.observation_count(), 1);
        indeterminate_harness.event(ResolverEvent::ControllerChanged("hci0".to_owned()));
        probe.wait_for_calls(2).await;
        stop(indeterminate).await;
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
}
