use crate::{
    AsterRosterBeaconV1, AttemptKind, DiscoveryAdmission, DiscoveryCandidate, DiscoveryRecordError,
    DriverError, DriverErrorKind, FixedRole, ObservationOutcome, SupervisorError,
    ValidatedRosteredSupervisorConfig,
    discovery::{SCAN_ACTIVE_INTERVAL, SCAN_IDLE_INTERVAL},
    lifecycle::ContactAdmission,
    platform::{
        discovery::{
            BluezDiscoveryPlatform, BluezOwnerLoss, DiscoveryObservation, DiscoveryPlatform,
            PlatformFuture, RosterAdvertisement, ScanTermination, TerminationFuture,
        },
        socket::{
            BluezRosteredSocketFactory, OpenedContact, RosteredSocketFactory,
            opened_rostered_contact,
        },
    },
    policy::{CappedBackoff, LifecycleCancellation},
};
use aster_contact::OrderedContact;
use aster_node::{
    MissionPeerExpectation, OrderedEventContactError, OrderedEventContactHandle,
    OrderedEventContactRole, PeerReceipt,
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{Duration, timeout},
};

const ADVERTISEMENT_ROTATION_INTERVAL: Duration = Duration::from_secs(25);
const OWNED_STOP_DEADLINE: Duration = Duration::from_secs(5);
const CONTACT_DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const INITIAL_EPOCH_RETRY: Duration = Duration::from_millis(250);
const MAXIMUM_EPOCH_RETRY: Duration = Duration::from_secs(30);
const STABLE_EPOCH_DURATION: Duration = Duration::from_secs(30);
const OWNER_LOSS_AFTER: Duration = Duration::from_secs(35);
const OWNER_LOSS_JOIN_DEADLINE: Duration = Duration::from_secs(5);

struct ActiveScan {
    owner: Box<dyn crate::platform::discovery::OwnedScan>,
    observations: tokio::sync::mpsc::Receiver<DiscoveryObservation>,
}

enum ScanPhase {
    Active {
        scan: ActiveScan,
        deadline: tokio::time::Instant,
    },
    Idle {
        deadline: tokio::time::Instant,
    },
}

enum EpochEvent {
    Cancelled,
    AdvertisementTerminated,
    AdvertisementRotation,
    ScanTerminated(ScanTermination),
    Observation(Option<DiscoveryObservation>),
    ScanDeadline,
    ScanIdleDeadline,
    InboundAccepted(Result<(crate::SocketOpen, crate::CanonicalLocator), DriverError>),
    InboundAcceptReady,
    OutboundRetry,
    ContactFinished(ContactAttemptOutcome),
    CredentialExpired,
}

type ContactWorkFuture = Pin<Box<dyn Future<Output = ContactAttemptOutcome> + Send>>;
type SharedContactAdmission = Arc<dyn ContactAdmission>;
type InboundAcceptFuture = Pin<
    Box<
        dyn Future<Output = Result<(crate::SocketOpen, crate::CanonicalLocator), DriverError>>
            + Send,
    >,
>;

#[derive(Default)]
struct EpochSignals {
    availability: Option<watch::Sender<crate::BtleAvailability>>,
    available_started: Option<oneshot::Sender<Instant>>,
}

impl EpochSignals {
    const fn monitored(
        availability: watch::Sender<crate::BtleAvailability>,
        available_started: oneshot::Sender<Instant>,
    ) -> Self {
        Self {
            availability: Some(availability),
            available_started: Some(available_started),
        }
    }
}

enum ContactAttemptOutcome {
    Opened(Box<OpenedContact>),
    Completed(Box<Result<PeerReceipt, OrderedEventContactError>>),
    OpenFailed(Box<ContactOpenFailure>),
    Cancelled,
}

struct ContactOpenFailure {
    candidate: DiscoveryCandidate,
    error: DriverError,
}

enum ContactPhase {
    Accepting(InboundAcceptFuture),
    Paused(tokio::time::Instant),
    Active {
        cancellation: LifecycleCancellation,
        work: ContactWorkFuture,
    },
}

#[derive(Clone, Copy)]
enum OutboundDelay {
    Ready,
    PeerRetryUntil(Instant),
    TokenRefillUntil(Instant),
    CadenceUntil(Instant),
}

impl OutboundDelay {
    fn deadline(self, now: Instant) -> Instant {
        match self {
            Self::Ready => now,
            Self::PeerRetryUntil(deadline)
            | Self::TokenRefillUntil(deadline)
            | Self::CadenceUntil(deadline) => deadline,
        }
    }

    fn wake_for_new_candidate(&mut self) {
        if matches!(self, Self::PeerRetryUntil(_)) {
            *self = Self::Ready;
        }
    }
}

impl ContactPhase {
    fn accepting<S>(sockets: Arc<S>, listener: Arc<S::Listener>) -> Self
    where
        S: RosteredSocketFactory + 'static,
    {
        Self::Accepting(Box::pin(
            async move { sockets.accept(listener.as_ref()).await },
        ))
    }

    fn opening<S>(
        config: Arc<ValidatedRosteredSupervisorConfig>,
        sockets: Arc<S>,
        candidate: DiscoveryCandidate,
    ) -> Self
    where
        S: RosteredSocketFactory + 'static,
    {
        let cancellation = LifecycleCancellation::new();
        let work_cancellation = cancellation.clone();
        Self::Active {
            cancellation,
            work: Box::pin(async move {
                match open_candidate(
                    config.as_ref(),
                    sockets.as_ref(),
                    candidate,
                    &work_cancellation,
                )
                .await
                {
                    Ok(opened) => ContactAttemptOutcome::Opened(Box::new(opened)),
                    Err(error) => ContactAttemptOutcome::OpenFailed(Box::new(ContactOpenFailure {
                        candidate,
                        error,
                    })),
                }
            }),
        }
    }

    fn paused_until(deadline: Instant) -> Self {
        Self::Paused(tokio::time::Instant::from_std(deadline))
    }

    fn admitted(
        config: Arc<ValidatedRosteredSupervisorConfig>,
        contacts: SharedContactAdmission,
        role: OrderedEventContactRole,
        opened: OpenedContact,
    ) -> Self {
        let cancellation = LifecycleCancellation::new();
        let work_cancellation = cancellation.clone();
        Self::Active {
            cancellation,
            work: Box::pin(async move {
                run_opened_contact(
                    config.as_ref(),
                    contacts.as_ref(),
                    role,
                    opened,
                    &work_cancellation,
                )
                .await
            }),
        }
    }

    async fn next(&mut self) -> EpochEvent {
        match self {
            Self::Accepting(accept) => EpochEvent::InboundAccepted(accept.await),
            Self::Paused(deadline) => {
                tokio::time::sleep_until(*deadline).await;
                EpochEvent::InboundAcceptReady
            }
            Self::Active { work, .. } => EpochEvent::ContactFinished(work.await),
        }
    }

    const fn is_free(&self) -> bool {
        matches!(self, Self::Accepting(_) | Self::Paused(_))
    }

    fn cancel(&self) {
        if let Self::Active { cancellation, .. } = self {
            cancellation.cancel();
        }
    }

    async fn join(self) {
        if let Self::Active { mut work, .. } = self {
            let _ = (&mut work).await;
        }
    }
}

trait DiscoveryNonceSource: Send + Sync {
    fn next_nonce(&self) -> Result<[u8; 16], DriverError>;
}

trait NonceRandom: Send + Sync {
    fn generate(&self) -> Result<[u8; 16], ()>;
}

#[derive(Clone, Copy, Debug, Default)]
struct OsNonceRandom;

impl NonceRandom for OsNonceRandom {
    fn generate(&self) -> Result<[u8; 16], ()> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| ())?;
        Ok(nonce)
    }
}

struct UniqueNonceSource<R> {
    random: R,
    previous: Mutex<Option<[u8; 16]>>,
}

impl<R> UniqueNonceSource<R> {
    const fn new(random: R) -> Self {
        Self {
            random,
            previous: Mutex::new(None),
        }
    }
}

fn production_nonce_source() -> UniqueNonceSource<OsNonceRandom> {
    UniqueNonceSource::new(OsNonceRandom)
}

impl<R> DiscoveryNonceSource for UniqueNonceSource<R>
where
    R: NonceRandom,
{
    fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
        let mut previous = self.previous.lock().map_err(|_| nonce_unavailable())?;
        for _ in 0..=3 {
            let nonce = self.random.generate().map_err(|_| nonce_unavailable())?;
            if previous.as_ref() != Some(&nonce) {
                *previous = Some(nonce);
                return Ok(nonce);
            }
        }
        Err(nonce_unavailable())
    }
}

fn nonce_unavailable() -> DriverError {
    DriverError::new(
        DriverErrorKind::Unavailable,
        "rostered discovery nonce generation is unavailable",
    )
}

/// Owned unattended Linux rostered-BTLE Event lifecycle.
pub struct LinuxRosteredBtleEventSupervisor {
    availability: watch::Receiver<crate::BtleAvailability>,
    completion: watch::Receiver<bool>,
    cancellation: LifecycleCancellation,
    platform_owner: Arc<PlatformOwner>,
    task: JoinHandle<Result<(), SupervisorError>>,
}

trait PlatformOwnerLoss: Send + Sync {
    fn force(&self);
}

impl PlatformOwnerLoss for BluezOwnerLoss {
    fn force(&self) {
        BluezOwnerLoss::force(self);
    }
}

#[derive(Default)]
struct PlatformOwner(Mutex<Option<Arc<dyn PlatformOwnerLoss>>>);

impl PlatformOwner {
    fn replace(&self, owner: impl PlatformOwnerLoss + 'static) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(owner));
    }

    fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn force_loss(&self) -> bool {
        let owner = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(owner) = owner {
            owner.force();
            true
        } else {
            false
        }
    }
}

impl LinuxRosteredBtleEventSupervisor {
    /// Returns coarse adapter availability without exposing discovery material.
    pub fn availability(&self) -> watch::Receiver<crate::BtleAvailability> {
        self.availability.clone()
    }

    /// Requests idempotent cancellation of all owned rostered lifecycle work.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Waits until the owned rostered lifecycle reaches a terminal result.
    pub async fn wait_for_completion(&self) {
        let mut completion = self.completion.clone();
        while !*completion.borrow_and_update() {
            if completion.changed().await.is_err() {
                return;
            }
        }
    }

    /// Consumes the supervisor and bounds cleanup to the advertised hard timeout.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.cancel();
        let mut task = self.task;
        match timeout(OWNER_LOSS_AFTER, &mut task).await {
            Ok(result) => {
                let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                eprintln!("BTLE_EVENT status=stopped");
                result
            }
            Err(_) => {
                self.platform_owner.force_loss();
                match timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await {
                    Ok(result) => {
                        let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                        eprintln!("BTLE_EVENT status=stopped owner_loss=forced");
                        result
                    }
                    Err(_) => {
                        task.abort();
                        let _ = task.await;
                        eprintln!("BTLE_EVENT status=cleanup-unconfirmed");
                        Err(SupervisorError::PlatformCleanupUnconfirmed)
                    }
                }
            }
        }
    }
}

struct CompletionOnDrop(watch::Sender<bool>);

impl Drop for CompletionOnDrop {
    fn drop(&mut self) {
        self.0.send_if_modified(|completed| {
            if *completed {
                false
            } else {
                *completed = true;
                true
            }
        });
    }
}

/// Starts one unattended rostered Linux BTLE Event supervisor.
pub fn spawn_linux_rostered_btle_event_supervisor(
    config: ValidatedRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
) -> LinuxRosteredBtleEventSupervisor {
    let cancellation = LifecycleCancellation::new();
    let initial = crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    eprintln!("BTLE_EVENT status=unavailable reason=BluezUnavailable");
    let (availability_updates, availability) = watch::channel(initial);
    let (completion_updates, completion) = watch::channel(false);
    let platform_owner = Arc::new(PlatformOwner::default());
    let task_cancellation = cancellation.clone();
    let task_platform_owner = platform_owner.clone();
    let task = tokio::spawn(async move {
        let _completion = CompletionOnDrop(completion_updates);
        run_rostered_supervisor(
            Arc::new(config),
            Arc::new(contacts),
            availability_updates,
            task_cancellation,
            task_platform_owner,
        )
        .await
    });
    LinuxRosteredBtleEventSupervisor {
        availability,
        completion,
        cancellation,
        platform_owner,
        task,
    }
}

async fn run_rostered_supervisor(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    contacts: Arc<OrderedEventContactHandle>,
    availability: watch::Sender<crate::BtleAvailability>,
    cancellation: LifecycleCancellation,
    platform_owner: Arc<PlatformOwner>,
) -> Result<(), SupervisorError> {
    let sockets = Arc::new(BluezRosteredSocketFactory);
    let nonces = Arc::new(production_nonce_source());
    let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        if lifecycle_now() >= config.discovery_credentials().expires_at() {
            return park_expired_adapter(config, &availability, &cancellation).await;
        }
        let credential_deadline =
            tokio::time::Instant::from_std(config.discovery_credentials().expires_at());
        let discovery = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(credential_deadline) => {
                return park_expired_adapter(config, &availability, &cancellation).await;
            }
            result = BluezDiscoveryPlatform::open() => match result {
                Ok(discovery) => discovery,
                Err(error) => {
                    if error.kind() == DriverErrorKind::Configuration {
                        return Err(SupervisorError::Configuration);
                    }
                    publish_availability(&availability, crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ));
                    if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                        return Ok(());
                    }
                    continue;
                }
            }
        };
        platform_owner.replace(discovery.owner_loss());
        let (available_started, available_started_at) = oneshot::channel();
        let result = run_available_epoch(
            config.clone(),
            sockets.clone(),
            Arc::new(discovery),
            nonces.clone(),
            contacts.clone(),
            EpochSignals::monitored(availability.clone(), available_started),
            cancellation.clone(),
        )
        .await;
        platform_owner.clear();
        if available_started_at
            .await
            .is_ok_and(|started| stable_epoch_elapsed(started, lifecycle_now()))
        {
            backoff.reset();
        }
        match result {
            Ok(()) => return Ok(()),
            Err(SupervisorError::Configuration) => return Err(SupervisorError::Configuration),
            Err(
                error @ (SupervisorError::AdmissionClosed
                | SupervisorError::ActorUnavailable
                | SupervisorError::ActorStopped
                | SupervisorError::TaskStopped
                | SupervisorError::PlatformCleanupUnconfirmed),
            ) => return Err(error),
            Err(SupervisorError::Controller(_)) => {
                publish_availability(
                    &availability,
                    crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ),
                );
                if lifecycle_now() >= config.discovery_credentials().expires_at() {
                    return park_expired_adapter(config, &availability, &cancellation).await;
                }
                if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn park_expired_adapter(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    availability: &watch::Sender<crate::BtleAvailability>,
    cancellation: &LifecycleCancellation,
) -> Result<(), SupervisorError> {
    drop(config);
    publish_availability(
        availability,
        crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
    );
    cancellation.cancelled().await;
    Ok(())
}

fn stable_epoch_elapsed(started: Instant, ended: Instant) -> bool {
    ended.saturating_duration_since(started) >= STABLE_EPOCH_DURATION
}

fn supervisor_error(error: DriverError) -> SupervisorError {
    if error.kind() == DriverErrorKind::Configuration {
        SupervisorError::Configuration
    } else {
        SupervisorError::Controller(error.kind())
    }
}

fn operation_interrupted(error: SupervisorError) -> bool {
    matches!(
        error,
        SupervisorError::Controller(DriverErrorKind::Cancelled | DriverErrorKind::Unavailable)
    )
}

async fn wait_epoch_retry(delay: Duration, cancellation: &LifecycleCancellation) -> bool {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

async fn await_epoch_platform<T, F>(
    expires_at: Instant,
    cancellation: &LifecycleCancellation,
    operation: F,
) -> Result<T, SupervisorError>
where
    F: Future<Output = Result<T, DriverError>>,
{
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
        }
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)) => {
            Err(SupervisorError::Controller(DriverErrorKind::Unavailable))
        }
        result = &mut operation => result.map_err(supervisor_error),
    }
}

fn publish_availability(
    updates: &watch::Sender<crate::BtleAvailability>,
    availability: crate::BtleAvailability,
) {
    if updates.send_if_modified(|current| {
        if *current == availability {
            false
        } else {
            *current = availability;
            true
        }
    }) {
        match availability {
            crate::BtleAvailability::Available => eprintln!("BTLE_EVENT status=available"),
            crate::BtleAvailability::Unavailable(reason) => {
                eprintln!("BTLE_EVENT status=unavailable reason={reason:?}");
            }
        }
    }
}

async fn run_available_epoch<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    contacts: SharedContactAdmission,
    mut signals: EpochSignals,
    cancellation: LifecycleCancellation,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let expires_at = config.discovery_credentials().expires_at();
    let bound_listener = await_epoch_platform(
        expires_at,
        &cancellation,
        sockets.bind_dynamic_listener(config.controller()),
    )
    .await?;
    let listener_psm = bound_listener.allocated_psm();
    let listener = Arc::new(bound_listener.into_listener());
    let record =
        encode_advertisement(&config, listener_psm, nonces.as_ref()).map_err(supervisor_error)?;
    let mut advertisement = Some(
        match await_epoch_platform(
            expires_at,
            &cancellation,
            discovery.start_advertisement(config.controller(), record),
        )
        .await
        {
            Ok(owner) => owner,
            Err(error) => {
                if operation_interrupted(error) {
                    discovery.force_owner_loss();
                }
                return Err(error);
            }
        },
    );
    if lifecycle_now() >= expires_at {
        discovery.force_owner_loss();
        let cleanup = stop_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        )
        .await;
        drop(listener);
        cleanup.map_err(supervisor_error)?;
        return Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
    }
    let started_scan = match await_epoch_platform(
        expires_at,
        &cancellation,
        discovery.start_scan(config.controller()),
    )
    .await
    {
        Ok(started) => started,
        Err(error) => {
            discovery.force_owner_loss();
            let cleanup = stop_advertisement(
                advertisement
                    .as_mut()
                    .expect("advertisement was just registered")
                    .as_mut(),
            )
            .await;
            drop(listener);
            cleanup.map_err(supervisor_error)?;
            return Err(error);
        }
    };
    if lifecycle_now() >= expires_at {
        discovery.force_owner_loss();
        let (mut scan, _) = started_scan.into_parts();
        let scan_cleanup = stop_scan(scan.as_mut());
        let advertisement_cleanup = stop_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        );
        let (scan_result, advertisement_result) = tokio::join!(scan_cleanup, advertisement_cleanup);
        drop(listener);
        scan_result.map_err(supervisor_error)?;
        advertisement_result.map_err(supervisor_error)?;
        return Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
    }
    let (scan, observations) = started_scan.into_parts();
    let mut admission = DiscoveryAdmission::new();
    let started_at = lifecycle_now();
    debug_assert_eq!(
        admission.start_scan(started_at),
        crate::ScanStartOutcome::Started
    );
    let mut scan_phase = ScanPhase::Active {
        scan: ActiveScan {
            owner: scan,
            observations,
        },
        deadline: tokio::time::Instant::now() + SCAN_ACTIVE_INTERVAL,
    };
    let mut advertisement_deadline = tokio::time::Instant::now() + ADVERTISEMENT_ROTATION_INTERVAL;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let mut contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
    let mut outbound_delay = OutboundDelay::Ready;
    let mut outbound_candidate_pending = false;
    let mut contact_backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    if let Some(ref availability) = signals.availability {
        publish_availability(availability, crate::BtleAvailability::Available);
    }
    if let Some(available_started) = signals.available_started.take() {
        let _ = available_started.send(lifecycle_now());
    }

    let result = loop {
        let contact_is_free = contact_phase.is_free();
        let outbound_retry_enabled =
            contact_is_free && outbound_candidate_pending && config.role() == FixedRole::Initiator;
        let outbound_retry_deadline =
            tokio::time::Instant::from_std(outbound_delay.deadline(lifecycle_now()));
        let event = match &mut scan_phase {
            ScanPhase::Active { scan, deadline } => {
                let advertisement_terminated = advertisement
                    .as_ref()
                    .expect("advertisement is live")
                    .terminated();
                let scan_terminated = scan.owner.termination();
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => EpochEvent::Cancelled,
                    () = tokio::time::sleep_until(credential_deadline) => EpochEvent::CredentialExpired,
                    () = tokio::time::sleep_until(*deadline) => EpochEvent::ScanDeadline,
                    () = tokio::time::sleep_until(advertisement_deadline) => {
                        EpochEvent::AdvertisementRotation
                    },
                    () = advertisement_terminated => EpochEvent::AdvertisementTerminated,
                    reason = scan_terminated => EpochEvent::ScanTerminated(reason),
                    () = tokio::time::sleep_until(outbound_retry_deadline), if outbound_retry_enabled => {
                        EpochEvent::OutboundRetry
                    },
                    observation = scan.observations.recv() => EpochEvent::Observation(observation),
                    event = contact_phase.next() => event,
                }
            }
            ScanPhase::Idle { deadline } => {
                let advertisement_terminated = advertisement
                    .as_ref()
                    .expect("advertisement is live")
                    .terminated();
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => EpochEvent::Cancelled,
                    () = tokio::time::sleep_until(credential_deadline) => EpochEvent::CredentialExpired,
                    () = tokio::time::sleep_until(*deadline), if contact_is_free => {
                        EpochEvent::ScanIdleDeadline
                    },
                    () = tokio::time::sleep_until(advertisement_deadline) => {
                        EpochEvent::AdvertisementRotation
                    },
                    () = advertisement_terminated => EpochEvent::AdvertisementTerminated,
                    () = tokio::time::sleep_until(outbound_retry_deadline), if outbound_retry_enabled => {
                        EpochEvent::OutboundRetry
                    },
                    event = contact_phase.next() => event,
                }
            }
        };
        match event {
            EpochEvent::Cancelled => break Ok(()),
            EpochEvent::AdvertisementTerminated => {
                break Err(SupervisorError::Controller(DriverErrorKind::Transport));
            }
            EpochEvent::CredentialExpired => {
                break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
            }
            EpochEvent::ScanTerminated(ScanTermination::CapacityExceeded) => {
                finish_ended_scan(&mut scan_phase, &mut admission);
            }
            EpochEvent::ScanTerminated(
                ScanTermination::Requested | ScanTermination::Unexpected,
            )
            | EpochEvent::Observation(None) => {
                break Err(SupervisorError::Controller(DriverErrorKind::Transport));
            }
            EpochEvent::AdvertisementRotation => {
                let record = match encode_advertisement(&config, listener_psm, nonces.as_ref()) {
                    Ok(record) => record,
                    Err(error) => break Err(supervisor_error(error)),
                };
                let mut previous = advertisement.take().expect("advertisement is live");
                if let Err(error) = stop_advertisement(previous.as_mut()).await {
                    break Err(supervisor_error(error));
                }
                if lifecycle_now() >= config.discovery_credentials().expires_at() {
                    break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                }
                advertisement = match await_epoch_platform(
                    expires_at,
                    &cancellation,
                    discovery.start_advertisement(config.controller(), record),
                )
                .await
                {
                    Ok(owner) => Some(owner),
                    Err(error) => break Err(error),
                };
                if lifecycle_now() >= expires_at {
                    let mut owner = advertisement
                        .take()
                        .expect("advertisement was just registered");
                    if let Err(error) = stop_advertisement(owner.as_mut()).await {
                        break Err(supervisor_error(error));
                    }
                    break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                }
                advertisement_deadline =
                    tokio::time::Instant::now() + ADVERTISEMENT_ROTATION_INTERVAL;
            }
            EpochEvent::Observation(Some(observation)) => {
                let now = lifecycle_now();
                let outcome = admit_platform_observation(&mut admission, &config, observation, now);
                if matches!(outcome, ObservationOutcome::StopWindow(_)) {
                    if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                        break Err(supervisor_error(error));
                    }
                } else if outcome == ObservationOutcome::Accepted
                    && config.role() == FixedRole::Initiator
                {
                    outbound_candidate_pending = true;
                    outbound_delay.wake_for_new_candidate();
                    match begin_outbound_contact(
                        &config,
                        &sockets,
                        &mut admission,
                        &mut scan_phase,
                        &mut outbound_candidate_pending,
                        &mut outbound_delay,
                    )
                    .await
                    {
                        Ok(Some(phase)) => contact_phase = phase,
                        Ok(None) => {}
                        Err(error) => break Err(supervisor_error(error)),
                    }
                }
            }
            EpochEvent::InboundAccepted(accepted) => {
                let (opened_socket, locator) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == DriverErrorKind::PeerRejected => {
                        contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
                        continue;
                    }
                    Err(error) => break Err(supervisor_error(error)),
                };
                let now = lifecycle_now();
                match admit_inbound_contact(&config, &mut admission, locator, now) {
                    InboundContactAdmission::Admitted => {}
                    InboundContactAdmission::Rejected => {
                        drop(opened_socket);
                        contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
                        continue;
                    }
                    InboundContactAdmission::BackoffUntil(deadline) => {
                        drop(opened_socket);
                        contact_phase = ContactPhase::paused_until(deadline);
                        continue;
                    }
                }
                let opened = match opened_rostered_contact(&config, locator, opened_socket) {
                    Ok(opened) => opened,
                    Err(error) => break Err(supervisor_error(error)),
                };
                if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                    break Err(supervisor_error(error));
                }
                admission.enter_authenticated_contact(now);
                contact_phase = ContactPhase::admitted(
                    config.clone(),
                    contacts.clone(),
                    OrderedEventContactRole::Responder,
                    opened,
                );
            }
            EpochEvent::InboundAcceptReady => {
                contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
            }
            EpochEvent::OutboundRetry => {
                match begin_outbound_contact(
                    &config,
                    &sockets,
                    &mut admission,
                    &mut scan_phase,
                    &mut outbound_candidate_pending,
                    &mut outbound_delay,
                )
                .await
                {
                    Ok(Some(phase)) => contact_phase = phase,
                    Ok(None) => {}
                    Err(error) => break Err(supervisor_error(error)),
                }
            }
            EpochEvent::ContactFinished(outcome) => {
                let now = lifecycle_now();
                let outcome = match outcome {
                    ContactAttemptOutcome::Opened(opened) => {
                        if now >= config.discovery_credentials().expires_at() {
                            drop(opened);
                            break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                        }
                        if !admission.try_consume_attempt(AttemptKind::MissionHandshake, now) {
                            drop(opened);
                            admission.contact_closed(now);
                            scan_phase = idle_scan_phase();
                            outbound_candidate_pending = true;
                            outbound_delay = OutboundDelay::TokenRefillUntil(
                                admission.attempt_retry_at(AttemptKind::MissionHandshake, now),
                            );
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        contact_phase = ContactPhase::admitted(
                            config.clone(),
                            contacts.clone(),
                            OrderedEventContactRole::Initiator,
                            *opened,
                        );
                        continue;
                    }
                    outcome => outcome,
                };
                admission.contact_closed(now);
                scan_phase = idle_scan_phase();
                if let Err(error) = finish_contact_attempt(
                    &config,
                    &mut admission,
                    outcome,
                    now,
                    &mut outbound_delay,
                    &mut outbound_candidate_pending,
                    &mut contact_backoff,
                ) {
                    break Err(error);
                }
                contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
            }
            EpochEvent::ScanDeadline => {
                if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                    break Err(supervisor_error(error));
                }
            }
            EpochEvent::ScanIdleDeadline => {
                let started_scan = match await_epoch_platform(
                    expires_at,
                    &cancellation,
                    discovery.start_scan(config.controller()),
                )
                .await
                {
                    Ok(started) => started,
                    Err(error) => break Err(error),
                };
                if lifecycle_now() >= expires_at {
                    let (mut owner, _) = started_scan.into_parts();
                    if let Err(error) = stop_scan(owner.as_mut()).await {
                        break Err(supervisor_error(error));
                    }
                    break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                }
                let (owner, observations) = started_scan.into_parts();
                let now = lifecycle_now();
                debug_assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);
                scan_phase = ScanPhase::Active {
                    scan: ActiveScan {
                        owner,
                        observations,
                    },
                    deadline: tokio::time::Instant::now() + SCAN_ACTIVE_INTERVAL,
                };
            }
        }
    };

    if result.is_err()
        && let Some(ref availability) = signals.availability
    {
        publish_availability(
            availability,
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
    }
    if result.is_err() {
        discovery.force_owner_loss();
    }
    contact_phase.cancel();
    let contact_join = contact_phase.join();
    let scan_cleanup = async move {
        match scan_phase {
            ScanPhase::Active { mut scan, .. } => stop_scan(scan.owner.as_mut()).await,
            ScanPhase::Idle { .. } => Ok(()),
        }
    };
    let advertisement_cleanup = async move {
        match advertisement {
            Some(mut advertisement) => stop_advertisement(advertisement.as_mut()).await,
            None => Ok(()),
        }
    };
    let (_, scan_stop, advertisement_stop) =
        tokio::join!(contact_join, scan_cleanup, advertisement_cleanup);
    drop(listener);
    if result.is_ok() && (scan_stop.is_err() || advertisement_stop.is_err()) {
        discovery.force_owner_loss();
    }
    result?;
    scan_stop.map_err(supervisor_error)?;
    advertisement_stop.map_err(supervisor_error)
}

fn finish_contact_attempt(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    outcome: ContactAttemptOutcome,
    now: Instant,
    outbound_delay: &mut OutboundDelay,
    outbound_candidate_pending: &mut bool,
    contact_backoff: &mut CappedBackoff,
) -> Result<(), SupervisorError> {
    match outcome {
        ContactAttemptOutcome::Opened(_) => unreachable!("opened contact is handled in the epoch"),
        ContactAttemptOutcome::OpenFailed(failure) => {
            let ContactOpenFailure { candidate, error } = *failure;
            if error.kind() == DriverErrorKind::Configuration {
                return Err(SupervisorError::Configuration);
            }
            if error.kind() != DriverErrorKind::Cancelled {
                admission.invalidate_after_open_failure(candidate, now);
                if config.role() == FixedRole::Initiator {
                    *outbound_candidate_pending = admission.selected_candidate(now).is_some();
                    if *outbound_candidate_pending {
                        *outbound_delay =
                            OutboundDelay::PeerRetryUntil(now + contact_backoff.next_delay());
                    }
                }
            }
        }
        ContactAttemptOutcome::Cancelled => {}
        ContactAttemptOutcome::Completed(result) => match *result {
            Ok(receipt) => {
                eprintln!(
                    "BTLE_EVENT status=contact-complete offered={} fetched={} inserted={}",
                    receipt.offered, receipt.fetched, receipt.inserted
                );
                if config.role() == FixedRole::Initiator {
                    contact_backoff.reset();
                    *outbound_candidate_pending = admission.selected_candidate(now).is_some();
                    *outbound_delay = OutboundDelay::CadenceUntil(now + config.contact_cadence());
                }
            }
            Err(OrderedEventContactError::AdmissionBusy | OrderedEventContactError::Contact(_)) => {
                if config.role() == FixedRole::Initiator {
                    *outbound_candidate_pending = admission.selected_candidate(now).is_some();
                    if *outbound_candidate_pending {
                        *outbound_delay =
                            OutboundDelay::PeerRetryUntil(now + contact_backoff.next_delay());
                    }
                }
            }
            Err(OrderedEventContactError::AdmissionClosed) => {
                return Err(SupervisorError::AdmissionClosed);
            }
            Err(OrderedEventContactError::ActorUnavailable) => {
                return Err(SupervisorError::ActorUnavailable);
            }
            Err(OrderedEventContactError::ActorStopped) => {
                return Err(SupervisorError::ActorStopped);
            }
        },
    }
    Ok(())
}

async fn begin_outbound_contact<S>(
    config: &Arc<ValidatedRosteredSupervisorConfig>,
    sockets: &Arc<S>,
    admission: &mut DiscoveryAdmission,
    scan_phase: &mut ScanPhase,
    candidate_pending: &mut bool,
    outbound_delay: &mut OutboundDelay,
) -> Result<Option<ContactPhase>, DriverError>
where
    S: RosteredSocketFactory + 'static,
{
    let now = lifecycle_now();
    if config.role() != FixedRole::Initiator
        || now >= config.discovery_credentials().expires_at()
        || now < outbound_delay.deadline(now)
    {
        return Ok(None);
    }
    let Some(candidate) = admission.selected_candidate(now) else {
        *candidate_pending = false;
        return Ok(None);
    };
    if !admission.try_consume_attempt(AttemptKind::OutboundOpen, now) {
        *outbound_delay = OutboundDelay::TokenRefillUntil(
            admission.attempt_retry_at(AttemptKind::OutboundOpen, now),
        );
        return Ok(None);
    }
    stop_active_scan(scan_phase, admission).await?;
    admission.enter_authenticated_contact(now);
    *candidate_pending = false;
    *outbound_delay = OutboundDelay::Ready;
    Ok(Some(ContactPhase::opening(
        config.clone(),
        sockets.clone(),
        candidate,
    )))
}

fn idle_scan_phase() -> ScanPhase {
    ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    }
}

async fn stop_active_scan(
    phase: &mut ScanPhase,
    admission: &mut DiscoveryAdmission,
) -> Result<(), DriverError> {
    let now = lifecycle_now();
    let idle = ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    };
    let ScanPhase::Active { mut scan, .. } = std::mem::replace(phase, idle) else {
        return Ok(());
    };
    let result = stop_scan(scan.owner.as_mut()).await;
    admission.stop_scan(now);
    result
}

fn finish_ended_scan(phase: &mut ScanPhase, admission: &mut DiscoveryAdmission) {
    let idle = ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    };
    let previous = std::mem::replace(phase, idle);
    debug_assert!(matches!(previous, ScanPhase::Active { .. }));
    admission.callback_queue_overflow(lifecycle_now());
}

fn lifecycle_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

enum InboundContactAdmission {
    Admitted,
    Rejected,
    BackoffUntil(Instant),
}

fn admit_inbound_contact(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    locator: crate::CanonicalLocator,
    now: Instant,
) -> InboundContactAdmission {
    if admission.candidate(locator, now).is_none()
        || config.role() != FixedRole::Listener
        || now >= config.discovery_credentials().expires_at()
    {
        return InboundContactAdmission::Rejected;
    }
    if !admission.try_consume_attempt(AttemptKind::InboundAccept, now) {
        return InboundContactAdmission::BackoffUntil(
            admission.attempt_retry_at(AttemptKind::InboundAccept, now),
        );
    }
    if !admission.try_consume_attempt(AttemptKind::MissionHandshake, now) {
        return InboundContactAdmission::BackoffUntil(
            admission.attempt_retry_at(AttemptKind::MissionHandshake, now),
        );
    }
    InboundContactAdmission::Admitted
}

async fn open_candidate<S>(
    config: &ValidatedRosteredSupervisorConfig,
    sockets: &S,
    candidate: DiscoveryCandidate,
    cancellation: &LifecycleCancellation,
) -> Result<OpenedContact, DriverError>
where
    S: RosteredSocketFactory,
{
    let connect = sockets.connect(
        config.controller(),
        candidate.locator(),
        candidate.listener_psm(),
    );
    let opened = tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DriverError::new(
            DriverErrorKind::Cancelled,
            "rostered contact open was cancelled",
        )),
        result = timeout(config.open_timeout(), connect) => match result {
            Ok(result) => result,
            Err(_) => Err(DriverError::new(
                DriverErrorKind::Timeout,
                "rostered contact open exceeded its deadline",
            )),
        }
    }?;
    opened_rostered_contact(config, candidate.locator(), opened)
}

async fn run_opened_contact(
    config: &ValidatedRosteredSupervisorConfig,
    contacts: &dyn ContactAdmission,
    role: OrderedEventContactRole,
    opened: OpenedContact,
    cancellation: &LifecycleCancellation,
) -> ContactAttemptOutcome {
    let contact: Arc<dyn OrderedContact> = opened.into_contact();
    let peer = MissionPeerExpectation::new(contact.peer_evidence(), config.peer_mission_id());
    let mut admission = contacts.run(role, contact.clone(), peer);
    let completion = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            contact.close();
            let _ = timeout(CONTACT_DRAIN_DEADLINE, &mut admission).await;
            ContactAttemptOutcome::Cancelled
        }
        result = &mut admission => {
            contact.close();
            ContactAttemptOutcome::Completed(Box::new(result))
        }
    };
    drop(admission);
    drop(contact);
    completion
}

async fn stop_advertisement(
    owner: &mut dyn crate::platform::discovery::OwnedAdvertisement,
) -> Result<(), DriverError> {
    let terminated = owner.terminated();
    let stop = owner.stop();
    stop_with_barrier(
        stop,
        terminated,
        "owned roster advertisement stop timed out",
    )
    .await
}

async fn stop_scan(
    owner: &mut dyn crate::platform::discovery::OwnedScan,
) -> Result<(), DriverError> {
    let termination = owner.termination();
    let terminated: TerminationFuture<'static> = Box::pin(async move {
        let _ = termination.await;
    });
    let stop = owner.stop();
    stop_with_barrier(stop, terminated, "owned roster scan stop timed out").await
}

async fn stop_with_barrier(
    mut stop: PlatformFuture<'_, ()>,
    mut terminated: TerminationFuture<'static>,
    timeout_message: &'static str,
) -> Result<(), DriverError> {
    let stopped = async {
        tokio::select! {
            result = stop.as_mut() => result,
            () = terminated.as_mut() => Ok(()),
        }
    };
    match timeout(OWNED_STOP_DEADLINE, stopped).await {
        Ok(result) => result,
        Err(_) => Err(DriverError::new(
            DriverErrorKind::Transport,
            timeout_message,
        )),
    }
}

fn encode_advertisement(
    config: &ValidatedRosteredSupervisorConfig,
    listener_psm: u16,
    nonces: &dyn DiscoveryNonceSource,
) -> Result<RosterAdvertisement, DriverError> {
    AsterRosterBeaconV1::encode(
        listener_psm,
        nonces.next_nonce()?,
        config.discovery_credentials(),
        lifecycle_now(),
    )
    .map(RosterAdvertisement::new)
    .map_err(|error| {
        if error == DiscoveryRecordError::CredentialExpired {
            DriverError::new(
                DriverErrorKind::Unavailable,
                "rostered discovery credential lease expired",
            )
        } else {
            DriverError::new(
                DriverErrorKind::Configuration,
                "roster advertisement could not be encoded",
            )
        }
    })
}

fn admit_platform_observation(
    admission: &mut DiscoveryAdmission,
    config: &ValidatedRosteredSupervisorConfig,
    observation: DiscoveryObservation,
    now: Instant,
) -> ObservationOutcome {
    admission.observe(
        observation.locator(),
        observation.record(),
        config.discovery_credentials(),
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContactLimits, ControllerConfig, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
        LeasedDiscoveryCredentialSet, RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES,
        RosteredAdapterConfig, RosteredDiscoveryConfig, RosteredSupervisorConfig,
        ValidatedControllerConfig, ValidatedRosteredSupervisorConfig,
        platform::{
            discovery::{
                DiscoveryPlatform, OwnedAdvertisement, OwnedScan, PlatformFuture,
                RosterAdvertisement, ScanTerminationFuture, StartedScan, TerminationFuture,
            },
            socket::{BoundRosteredListener, RosteredBindFuture, RosteredSocketFactory},
        },
        policy::LifecycleCancellation,
        stream::SocketOpen,
    };
    use aster_contact::OrderedContact;
    use aster_node::{
        MissionPeerExpectation, OrderedEventContactError, OrderedEventContactRole, PeerReceipt,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::sync::{Notify, mpsc, oneshot};

    fn config() -> ValidatedRosteredSupervisorConfig {
        config_with_ids([0x11; 32], [0x22; 32])
    }

    fn config_with_ids(
        local_mission_id: [u8; 32],
        peer_mission_id: [u8; 32],
    ) -> ValidatedRosteredSupervisorConfig {
        config_with_ids_and_lease(local_mission_id, peer_mission_id, Duration::from_secs(60))
    }

    fn config_with_ids_and_lease(
        local_mission_id: [u8; 32],
        peer_mission_id: [u8; 32],
        lease: Duration,
    ) -> ValidatedRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + lease,
        )
        .unwrap();
        RosteredAdapterConfig::Enabled(Box::new(RosteredSupervisorConfig {
            controller: ControllerConfig {
                adapter_name: "hci7".to_owned(),
                local_address: Address::new([2, 0, 0, 0, 0, 1]),
                local_address_type: AddressType::LeRandom,
            },
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id,
            peer_mission_id,
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }))
        .validate()
        .unwrap()
        .unwrap()
    }

    struct FakeOwner {
        stop_event: &'static str,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.events.lock().unwrap().push(self.stop_event);
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    impl OwnedAdvertisement for FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            FakeOwner::stop(self)
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            FakeOwner::terminated(self)
        }
    }

    impl OwnedScan for FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            FakeOwner::stop(self)
        }

        fn termination(&self) -> ScanTerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    struct FakeDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        advertisements: Arc<Mutex<Vec<RosterAdvertisement>>>,
        scan_started: Arc<Notify>,
        observation_sender:
            Mutex<Option<mpsc::Sender<crate::platform::discovery::DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for FakeDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            self.advertisements.lock().unwrap().push(_advertisement);
            let owner = FakeOwner {
                stop_event: "advertisement-stop",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan");
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            self.scan_started.notify_one();
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    observations,
                ))
            })
        }
    }

    struct FakeSockets {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct ConnectingSockets {
        connected: Mutex<Vec<(crate::CanonicalLocator, u16)>>,
    }

    struct RecordingAdmission {
        roles: Mutex<Vec<OrderedEventContactRole>>,
        peers: Mutex<Vec<[u8; 32]>>,
    }

    fn recording_admission() -> Arc<RecordingAdmission> {
        Arc::new(RecordingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
        })
    }

    struct DrainingAdmission {
        started: Arc<Notify>,
        drained: Arc<AtomicU8>,
    }

    struct PendingAdmission {
        started: Arc<Notify>,
    }

    struct NotifyingAdmission {
        roles: Mutex<Vec<OrderedEventContactRole>>,
        peers: Mutex<Vec<[u8; 32]>>,
        admitted: Notify,
    }

    type AcceptedContact = Result<(SocketOpen, crate::CanonicalLocator), DriverError>;

    struct InboundSockets {
        accepted: tokio::sync::Mutex<Option<oneshot::Receiver<AcceptedContact>>>,
    }

    impl crate::lifecycle::ContactAdmission for RecordingAdmission {
        fn run(
            &self,
            role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            self.roles.lock().unwrap().push(role);
            self.peers.lock().unwrap().push(peer.mission_id());
            Box::pin(async { Ok(PeerReceipt::default()) })
        }
    }

    impl crate::lifecycle::ContactAdmission for DrainingAdmission {
        fn run(
            &self,
            _role: OrderedEventContactRole,
            contact: Arc<dyn OrderedContact>,
            _peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            let started = self.started.clone();
            let drained = self.drained.clone();
            Box::pin(async move {
                started.notify_one();
                let result = contact.finish_as_initiator().await;
                drained.store(1, Ordering::SeqCst);
                result.map(|()| PeerReceipt::default()).map_err(|_| {
                    OrderedEventContactError::Contact(aster_node::NodeError::Protocol(
                        "test contact closed".to_owned(),
                    ))
                })
            })
        }
    }

    impl crate::lifecycle::ContactAdmission for PendingAdmission {
        fn run(
            &self,
            _role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            _peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            let started = self.started.clone();
            Box::pin(async move {
                started.notify_one();
                pending().await
            })
        }
    }

    impl crate::lifecycle::ContactAdmission for NotifyingAdmission {
        fn run(
            &self,
            role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            self.roles.lock().unwrap().push(role);
            self.peers.lock().unwrap().push(peer.mission_id());
            self.admitted.notify_one();
            Box::pin(async { Ok(PeerReceipt::default()) })
        }
    }

    impl RosteredSocketFactory for InboundSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            Box::pin(pending())
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(async move {
                let accepted = self.accepted.lock().await.take();
                match accepted {
                    Some(accepted) => accepted.await.expect("test accept sender remains live"),
                    None => pending().await,
                }
            })
        }
    }

    impl RosteredSocketFactory for ConnectingSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            locator: crate::CanonicalLocator,
            advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            self.connected
                .lock()
                .unwrap()
                .push((locator, advertised_psm));
            Box::pin(async {
                let (stream, _peer) = tokio::io::duplex(4096);
                SocketOpen::with_observed_mtu(Box::new(stream), 128, 96)
            })
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    struct FailingScanDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct PendingAdvertisementDiscovery {
        owner_loss_forced: Arc<AtomicU8>,
    }

    impl DiscoveryPlatform for PendingAdvertisementDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            Box::pin(pending())
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            unreachable!("expired advertisement registration never starts scanning")
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(1, Ordering::Release);
        }
    }

    impl DiscoveryPlatform for FailingScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            let owner = FakeOwner {
                stop_event: "advertisement-stop",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan-failed");
            Box::pin(async {
                Err(DriverError::new(
                    DriverErrorKind::Unavailable,
                    "test scan unavailable",
                ))
            })
        }
    }

    struct BlockingAdvertisementOwner {
        events: Arc<Mutex<Vec<&'static str>>>,
        stop_released: Option<Arc<Notify>>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for BlockingAdvertisementOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.events
                    .lock()
                    .unwrap()
                    .push("advertisement-stop-started");
                match &self.stop_released {
                    Some(released) => {
                        released.notified().await;
                        Ok(())
                    }
                    None => pending().await,
                }
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move { terminated.notified().await })
        }
    }

    struct BarrierDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        advertisement_stop_released: Option<Arc<Notify>>,
        advertisement_terminated: Arc<Notify>,
        scan_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for BarrierDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            let owner = BlockingAdvertisementOwner {
                events: self.events.clone(),
                stop_released: self.advertisement_stop_released.clone(),
                terminated: self.advertisement_terminated.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan");
            self.scan_started.notify_one();
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    observations,
                ))
            })
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.fetch_add(1, Ordering::AcqRel);
            self.advertisement_terminated.notify_waiters();
            self.advertisement_terminated.notify_one();
        }
    }

    struct FixedNonce([u8; 16]);

    impl DiscoveryNonceSource for FixedNonce {
        fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
            Ok(self.0)
        }
    }

    struct SequenceNonce(AtomicU8);

    impl DiscoveryNonceSource for SequenceNonce {
        fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
            Ok([self.0.fetch_add(1, Ordering::AcqRel); 16])
        }
    }

    struct FakeRandom(Mutex<VecDeque<Result<[u8; 16], ()>>>);

    impl NonceRandom for FakeRandom {
        fn generate(&self) -> Result<[u8; 16], ()> {
            self.0.lock().unwrap().pop_front().unwrap()
        }
    }

    struct RecordingOwnerLoss {
        force_count: Arc<AtomicU8>,
        release: Option<Arc<Notify>>,
    }

    impl PlatformOwnerLoss for RecordingOwnerLoss {
        fn force(&self) {
            self.force_count.fetch_add(1, Ordering::AcqRel);
            if let Some(release) = &self.release {
                release.notify_one();
            }
        }
    }

    fn test_supervisor(
        task: JoinHandle<Result<(), SupervisorError>>,
        platform_owner: Arc<PlatformOwner>,
    ) -> LinuxRosteredBtleEventSupervisor {
        let (_availability_updates, availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
        let (_completion_updates, completion) = watch::channel(false);
        LinuxRosteredBtleEventSupervisor {
            availability,
            completion,
            cancellation: LifecycleCancellation::new(),
            platform_owner,
            task,
        }
    }

    #[test]
    fn nonce_source_rejects_reuse_and_exhausts_three_redraws() {
        let source = UniqueNonceSource::new(FakeRandom(Mutex::new(
            [
                [1; 16], [1; 16], [2; 16], [2; 16], [2; 16], [2; 16], [2; 16],
            ]
            .into_iter()
            .map(Ok)
            .collect(),
        )));

        assert_eq!(source.next_nonce().unwrap(), [1; 16]);
        assert_eq!(source.next_nonce().unwrap(), [2; 16]);
        assert_eq!(
            source.next_nonce().unwrap_err().kind(),
            DriverErrorKind::Unavailable
        );
    }

    #[test]
    fn production_nonce_source_uses_the_operating_system_rng() {
        let source = production_nonce_source();
        assert!(source.next_nonce().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_does_not_force_owner_loss_after_normal_cleanup() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let supervisor = test_supervisor(tokio::spawn(async { Ok(()) }), platform_owner);

        assert_eq!(supervisor.shutdown().await, Ok(()));
        assert_eq!(force_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_forces_owner_loss_after_graceful_deadline() {
        let force_count = Arc::new(AtomicU8::new(0));
        let release = Arc::new(Notify::new());
        let task_release = release.clone();
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: Some(release),
        });
        let supervisor = test_supervisor(
            tokio::spawn(async move {
                task_release.notified().await;
                Ok(())
            }),
            platform_owner,
        );
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(!shutdown.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(shutdown.await.unwrap(), Ok(()));
        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_reports_unconfirmed_cleanup_after_forced_join_deadline() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let supervisor = test_supervisor(
            tokio::spawn(async { pending::<Result<(), SupervisorError>>().await }),
            platform_owner,
        );
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert!(!shutdown.is_finished());

        tokio::time::advance(OWNER_LOSS_JOIN_DEADLINE).await;
        assert_eq!(
            shutdown.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn only_a_stable_epoch_resets_outer_retry_backoff() {
        let started = Instant::now();

        assert!(!stable_epoch_elapsed(
            started,
            started + STABLE_EPOCH_DURATION - Duration::from_millis(1),
        ));
        assert!(stable_epoch_elapsed(
            started,
            started + STABLE_EPOCH_DURATION,
        ));
    }

    #[test]
    fn new_candidates_wake_retry_backoff_but_never_success_cadence() {
        let now = Instant::now();
        let cadence_deadline = now + Duration::from_secs(60);
        let mut cadence = OutboundDelay::CadenceUntil(cadence_deadline);
        cadence.wake_for_new_candidate();
        assert_eq!(cadence.deadline(now), cadence_deadline);

        let mut retry = OutboundDelay::PeerRetryUntil(now + Duration::from_secs(30));
        retry.wake_for_new_candidate();
        assert_eq!(retry.deadline(now), now);

        let refill_deadline = now + Duration::from_secs(10);
        let mut refill = OutboundDelay::TokenRefillUntil(refill_deadline);
        refill.wake_for_new_candidate();
        assert_eq!(refill.deadline(now), refill_deadline);
    }

    #[tokio::test]
    async fn expired_adapter_parks_until_cancelled_without_terminal_failure() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let config = Arc::new(config());
        let config_weak = Arc::downgrade(&config);
        let (updates, availability) = watch::channel(crate::BtleAvailability::Available);
        let task = tokio::spawn(async move {
            park_expired_adapter(config, &updates, &task_cancellation).await
        });

        tokio::task::yield_now().await;
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert!(!task.is_finished());
        assert!(
            config_weak.upgrade().is_none(),
            "parking must release expired discovery credentials"
        );

        cancellation.cancel();
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[test]
    fn terminal_contact_admission_errors_remain_terminal_supervisor_errors() {
        let cases = [
            (
                OrderedEventContactError::AdmissionClosed,
                SupervisorError::AdmissionClosed,
            ),
            (
                OrderedEventContactError::ActorUnavailable,
                SupervisorError::ActorUnavailable,
            ),
            (
                OrderedEventContactError::ActorStopped,
                SupervisorError::ActorStopped,
            ),
        ];

        for (contact_error, expected) in cases {
            let now = Instant::now();
            let mut admission = DiscoveryAdmission::new();
            let mut outbound_delay = OutboundDelay::Ready;
            let mut outbound_candidate_pending = false;
            let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
            let error = finish_contact_attempt(
                &config(),
                &mut admission,
                ContactAttemptOutcome::Completed(Box::new(Err(contact_error))),
                now,
                &mut outbound_delay,
                &mut outbound_candidate_pending,
                &mut backoff,
            )
            .unwrap_err();

            assert_eq!(error, expected);
        }
    }

    #[test]
    fn platform_observation_enters_authenticated_candidate_admission() {
        let config = config();
        let now = Instant::now();
        let record =
            AsterRosterBeaconV1::encode(0x0081, [0x5a; 16], config.discovery_credentials(), now)
                .unwrap();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let observation =
            DiscoveryObservation::new(locator.address(), locator.address_type(), &record).unwrap();
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);

        assert_eq!(
            admit_platform_observation(&mut admission, &config, observation, now),
            ObservationOutcome::Accepted
        );
        assert_eq!(
            admission.selected_candidate(now).unwrap().locator(),
            locator
        );
    }

    impl RosteredSocketFactory for FakeSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            self.events.lock().unwrap().push("bind");
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            unreachable!("startup-order test does not connect")
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    #[tokio::test]
    async fn epoch_marks_available_only_after_listener_advertisement_and_scan_start() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (available_started, mut available_started_at) = oneshot::channel();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(FixedNonce([0x33; 16])),
                recording_admission(),
                EpochSignals {
                    available_started: Some(available_started),
                    ..EpochSignals::default()
                },
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::task::yield_now().await;
        assert!(
            available_started_at.try_recv().is_ok(),
            "a fully started epoch must expose its Available start time"
        );
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-stop"
            ]
        );
    }

    #[tokio::test]
    async fn scan_start_failure_awaits_advertisement_cessation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let result = run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            Arc::new(FailingScanDiscovery {
                events: events.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["bind", "advertise", "scan-failed", "advertisement-stop"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_expiry_bounds_initial_platform_registration() {
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let (available_started, available_started_at) = oneshot::channel();
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config_with_ids_and_lease(
                [0x11; 32],
                [0x22; 32],
                Duration::from_secs(1),
            )),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingAdvertisementDiscovery {
                owner_loss_forced: owner_loss_forced.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals {
                available_started: Some(available_started),
                ..EpochSignals::default()
            },
            LifecycleCancellation::new(),
        ));

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert!(
            available_started_at.await.is_err(),
            "failed startup must not count toward stable Available time"
        );
    }

    #[tokio::test]
    async fn outbound_open_uses_the_newest_authenticated_candidate_and_dynamic_psm() {
        let config = config();
        let now = Instant::now();
        let newer = now + Duration::from_millis(1);
        let older_locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 8]), AddressType::LeRandom)
                .unwrap();
        let newer_locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let older_record =
            AsterRosterBeaconV1::encode(0x0081, [0x41; 16], config.discovery_credentials(), now)
                .unwrap();
        let newer_record =
            AsterRosterBeaconV1::encode(0x0083, [0x42; 16], config.discovery_credentials(), newer)
                .unwrap();
        let mut candidates = DiscoveryAdmission::new();
        assert_eq!(candidates.start_scan(now), crate::ScanStartOutcome::Started);
        assert_eq!(
            candidates.observe(
                older_locator,
                &older_record,
                config.discovery_credentials(),
                now,
            ),
            ObservationOutcome::Accepted
        );
        assert_eq!(
            candidates.observe(
                newer_locator,
                &newer_record,
                config.discovery_credentials(),
                newer,
            ),
            ObservationOutcome::Accepted
        );
        let sockets = ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        };

        let candidate = candidates.selected_candidate(newer).unwrap();
        assert!(candidates.try_consume_attempt(AttemptKind::OutboundOpen, newer));
        let opened = open_candidate(&config, &sockets, candidate, &LifecycleCancellation::new())
            .await
            .unwrap();

        assert_eq!(
            *sockets.connected.lock().unwrap(),
            [(newer_locator, 0x0083)]
        );
        assert_eq!(
            opened.maximum_exchange_bytes(),
            RING1_MAXIMUM_EXCHANGE_BYTES
        );
    }

    #[tokio::test]
    async fn opened_outbound_contact_runs_initiator_with_the_exact_rostered_mission_peer() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            &config,
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let contacts = RecordingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
        };

        let outcome = run_opened_contact(
            &config,
            &contacts,
            OrderedEventContactRole::Initiator,
            opened,
            &LifecycleCancellation::new(),
        )
        .await;

        assert!(matches!(
            outcome,
            ContactAttemptOutcome::Completed(result) if result.is_ok()
        ));
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Initiator]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [config.peer_mission_id()]);
    }

    #[tokio::test]
    async fn cancelling_an_opened_contact_closes_and_drains_admission() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            &config,
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let started = Arc::new(Notify::new());
        let drained = Arc::new(AtomicU8::new(0));
        let contacts = Arc::new(DrainingAdmission {
            started: started.clone(),
            drained: drained.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_contacts = contacts.clone();
        let task = tokio::spawn(async move {
            run_opened_contact(
                &config,
                task_contacts.as_ref(),
                OrderedEventContactRole::Initiator,
                opened,
                &task_cancellation,
            )
            .await
        });

        started.notified().await;
        cancellation.cancel();

        assert!(matches!(
            task.await.unwrap(),
            ContactAttemptOutcome::Cancelled
        ));
        assert_eq!(drained.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_stuck_admission_releases_secret_bearing_config() {
        let config = Arc::new(config());
        let config_weak = Arc::downgrade(&config);
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            config.as_ref(),
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let started = Arc::new(Notify::new());
        let contacts = Arc::new(PendingAdmission {
            started: started.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            run_opened_contact(
                config.as_ref(),
                contacts.as_ref(),
                OrderedEventContactRole::Initiator,
                opened,
                &task_cancellation,
            )
            .await
        });

        started.notified().await;
        cancellation.cancel();
        let outcome = timeout(Duration::from_secs(6), task)
            .await
            .expect("contact cancellation must bound admission drain")
            .unwrap();

        assert!(matches!(outcome, ContactAttemptOutcome::Cancelled));
        assert!(config_weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn newest_authenticated_candidate_is_opened_and_admitted_as_initiator() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x55; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_sockets = sockets.clone();
        let task_discovery = discovery.clone();
        let task_contacts = contacts.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config),
                task_sockets,
                task_discovery,
                Arc::new(FixedNonce([0x33; 16])),
                task_contacts,
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        let sender = discovery
            .observation_sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        sender
            .send(
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
            )
            .await
            .unwrap();

        contacts.admitted.notified().await;
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(*sockets.connected.lock().unwrap(), [(locator, 0x0083)]);
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Initiator]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [[0x22; 32]]);
    }

    #[tokio::test]
    async fn recent_authenticated_inbound_is_admitted_as_responder_for_the_exact_mission_peer() {
        let config = config_with_ids([0x22; 32], [0x11; 32]);
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x55; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
        let (accept_sender, accept_receiver) = oneshot::channel();
        let sockets = Arc::new(InboundSockets {
            accepted: tokio::sync::Mutex::new(Some(accept_receiver)),
        });
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_discovery = discovery.clone();
        let task_contacts = contacts.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config),
                sockets,
                task_discovery,
                Arc::new(FixedNonce([0x33; 16])),
                task_contacts,
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        let observation_sender = discovery
            .observation_sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        observation_sender
            .send(
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
            )
            .await
            .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        assert!(
            accept_sender
                .send(
                    SocketOpen::with_observed_mtu(Box::new(stream), 128, 96)
                        .map(|opened| (opened, locator)),
                )
                .is_ok()
        );

        contacts.admitted.notified().await;
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Responder]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [[0x11; 32]]);
    }

    #[tokio::test(start_paused = true)]
    async fn scan_owner_runs_ten_seconds_then_waits_twenty_before_restarting() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let socket_events = events.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: socket_events,
                }),
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan-stop")
                .count(),
            1
        );

        tokio::time::advance(Duration::from_secs(19)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan")
                .count(),
            1
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan")
                .count(),
            2
        );

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn credential_lease_expiry_ends_the_epoch_and_drains_owned_platform_work() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config_with_ids_and_lease(
                    [0x11; 32],
                    [0x22; 32],
                    Duration::from_secs(1),
                )),
                sockets,
                discovery,
                Arc::new(FixedNonce([0x33; 16])),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = task.await.unwrap().unwrap_err();

        assert_eq!(
            error,
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-stop"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_expiry_forces_owner_loss_when_platform_stop_is_stalled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_stop_released: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config_with_ids_and_lease(
                [0x11; 32],
                [0x22; 32],
                Duration::from_secs(1),
            )),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            discovery,
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));

        scan_started.notified().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let outcome = timeout(Duration::from_secs(6), task)
            .await
            .expect("credential expiry must bound cleanup")
            .unwrap()
            .unwrap_err();
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert_eq!(
            outcome,
            SupervisorError::Controller(DriverErrorKind::Unavailable),
            "events: {:?}",
            *events.lock().unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_forces_owner_loss_when_platform_stop_is_stalled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_stop_released: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            discovery,
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            task_cancellation,
        ));

        scan_started.notified().await;
        tokio::task::yield_now().await;
        cancellation.cancel();
        let outcome = timeout(OWNED_STOP_DEADLINE + Duration::from_secs(1), task)
            .await
            .expect("cancelled epoch cleanup must remain bounded")
            .unwrap()
            .unwrap_err();

        assert_eq!(
            outcome,
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_stops_the_old_advertisement_before_registering_a_fresh_nonce() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let advertisements = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: advertisements.clone(),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-stop",
                "advertise"
            ]
        );
        {
            let records = advertisements.lock().unwrap();
            assert_eq!(records.len(), 2);
            assert_ne!(records[0].record(), records[1].record());
        }

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_rotation_forces_owner_loss_and_never_registers_a_replacement() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_stop_released: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-stop-started"
            ]
        );

        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert!(task.is_finished(), "owner loss must release the epoch");
        assert!(task.await.unwrap().is_err());
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "advertise")
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_completion_before_deadline_rotates_without_forced_owner_loss() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop_released = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_stop_released: Some(stop_released.clone()),
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        stop_released.notify_one();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "advertise")
                .count(),
            2
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 0);

        stop_released.notify_one();
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }
}
