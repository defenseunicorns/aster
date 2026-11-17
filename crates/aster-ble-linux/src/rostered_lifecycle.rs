use crate::{
    AsterRosterBeaconV1, AttemptKind, DiscoveryAdmission, DiscoveryCandidate, DiscoveryRecordError,
    DriverError, DriverErrorKind, FixedRole, ObservationOutcome, SupervisorError,
    ValidatedAutomaticRosteredSupervisorConfig, ValidatedRosteredSupervisorConfig,
    controller_resolver::{
        ControllerEpochActivator, ControllerEpochView, OperationalControllerEpoch,
        OperationalEpochFuture, OperationalEpochOutcome, OperationalEpochState,
        spawn_linux_controller_resolver_with_activation,
    },
    discovery::{SCAN_ACTIVE_INTERVAL, SCAN_IDLE_INTERVAL},
    lifecycle::{ContactAdmission, ContactScheduleEffect, contact_schedule_effect},
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
    policy::{CappedBackoff, LifecycleCancellation, LifecycleCancellationObserver},
};
use aster_contact::OrderedContact;
use aster_mesh::NodeId;
use aster_node::{
    ContactDisposition, ContactOutcome, ContactReason, EventAdapterControl,
    EventAdapterRegistration, EventAdapterSnapshot, EventAdapterState, EventAttemptReceiver,
    EventOutboundAttempt, EventTransportKind, MissionPeerExpectation, OrderedEventContactHandle,
    OrderedEventContactRole, PeerReceipt,
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, oneshot, watch},
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
    CoordinatorAttempt(Option<Box<dyn CoordinatorAttempt>>),
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
type CoordinatorAttemptFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type CoordinatorAttemptReceiveFuture<'a> =
    Pin<Box<dyn Future<Output = Option<Box<dyn CoordinatorAttempt>>> + Send + 'a>>;

trait CoordinatorAttempt: Send {
    fn transport_kind(&self) -> EventTransportKind;
    fn mission(&self) -> NodeId;
    fn peer(&self) -> NodeId;
    fn run(self: Box<Self>, contact: Arc<dyn OrderedContact>) -> CoordinatorAttemptFuture;
    fn fail_carrier_open(self: Box<Self>);
    fn fail_unauthenticated_carrier_open(
        self: Box<Self>,
        failure: aster_node::UnauthenticatedCarrierOpenFailure,
    );
    fn cancel_carrier_open(self: Box<Self>);
}

impl CoordinatorAttempt for EventOutboundAttempt {
    fn transport_kind(&self) -> EventTransportKind {
        self.transport_kind()
    }

    fn mission(&self) -> NodeId {
        self.mission()
    }

    fn peer(&self) -> NodeId {
        self.peer()
    }

    fn run(self: Box<Self>, contact: Arc<dyn OrderedContact>) -> CoordinatorAttemptFuture {
        Box::pin(async move {
            let _ = EventOutboundAttempt::run(*self, contact).await;
        })
    }

    fn fail_carrier_open(self: Box<Self>) {
        let _ = EventOutboundAttempt::fail_carrier_open(*self);
    }

    fn fail_unauthenticated_carrier_open(
        self: Box<Self>,
        failure: aster_node::UnauthenticatedCarrierOpenFailure,
    ) {
        let _ = EventOutboundAttempt::fail_unauthenticated_carrier_open(*self, failure);
    }

    fn cancel_carrier_open(self: Box<Self>) {
        let _ = EventOutboundAttempt::cancel_carrier_open(*self);
    }
}

trait CoordinatorAttemptSource: Send {
    fn recv(&mut self) -> CoordinatorAttemptReceiveFuture<'_>;
}

impl CoordinatorAttemptSource for EventAttemptReceiver {
    fn recv(&mut self) -> CoordinatorAttemptReceiveFuture<'_> {
        Box::pin(async move {
            EventAttemptReceiver::recv(self)
                .await
                .map(|attempt| Box::new(attempt) as Box<dyn CoordinatorAttempt>)
        })
    }
}

enum EpochContactMode {
    FixedEvaluation,
    Automatic {
        attempts: Box<dyn CoordinatorAttemptSource>,
        pending: Option<Box<dyn CoordinatorAttempt>>,
    },
}

impl EpochContactMode {
    fn automatic(attempts: Box<dyn CoordinatorAttemptSource>) -> Self {
        Self::Automatic {
            attempts,
            pending: None,
        }
    }

    const fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic { .. })
    }

    fn accepts_inbound(&self, config: &ValidatedRosteredSupervisorConfig) -> bool {
        self.is_automatic() || config.role() == FixedRole::Listener
    }

    fn can_open_outbound(&self, config: &ValidatedRosteredSupervisorConfig) -> bool {
        match self {
            Self::FixedEvaluation => config.role() == FixedRole::Initiator,
            Self::Automatic { pending, .. } => {
                config.role() == FixedRole::Initiator && pending.is_some()
            }
        }
    }

    fn receive_enabled(&self) -> bool {
        matches!(self, Self::Automatic { pending: None, .. })
    }

    async fn recv(&mut self) -> Option<Box<dyn CoordinatorAttempt>> {
        match self {
            Self::FixedEvaluation => std::future::pending().await,
            Self::Automatic { attempts, .. } => attempts.recv().await,
        }
    }

    fn accept_attempt(
        &mut self,
        config: &ValidatedRosteredSupervisorConfig,
        attempt: Box<dyn CoordinatorAttempt>,
    ) -> bool {
        let matches = attempt.transport_kind() == EventTransportKind::BLE_L2CAP_V1
            && attempt.mission() == config.local_mission_id()
            && attempt.peer() == config.peer_mission_id();
        let Self::Automatic { pending, .. } = self else {
            attempt.cancel_carrier_open();
            return false;
        };
        if !matches || pending.is_some() {
            attempt.cancel_carrier_open();
            false
        } else if config.role() != FixedRole::Initiator {
            attempt.fail_carrier_open();
            false
        } else {
            *pending = Some(attempt);
            true
        }
    }

    fn take_outbound(&mut self) -> OutboundAttemptOwner {
        match self {
            Self::FixedEvaluation => OutboundAttemptOwner::FixedEvaluation,
            Self::Automatic { pending, .. } => OutboundAttemptOwner::Coordinator(
                pending
                    .take()
                    .expect("automatic outbound requires a ticket"),
            ),
        }
    }

    fn restore_outbound(&mut self, owner: OutboundAttemptOwner) {
        if let (Self::Automatic { pending, .. }, OutboundAttemptOwner::Coordinator(attempt)) =
            (self, owner)
        {
            debug_assert!(pending.is_none());
            *pending = Some(attempt);
        }
    }

    fn fail_pending_carrier_open(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(attempt) = pending.take()
        {
            attempt.fail_carrier_open();
        }
    }

    fn cancel_pending_carrier_open(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(attempt) = pending.take()
        {
            attempt.cancel_carrier_open();
        }
    }
}

enum OutboundAttemptOwner {
    FixedEvaluation,
    Coordinator(Box<dyn CoordinatorAttempt>),
}

trait EventAvailabilityControl: Send + Sync {
    fn publish_availability(&self, snapshot: EventAdapterSnapshot) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AvailabilityPublishError {
    RegistrationRejected,
    EpochExhausted,
}

impl EventAvailabilityControl for EventAdapterControl {
    fn publish_availability(&self, snapshot: EventAdapterSnapshot) -> bool {
        EventAdapterControl::publish_availability(self, snapshot)
    }
}

struct AdapterAvailabilityPublisher {
    publication: Arc<AvailabilityPublication>,
    selector_can_originate: bool,
}

struct AvailabilityPublication {
    control: Option<Arc<dyn EventAvailabilityControl>>,
    updates: watch::Sender<crate::BtleAvailability>,
    output: crate::BtleOperatorOutput,
    epoch: Mutex<u64>,
}

#[derive(Clone)]
struct UnavailableAvailabilityPublisher {
    publication: Arc<AvailabilityPublication>,
}

impl AdapterAvailabilityPublisher {
    fn fixed(
        updates: watch::Sender<crate::BtleAvailability>,
        output: crate::BtleOperatorOutput,
    ) -> Self {
        Self {
            publication: Arc::new(AvailabilityPublication {
                control: None,
                updates,
                output,
                epoch: Mutex::new(crate::AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH),
            }),
            selector_can_originate: false,
        }
    }

    fn automatic(
        control: Arc<dyn EventAvailabilityControl>,
        updates: watch::Sender<crate::BtleAvailability>,
        output: crate::BtleOperatorOutput,
        role: FixedRole,
    ) -> Self {
        Self {
            publication: Arc::new(AvailabilityPublication {
                control: Some(control),
                updates,
                output,
                epoch: Mutex::new(crate::AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH),
            }),
            selector_can_originate: role == FixedRole::Initiator,
        }
    }

    fn unavailable_only(&self) -> UnavailableAvailabilityPublisher {
        UnavailableAvailabilityPublisher {
            publication: self.publication.clone(),
        }
    }

    fn publish(
        &self,
        availability: crate::BtleAvailability,
    ) -> Result<(), AvailabilityPublishError> {
        let state =
            if self.selector_can_originate && availability == crate::BtleAvailability::Available {
                EventAdapterState::Available
            } else {
                EventAdapterState::Unavailable
            };
        self.publication.publish(availability, state)
    }
}

impl UnavailableAvailabilityPublisher {
    fn publish(&self) -> Result<(), AvailabilityPublishError> {
        self.publication.publish(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
            EventAdapterState::Unavailable,
        )
    }
}

impl AvailabilityPublication {
    fn publish(
        &self,
        availability: crate::BtleAvailability,
        state: EventAdapterState,
    ) -> Result<(), AvailabilityPublishError> {
        let mut current_epoch = self
            .epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *self.updates.borrow() == availability {
            return Ok(());
        }
        if let Some(control) = &self.control {
            let epoch = (*current_epoch)
                .checked_add(1)
                .ok_or(AvailabilityPublishError::EpochExhausted)?;
            if !control.publish_availability(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                epoch,
                state,
                true,
                0,
            )) {
                return Err(AvailabilityPublishError::RegistrationRejected);
            }
            *current_epoch = epoch;
        }
        self.updates.send_replace(availability);
        self.output
            .emit(crate::controller::availability_event(availability));
        Ok(())
    }
}

#[derive(Default)]
struct EpochSignals {
    availability: Option<watch::Sender<crate::BtleAvailability>>,
    publisher: Option<Arc<AdapterAvailabilityPublisher>>,
    available_started: Option<oneshot::Sender<Instant>>,
    operational: Option<watch::Sender<OperationalEpochState>>,
    availability_fence: Option<Arc<AvailabilityFence>>,
    supervisor_availability_fence: Option<Arc<AvailabilityFence>>,
}

#[derive(Default)]
struct AvailabilityFence(Mutex<bool>);

impl AvailabilityFence {
    fn quiesce(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }
}

impl EpochSignals {
    fn with_publisher(
        publisher: Arc<AdapterAvailabilityPublisher>,
        available_started: oneshot::Sender<Instant>,
    ) -> Self {
        Self {
            availability: None,
            publisher: Some(publisher),
            available_started: Some(available_started),
            operational: None,
            availability_fence: None,
            supervisor_availability_fence: None,
        }
    }

    fn operational(
        publisher: Arc<AdapterAvailabilityPublisher>,
        operational: watch::Sender<OperationalEpochState>,
        availability_fence: Arc<AvailabilityFence>,
        supervisor_availability_fence: Arc<AvailabilityFence>,
    ) -> Self {
        Self {
            availability: None,
            publisher: Some(publisher),
            available_started: None,
            operational: Some(operational),
            availability_fence: Some(availability_fence),
            supervisor_availability_fence: Some(supervisor_availability_fence),
        }
    }

    fn publish(&self, availability: crate::BtleAvailability) -> Result<(), SupervisorError> {
        let _supervisor_available_guard = if availability == crate::BtleAvailability::Available {
            let guard = self.supervisor_availability_fence.as_ref().map(|fence| {
                fence
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            });
            if guard.as_deref().is_some_and(|quiesced| *quiesced) {
                return Err(SupervisorError::TaskStopped);
            }
            guard
        } else {
            None
        };
        let _epoch_available_guard = if availability == crate::BtleAvailability::Available {
            let guard = self.availability_fence.as_ref().map(|fence| {
                fence
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            });
            if guard.as_deref().is_some_and(|quiesced| *quiesced) {
                return Err(SupervisorError::TaskStopped);
            }
            guard
        } else {
            None
        };
        let result = if let Some(publisher) = &self.publisher {
            publisher
                .publish(availability)
                .map_err(|_| SupervisorError::TaskStopped)
        } else if let Some(updates) = &self.availability {
            publish_availability(updates, availability);
            Ok(())
        } else {
            Ok(())
        };
        if result.is_ok()
            && let Some(operational) = &self.operational
        {
            let state = if availability == crate::BtleAvailability::Available {
                OperationalEpochState::Available
            } else {
                OperationalEpochState::Unavailable
            };
            operational.send_replace(state);
        }
        result
    }
}

/// Closed reason an automatic BTLE registration was rejected before startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomaticBtleRegistrationError {
    /// The paired registration belongs to another transport kind.
    WrongTransport,
    /// Automatic BTLE registration must begin at the fixed initial epoch.
    InitialEpoch,
    /// Automatic BTLE registration must begin unavailable.
    InitialState,
    /// The registration does not permit Event contacts.
    NotEventCapable,
}

impl fmt::Display for AutomaticBtleRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTransport => "automatic BTLE registration has the wrong transport kind",
            Self::InitialEpoch => "automatic BTLE registration has the wrong initial epoch",
            Self::InitialState => "automatic BTLE registration must begin unavailable",
            Self::NotEventCapable => "automatic BTLE registration is not Event-capable",
        })
    }
}

impl std::error::Error for AutomaticBtleRegistrationError {}

fn validate_automatic_registration(
    registration: EventAdapterRegistration,
) -> Result<(EventAdapterControl, EventAttemptReceiver), AutomaticBtleRegistrationError> {
    let snapshot = registration.initial_snapshot();
    if snapshot.kind() != EventTransportKind::BLE_L2CAP_V1 {
        return Err(AutomaticBtleRegistrationError::WrongTransport);
    }
    if snapshot.availability_epoch() != crate::AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH {
        return Err(AutomaticBtleRegistrationError::InitialEpoch);
    }
    if snapshot.state() != EventAdapterState::Unavailable {
        return Err(AutomaticBtleRegistrationError::InitialState);
    }
    if !snapshot.event_capable() {
        return Err(AutomaticBtleRegistrationError::NotEventCapable);
    }
    let (_, control, attempts) = registration.into_parts();
    Ok((control, attempts))
}

enum ContactAttemptOutcome {
    Opened {
        opened: Box<OpenedContact>,
        owner: OutboundAttemptOwner,
    },
    Completed(Box<Result<PeerReceipt, ContactOutcome>>),
    CoordinatorCompleted,
    OpenFailed(Box<ContactOpenFailure>),
    Cancelled,
}

struct ContactOpenFailure {
    candidate: DiscoveryCandidate,
    error: DriverError,
    owner: OutboundAttemptOwner,
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
        owner: OutboundAttemptOwner,
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
                    Ok(opened) => ContactAttemptOutcome::Opened {
                        opened: Box::new(opened),
                        owner,
                    },
                    Err(error) => ContactAttemptOutcome::OpenFailed(Box::new(ContactOpenFailure {
                        candidate,
                        error,
                        owner,
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

    fn admitted_coordinator(attempt: Box<dyn CoordinatorAttempt>, opened: OpenedContact) -> Self {
        let cancellation = LifecycleCancellation::new();
        let work_cancellation = cancellation.clone();
        Self::Active {
            cancellation,
            work: Box::pin(async move {
                run_coordinator_contact(attempt, opened, &work_cancellation).await
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

    async fn join(self) -> Option<ContactAttemptOutcome> {
        if let Self::Active { mut work, .. } = self {
            Some((&mut work).await)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
enum EpochContactTermination {
    Cancelled,
    LocalEpochLoss,
}

fn complete_interrupted_contact(
    outcome: Option<ContactAttemptOutcome>,
    termination: EpochContactTermination,
) {
    let owner = match outcome {
        Some(ContactAttemptOutcome::Opened { opened, owner }) => {
            drop(opened);
            Some(owner)
        }
        Some(ContactAttemptOutcome::OpenFailed(failure)) => Some(failure.owner),
        Some(
            ContactAttemptOutcome::Completed(_)
            | ContactAttemptOutcome::CoordinatorCompleted
            | ContactAttemptOutcome::Cancelled,
        )
        | None => None,
    };
    let Some(OutboundAttemptOwner::Coordinator(attempt)) = owner else {
        return;
    };
    match termination {
        EpochContactTermination::Cancelled => attempt.cancel_carrier_open(),
        EpochContactTermination::LocalEpochLoss => attempt.fail_carrier_open(),
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
    output: crate::BtleOperatorOutput,
    failure_park: Option<(Arc<AvailabilityFence>, UnavailableAvailabilityPublisher)>,
    task: Option<JoinHandle<Result<(), SupervisorError>>>,
    abort_on_unconfirmed_cleanup: bool,
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

    /// Returns the coarse terminal supervisor signal.
    pub fn completion(&self) -> watch::Receiver<bool> {
        self.completion.clone()
    }

    /// Requests idempotent cancellation of all owned rostered lifecycle work.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Fences late availability and publishes the adapter unavailable before
    /// an authority failure begins cleanup.
    pub fn park_unavailable(&self) -> Result<(), SupervisorError> {
        let Some((fence, publisher)) = &self.failure_park else {
            return Ok(());
        };
        fence.quiesce();
        publisher
            .publish()
            .map_err(|_| SupervisorError::TaskStopped)
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

    /// Consumes the supervisor and joins its owned lifecycle work.
    pub async fn shutdown(mut self) -> Result<(), SupervisorError> {
        self.cancel();
        let mut task = self.task.take().expect("supervisor task retained");
        match timeout(OWNER_LOSS_AFTER, &mut task).await {
            Ok(result) => {
                let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                self.output.emit(crate::BtleOperatorEvent::Stopped);
                result
            }
            Err(_) => {
                self.platform_owner.force_loss();
                self.output.emit(crate::BtleOperatorEvent::CleanupForced);
                match timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await {
                    Ok(result) => {
                        let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                        self.output.emit(crate::BtleOperatorEvent::Stopped);
                        result
                    }
                    Err(_) if self.abort_on_unconfirmed_cleanup => {
                        task.abort();
                        let _ = task.await;
                        self.output
                            .emit(crate::BtleOperatorEvent::CleanupUnconfirmed);
                        Err(SupervisorError::PlatformCleanupUnconfirmed)
                    }
                    Err(_) => {
                        self.output
                            .emit(crate::BtleOperatorEvent::CleanupUnconfirmed);
                        retain_task_custody(task);
                        Err(SupervisorError::PlatformCleanupUnconfirmed)
                    }
                }
            }
        }
    }
}

impl Drop for LinuxRosteredBtleEventSupervisor {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        let _ = self.park_unavailable();
        self.cancellation.cancel();
        let platform_owner = self.platform_owner.clone();
        let output = self.output.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                contain_supervisor_task(task, platform_owner, output).await;
            });
        }
    }
}

fn retain_task_custody(task: JoinHandle<Result<(), SupervisorError>>) {
    tokio::spawn(async move {
        let _ = task.await;
    });
}

async fn contain_supervisor_task(
    mut task: JoinHandle<Result<(), SupervisorError>>,
    platform_owner: Arc<PlatformOwner>,
    output: crate::BtleOperatorOutput,
) {
    if timeout(OWNER_LOSS_AFTER, &mut task).await.is_ok() {
        return;
    }
    platform_owner.force_loss();
    output.emit(crate::BtleOperatorEvent::CleanupForced);
    if timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await.is_err() {
        output.emit(crate::BtleOperatorEvent::CleanupUnconfirmed);
        let _ = task.await;
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
    spawn_rostered_btle_event_supervisor(
        config,
        contacts,
        EpochContactMode::FixedEvaluation,
        None,
        crate::BtleOperatorOutput::discard(),
    )
}

/// Starts the compatibility automatic-contact supervisor for one exact controller.
pub fn spawn_automatic_linux_rostered_btle_event_supervisor(
    config: ValidatedRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
    registration: EventAdapterRegistration,
    output: crate::BtleOperatorOutput,
) -> Result<LinuxRosteredBtleEventSupervisor, AutomaticBtleRegistrationError> {
    let (adapter_control, attempts) = validate_automatic_registration(registration)?;
    Ok(spawn_rostered_btle_event_supervisor(
        config,
        contacts,
        EpochContactMode::automatic(Box::new(attempts)),
        Some(Arc::new(adapter_control)),
        output,
    ))
}

struct RosteredEpochActivator {
    config: Arc<ValidatedAutomaticRosteredSupervisorConfig>,
    contacts: Arc<OrderedEventContactHandle>,
    mode: Arc<AsyncMutex<EpochContactMode>>,
    publisher: Arc<AdapterAvailabilityPublisher>,
    platform_owner: Arc<PlatformOwner>,
    supervisor_availability_fence: Arc<AvailabilityFence>,
}

impl ControllerEpochActivator for RosteredEpochActivator {
    fn activate(
        &self,
        epoch: ControllerEpochView<'_>,
    ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
        let config = Arc::new(self.config.for_controller(
            epoch.adapter_name().to_owned(),
            epoch.address(),
            epoch.address_type(),
            epoch.inventory_generation(),
            epoch.cancellation(),
        )?);
        let (updates, status) = watch::channel(OperationalEpochState::Starting);
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.observer();
        let task_cancellation = cancellation.clone();
        let availability_fence = Arc::new(AvailabilityFence::default());
        let task_availability_fence = availability_fence.clone();
        let (quiesce, mut quiesce_requests) = mpsc::channel(1);
        let contacts = self.contacts.clone();
        let mode = self.mode.clone();
        let publisher = self.publisher.clone();
        let platform_owner = self.platform_owner.clone();
        let supervisor_availability_fence = self.supervisor_availability_fence.clone();
        let task_updates = updates.clone();
        let task = tokio::spawn(async move {
            let epoch = async {
                let discovery = match await_startup_platform(
                    config.epoch_discovery_credentials().expires_at(),
                    config.open_timeout(),
                    &observer,
                    BluezDiscoveryPlatform::open(),
                )
                .await
                {
                    Ok(discovery) => discovery,
                    Err(error) => {
                        return finish_operational_epoch_result(
                            Err(error),
                            platform_owner.as_ref(),
                        );
                    }
                };
                platform_owner.replace(discovery.owner_loss());
                let sockets = Arc::new(BluezRosteredSocketFactory);
                let nonces = Arc::new(production_nonce_source());
                let mut mode = mode.lock().await;
                let result = run_available_epoch_with_mode(
                    config,
                    sockets,
                    Arc::new(discovery),
                    nonces,
                    contacts,
                    &mut mode,
                    EpochSignals::operational(
                        publisher.clone(),
                        task_updates.clone(),
                        task_availability_fence,
                        supervisor_availability_fence,
                    ),
                    observer.clone(),
                )
                .await;
                complete_pending_after_epoch(&mut mode, &observer, &result);
                finish_operational_epoch_result(result, platform_owner.as_ref())
            };
            tokio::pin!(epoch);
            let (result, quiesced) = tokio::select! {
                biased;
                request = quiesce_requests.recv() => {
                    if let Some(acknowledged) = request {
                        acknowledge_operational_quiesce(
                            &publisher,
                            &task_updates,
                            acknowledged,
                        );
                    }
                    task_cancellation.cancel();
                    (epoch.await, true)
                }
                result = &mut epoch => (result, false),
            };
            let _ = publisher.publish(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ));
            task_updates.send_replace(OperationalEpochState::Unavailable);
            if !quiesced && let Some(acknowledged) = quiesce_requests.recv().await {
                acknowledge_operational_quiesce(&publisher, &task_updates, acknowledged);
                task_cancellation.cancel();
            }
            result
        });
        Ok(Box::new(RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence,
            cancellation,
            task: Some(task),
            platform_owner: self.platform_owner.clone(),
            unavailable: self.publisher.unavailable_only(),
        }))
    }
}

fn finish_operational_epoch_result(
    result: Result<(), SupervisorError>,
    platform_owner: &PlatformOwner,
) -> OperationalEpochOutcome {
    let terminal = match result {
        Ok(()) | Err(SupervisorError::Controller(_)) => None,
        Err(SupervisorError::ContactSuppressed(_)) => {
            platform_owner.clear();
            return OperationalEpochOutcome::Suppressed;
        }
        Err(SupervisorError::PlatformCleanupUnconfirmed) => Some(DriverError::new(
            DriverErrorKind::Transport,
            "automatic rostered Event cleanup was not confirmed",
        )),
        Err(
            SupervisorError::Configuration
            | SupervisorError::AdmissionClosed
            | SupervisorError::ActorUnavailable
            | SupervisorError::ActorStopped
            | SupervisorError::ContactTerminal(_)
            | SupervisorError::TaskStopped,
        ) => Some(DriverError::new(
            DriverErrorKind::Transport,
            "automatic rostered Event operation terminated",
        )),
    };
    if let Some(error) = terminal {
        OperationalEpochOutcome::Terminal(error)
    } else {
        platform_owner.clear();
        OperationalEpochOutcome::Retryable
    }
}

fn acknowledge_operational_quiesce(
    publisher: &AdapterAvailabilityPublisher,
    updates: &watch::Sender<OperationalEpochState>,
    acknowledged: oneshot::Sender<Result<(), DriverError>>,
) {
    let unavailable = publisher
        .publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
        .map_err(|_| {
            DriverError::new(
                DriverErrorKind::Transport,
                "automatic Event availability publication failed",
            )
        });
    updates.send_replace(OperationalEpochState::Unavailable);
    let _ = acknowledged.send(unavailable);
}

struct RosteredOperationalEpoch {
    status: watch::Receiver<OperationalEpochState>,
    quiesce: mpsc::Sender<oneshot::Sender<Result<(), DriverError>>>,
    availability_fence: Arc<AvailabilityFence>,
    cancellation: LifecycleCancellation,
    task: Option<JoinHandle<OperationalEpochOutcome>>,
    platform_owner: Arc<PlatformOwner>,
    unavailable: UnavailableAvailabilityPublisher,
}

impl OperationalControllerEpoch for RosteredOperationalEpoch {
    fn status(&self) -> watch::Receiver<OperationalEpochState> {
        self.status.clone()
    }

    fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>> {
        self.availability_fence.quiesce();
        Box::pin(async move {
            let (acknowledged, acknowledgement) = oneshot::channel();
            self.quiesce.send(acknowledged).await.map_err(|_| {
                self.publish_unavailable_after_failure(
                    "automatic rostered Event epoch quiesce channel closed",
                )
            })?;
            acknowledgement.await.map_err(|_| {
                self.publish_unavailable_after_failure(
                    "automatic rostered Event epoch quiesce was not acknowledged",
                )
            })?
        })
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn join(mut self: Box<Self>) -> OperationalEpochFuture<'static, OperationalEpochOutcome> {
        Box::pin(async move {
            self.availability_fence.quiesce();
            let task_result = self
                .task
                .as_mut()
                .expect("operational epoch task retained")
                .await;
            let _ = self.task.take();
            match task_result {
                Ok(OperationalEpochOutcome::Retryable) => OperationalEpochOutcome::Retryable,
                Ok(OperationalEpochOutcome::Suppressed) => {
                    self.platform_owner.clear();
                    OperationalEpochOutcome::Suppressed
                }
                Ok(OperationalEpochOutcome::Terminal(error)) => {
                    let _ = self.unavailable.publish();
                    self.platform_owner.force_loss();
                    OperationalEpochOutcome::Terminal(error)
                }
                Err(_) => {
                    let _ = self.unavailable.publish();
                    self.platform_owner.force_loss();
                    OperationalEpochOutcome::Terminal(DriverError::new(
                        DriverErrorKind::Transport,
                        "automatic rostered Event epoch cleanup was not confirmed",
                    ))
                }
            }
        })
    }
}

impl RosteredOperationalEpoch {
    fn publish_unavailable_after_failure(&self, message: &'static str) -> DriverError {
        let _ = self.unavailable.publish();
        DriverError::new(DriverErrorKind::Transport, message)
    }
}

impl Drop for RosteredOperationalEpoch {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        self.availability_fence.quiesce();
        let _ = self.unavailable.publish();
        self.cancellation.cancel();
        let platform_owner = self.platform_owner.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                contain_operational_epoch_task(task, platform_owner).await;
            });
        } else {
            platform_owner.force_loss();
            task.abort();
        }
    }
}

async fn contain_operational_epoch_task(
    mut task: JoinHandle<OperationalEpochOutcome>,
    platform_owner: Arc<PlatformOwner>,
) {
    match timeout(OWNER_LOSS_AFTER, &mut task).await {
        Ok(Ok(OperationalEpochOutcome::Retryable | OperationalEpochOutcome::Suppressed)) => return,
        Ok(Ok(OperationalEpochOutcome::Terminal(_)) | Err(_)) => {
            platform_owner.force_loss();
            return;
        }
        Err(_) => {}
    }
    platform_owner.force_loss();
    if timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
}

/// Starts one automatic rostered Linux BTLE Event adapter.
///
/// The caller owns host policy and must first register an unavailable
/// `BLE_L2CAP_V1` adapter snapshot at epoch zero. This owner retains the
/// registration control and consumes the corresponding single-owner attempt
/// receiver until shutdown.
pub fn spawn_resolving_linux_rostered_btle_event_supervisor(
    config: ValidatedAutomaticRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
    registration: EventAdapterRegistration,
    output: crate::BtleOperatorOutput,
) -> Result<LinuxRosteredBtleEventSupervisor, AutomaticBtleRegistrationError> {
    let (adapter_control, attempts) = validate_automatic_registration(registration)?;
    let config = Arc::new(config);
    let expires_at = config.discovery_credentials_expires_at();
    let cancellation = LifecycleCancellation::new();
    let initial = crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    let (availability_updates, availability) = watch::channel(initial);
    let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
        Arc::new(adapter_control),
        availability_updates,
        crate::BtleOperatorOutput::discard(),
        config.role(),
    ));
    let platform_owner = Arc::new(PlatformOwner::default());
    let supervisor_availability_fence = Arc::new(AvailabilityFence::default());
    let activator = Arc::new(RosteredEpochActivator {
        config: config.clone(),
        contacts: Arc::new(contacts),
        mode: Arc::new(AsyncMutex::new(EpochContactMode::automatic(Box::new(
            attempts,
        )))),
        publisher: publisher.clone(),
        platform_owner: platform_owner.clone(),
        supervisor_availability_fence: supervisor_availability_fence.clone(),
    });
    let resolver = spawn_linux_controller_resolver_with_activation(
        config.controller_policy().clone(),
        config.controller_probe_limits(),
        output.clone(),
        activator,
    );
    let (completion_updates, completion) = watch::channel(false);
    let task_cancellation = cancellation.clone();
    let failure_park = (
        supervisor_availability_fence.clone(),
        publisher.unavailable_only(),
    );
    let task = tokio::spawn(async move {
        let _completion = CompletionOnDrop(completion_updates);
        let status = resolver.status();
        run_automatic_resolver_owner(
            status,
            task_cancellation,
            expires_at,
            supervisor_availability_fence,
            publisher.unavailable_only(),
            async move { resolver.shutdown_for_supervisor().await },
        )
        .await
    });
    Ok(LinuxRosteredBtleEventSupervisor {
        availability,
        completion,
        cancellation,
        platform_owner,
        output,
        failure_park: Some(failure_park),
        task: Some(task),
        abort_on_unconfirmed_cleanup: false,
    })
}

async fn run_automatic_resolver_owner<T, F>(
    mut status: watch::Receiver<T>,
    cancellation: LifecycleCancellation,
    expires_at: Instant,
    supervisor_availability_fence: Arc<AvailabilityFence>,
    unavailable: UnavailableAvailabilityPublisher,
    shutdown: F,
) -> Result<(), SupervisorError>
where
    T: Send + Sync + 'static,
    F: Future<Output = Result<(), DriverError>>,
{
    enum Wake {
        Stop,
        Expired,
    }

    let resolver_stopped = async { while status.changed().await.is_ok() {} };
    let wake = tokio::select! {
        biased;
        () = cancellation.cancelled() => Wake::Stop,
        () = resolver_stopped => Wake::Stop,
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)) => Wake::Expired,
    };
    let publication_error = if matches!(wake, Wake::Expired) {
        supervisor_availability_fence.quiesce();
        unavailable
            .publish()
            .err()
            .map(|_| SupervisorError::TaskStopped)
    } else {
        None
    };
    let shutdown_result = if matches!(wake, Wake::Expired) {
        timeout(OWNER_LOSS_AFTER, shutdown)
            .await
            .map_err(|_| SupervisorError::PlatformCleanupUnconfirmed)
            .and_then(|result| result.map_err(|_| SupervisorError::PlatformCleanupUnconfirmed))
    } else {
        shutdown
            .await
            .map_err(|_| SupervisorError::PlatformCleanupUnconfirmed)
    };
    shutdown_result?;
    if let Some(error) = publication_error {
        return Err(error);
    }
    if matches!(wake, Wake::Expired) {
        cancellation.cancelled().await;
    }
    Ok(())
}

fn spawn_rostered_btle_event_supervisor(
    config: ValidatedRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
    mode: EpochContactMode,
    adapter_control: Option<Arc<dyn EventAvailabilityControl>>,
    output: crate::BtleOperatorOutput,
) -> LinuxRosteredBtleEventSupervisor {
    let role = config.role();
    let cancellation = LifecycleCancellation::new();
    let initial = crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    let (availability_updates, availability) = watch::channel(initial);
    output.emit(crate::BtleOperatorEvent::AdapterUnavailable(
        crate::AvailabilityReason::BluezUnavailable,
    ));
    let publisher = Arc::new(match adapter_control {
        Some(control) => AdapterAvailabilityPublisher::automatic(
            control,
            availability_updates,
            output.clone(),
            role,
        ),
        None => AdapterAvailabilityPublisher::fixed(availability_updates, output.clone()),
    });
    let (completion_updates, completion) = watch::channel(false);
    let platform_owner = Arc::new(PlatformOwner::default());
    let task_cancellation = cancellation.clone();
    let task_platform_owner = platform_owner.clone();
    let task = tokio::spawn(async move {
        let _completion = CompletionOnDrop(completion_updates);
        run_rostered_supervisor(
            Arc::new(config),
            Arc::new(contacts),
            publisher,
            task_cancellation,
            task_platform_owner,
            mode,
        )
        .await
    });
    LinuxRosteredBtleEventSupervisor {
        availability,
        completion,
        cancellation,
        platform_owner,
        output,
        failure_park: None,
        task: Some(task),
        abort_on_unconfirmed_cleanup: true,
    }
}

async fn run_rostered_supervisor(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    contacts: Arc<OrderedEventContactHandle>,
    publisher: Arc<AdapterAvailabilityPublisher>,
    cancellation: LifecycleCancellation,
    platform_owner: Arc<PlatformOwner>,
    mut mode: EpochContactMode,
) -> Result<(), SupervisorError> {
    let sockets = Arc::new(BluezRosteredSocketFactory);
    let nonces = Arc::new(production_nonce_source());
    let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() {
            return park_expired_adapter(config, &publisher, &cancellation).await;
        }
        let discovery = match await_startup_platform(
            config.epoch_discovery_credentials().expires_at(),
            config.open_timeout(),
            &cancellation.observer(),
            BluezDiscoveryPlatform::open(),
        )
        .await
        {
            Ok(discovery) => discovery,
            Err(SupervisorError::Configuration) => return Err(SupervisorError::Configuration),
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled)) => return Ok(()),
            Err(_) if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() => {
                return park_expired_adapter(config, &publisher, &cancellation).await;
            }
            Err(_) => {
                publisher
                    .publish(crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ))
                    .map_err(|_| SupervisorError::TaskStopped)?;
                if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                    return Ok(());
                }
                continue;
            }
        };
        platform_owner.replace(discovery.owner_loss());
        let (available_started, available_started_at) = oneshot::channel();
        let result = run_available_epoch_with_mode(
            config.clone(),
            sockets.clone(),
            Arc::new(discovery),
            nonces.clone(),
            contacts.clone(),
            &mut mode,
            EpochSignals::with_publisher(publisher.clone(), available_started),
            cancellation.observer(),
        )
        .await;
        complete_pending_after_epoch(&mut mode, &cancellation.observer(), &result);
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
                | SupervisorError::ContactSuppressed(_)
                | SupervisorError::ContactTerminal(_)
                | SupervisorError::TaskStopped
                | SupervisorError::PlatformCleanupUnconfirmed),
            ) => return Err(error),
            Err(SupervisorError::Controller(_)) => {
                publisher
                    .publish(crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ))
                    .map_err(|_| SupervisorError::TaskStopped)?;
                if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() {
                    return park_expired_adapter(config, &publisher, &cancellation).await;
                }
                if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                    return Ok(());
                }
            }
        }
    }
}

fn complete_pending_after_epoch(
    mode: &mut EpochContactMode,
    cancellation: &LifecycleCancellationObserver,
    result: &Result<(), SupervisorError>,
) {
    if matches!(result, Err(SupervisorError::Controller(_))) && !cancellation.is_cancelled() {
        mode.fail_pending_carrier_open();
    } else {
        mode.cancel_pending_carrier_open();
    }
}

async fn park_expired_adapter(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    publisher: &AdapterAvailabilityPublisher,
    cancellation: &LifecycleCancellation,
) -> Result<(), SupervisorError> {
    drop(config);
    publisher
        .publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
        .map_err(|_| SupervisorError::TaskStopped)?;
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

async fn await_startup_platform<T, F>(
    expires_at: Instant,
    open_timeout: Duration,
    cancellation: &LifecycleCancellationObserver,
    operation: F,
) -> Result<T, SupervisorError>
where
    F: Future<Output = Result<T, DriverError>>,
{
    let local_deadline = tokio::time::Instant::now() + open_timeout;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let deadline = local_deadline.min(credential_deadline);
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
        }
        () = tokio::time::sleep_until(deadline) => {
            Err(SupervisorError::Controller(DriverErrorKind::Unavailable))
        }
        result = &mut operation => result.map_err(supervisor_error),
    }
}

fn publish_availability(
    updates: &watch::Sender<crate::BtleAvailability>,
    availability: crate::BtleAvailability,
) {
    let _ = updates.send_if_modified(|current| {
        if *current == availability {
            false
        } else {
            *current = availability;
            true
        }
    });
}

#[cfg(test)]
async fn run_available_epoch<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    contacts: SharedContactAdmission,
    signals: EpochSignals,
    cancellation: LifecycleCancellation,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let mut mode = EpochContactMode::FixedEvaluation;
    run_available_epoch_with_mode(
        config,
        sockets,
        discovery,
        nonces,
        contacts,
        &mut mode,
        signals,
        cancellation.observer(),
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn run_automatic_available_epoch<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    contacts: SharedContactAdmission,
    attempts: Box<dyn CoordinatorAttemptSource>,
    signals: EpochSignals,
    cancellation: LifecycleCancellation,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let mut mode = EpochContactMode::automatic(attempts);
    run_available_epoch_with_mode(
        config,
        sockets,
        discovery,
        nonces,
        contacts,
        &mut mode,
        signals,
        cancellation.observer(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_available_epoch_with_mode<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    contacts: SharedContactAdmission,
    mode: &mut EpochContactMode,
    mut signals: EpochSignals,
    cancellation: LifecycleCancellationObserver,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let expires_at = config.epoch_discovery_credentials().expires_at();
    let bound_listener = await_startup_platform(
        expires_at,
        config.open_timeout(),
        &cancellation,
        sockets.bind_dynamic_listener(config.controller()),
    )
    .await?;
    let listener_psm = bound_listener.allocated_psm();
    let listener = Arc::new(bound_listener.into_listener());
    let record =
        encode_advertisement(&config, listener_psm, nonces.as_ref()).map_err(supervisor_error)?;
    let mut advertisement = Some(
        match await_startup_platform(
            expires_at,
            config.open_timeout(),
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
        let cleanup = release_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        )
        .await;
        drop(listener);
        cleanup.map_err(owned_cleanup_unconfirmed)?;
        return Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
    }
    let started_scan = match await_startup_platform(
        expires_at,
        config.open_timeout(),
        &cancellation,
        discovery.start_scan(config.controller()),
    )
    .await
    {
        Ok(started) => started,
        Err(error) => {
            discovery.force_owner_loss();
            let cleanup = release_advertisement(
                advertisement
                    .as_mut()
                    .expect("advertisement was just registered")
                    .as_mut(),
            )
            .await;
            drop(listener);
            cleanup.map_err(owned_cleanup_unconfirmed)?;
            return Err(error);
        }
    };
    if lifecycle_now() >= expires_at {
        discovery.force_owner_loss();
        let (mut scan, _) = started_scan.into_parts();
        let scan_cleanup = stop_scan(scan.as_mut());
        let advertisement_cleanup = release_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        );
        let (scan_result, advertisement_result) = tokio::join!(scan_cleanup, advertisement_cleanup);
        drop(listener);
        scan_result.map_err(owned_cleanup_unconfirmed)?;
        advertisement_result.map_err(owned_cleanup_unconfirmed)?;
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
    let advertisement_deadline = tokio::time::Instant::now() + ADVERTISEMENT_ROTATION_INTERVAL;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let mut contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
    let mut outbound_delay = OutboundDelay::Ready;
    let mut outbound_candidate_pending = false;
    let mut contact_backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    let mut owner_loss_required = true;
    let mut result = if cancellation.is_cancelled() {
        Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
    } else {
        config
            .controller()
            .ensure_current()
            .map_err(supervisor_error)
            .and_then(|()| signals.publish(crate::BtleAvailability::Available))
    };
    if result.is_ok()
        && let Some(available_started) = signals.available_started.take()
    {
        let _ = available_started.send(lifecycle_now());
    }

    if result.is_ok() {
        result = loop {
            let contact_is_free = contact_phase.is_free();
            let outbound_retry_enabled =
                contact_is_free && outbound_candidate_pending && mode.can_open_outbound(&config);
            let coordinator_receive_enabled = mode.receive_enabled();
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
                        attempt = mode.recv(), if coordinator_receive_enabled => {
                            EpochEvent::CoordinatorAttempt(attempt)
                        },
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
                        attempt = mode.recv(), if coordinator_receive_enabled => {
                            EpochEvent::CoordinatorAttempt(attempt)
                        },
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
                    let mut previous = advertisement.take().expect("advertisement is live");
                    if let Err(error) = release_advertisement(previous.as_mut()).await {
                        break Err(owned_cleanup_unconfirmed(error));
                    }
                    owner_loss_required = false;
                    break Err(SupervisorError::Controller(DriverErrorKind::Transport));
                }
                EpochEvent::Observation(Some(observation)) => {
                    let now = lifecycle_now();
                    let outcome =
                        admit_platform_observation(&mut admission, &config, observation, now);
                    if matches!(outcome, ObservationOutcome::StopWindow(_)) {
                        if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await
                        {
                            break Err(error);
                        }
                    } else if outcome == ObservationOutcome::Accepted
                        && (mode.is_automatic() || config.role() == FixedRole::Initiator)
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
                            mode,
                        )
                        .await
                        {
                            Ok(Some(phase)) => contact_phase = phase,
                            Ok(None) => {}
                            Err(error) => break Err(error),
                        }
                    }
                }
                EpochEvent::InboundAccepted(accepted) => {
                    let (opened_socket, locator) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) if error.kind() == DriverErrorKind::PeerRejected => {
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        Err(error) => break Err(supervisor_error(error)),
                    };
                    let now = lifecycle_now();
                    match admit_inbound_contact(&config, &mut admission, locator, now, mode) {
                        InboundContactAdmission::Admitted => {}
                        InboundContactAdmission::Rejected => {
                            drop(opened_socket);
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
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
                        break Err(error);
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
                        mode,
                    )
                    .await
                    {
                        Ok(Some(phase)) => contact_phase = phase,
                        Ok(None) => {}
                        Err(error) => break Err(error),
                    }
                }
                EpochEvent::CoordinatorAttempt(Some(attempt)) => {
                    if mode.accept_attempt(&config, attempt) {
                        outbound_candidate_pending =
                            admission.selected_candidate(lifecycle_now()).is_some();
                        if outbound_candidate_pending && contact_phase.is_free() {
                            match begin_outbound_contact(
                                &config,
                                &sockets,
                                &mut admission,
                                &mut scan_phase,
                                &mut outbound_candidate_pending,
                                &mut outbound_delay,
                                mode,
                            )
                            .await
                            {
                                Ok(Some(phase)) => contact_phase = phase,
                                Ok(None) => {}
                                Err(error) => break Err(error),
                            }
                        }
                    }
                }
                EpochEvent::CoordinatorAttempt(None) => break Ok(()),
                EpochEvent::ContactFinished(outcome) => {
                    let now = lifecycle_now();
                    let outcome = match outcome {
                        ContactAttemptOutcome::Opened { opened, owner } => {
                            if now >= config.epoch_discovery_credentials().expires_at() {
                                drop(opened);
                                if let OutboundAttemptOwner::Coordinator(attempt) = owner {
                                    attempt.fail_carrier_open();
                                }
                                break Err(SupervisorError::Controller(
                                    DriverErrorKind::Unavailable,
                                ));
                            }
                            if !admission.try_consume_attempt(AttemptKind::MissionHandshake, now) {
                                drop(opened);
                                admission.contact_closed(now);
                                scan_phase = idle_scan_phase();
                                outbound_candidate_pending = true;
                                mode.restore_outbound(owner);
                                outbound_delay = OutboundDelay::TokenRefillUntil(
                                    admission.attempt_retry_at(AttemptKind::MissionHandshake, now),
                                );
                                contact_phase =
                                    ContactPhase::accepting(sockets.clone(), listener.clone());
                                continue;
                            }
                            contact_phase = match owner {
                                OutboundAttemptOwner::FixedEvaluation => ContactPhase::admitted(
                                    config.clone(),
                                    contacts.clone(),
                                    OrderedEventContactRole::Initiator,
                                    *opened,
                                ),
                                OutboundAttemptOwner::Coordinator(attempt) => {
                                    ContactPhase::admitted_coordinator(attempt, *opened)
                                }
                            };
                            continue;
                        }
                        ContactAttemptOutcome::CoordinatorCompleted => {
                            outbound_candidate_pending = false;
                            ContactAttemptOutcome::Cancelled
                        }
                        outcome => outcome,
                    };
                    admission.contact_closed(now);
                    scan_phase = idle_scan_phase();
                    let mut schedule = OutboundSchedule {
                        delay: &mut outbound_delay,
                        candidate_pending: &mut outbound_candidate_pending,
                        backoff: &mut contact_backoff,
                        self_schedule: !mode.is_automatic(),
                    };
                    if let Err(error) =
                        finish_contact_attempt(&config, &mut admission, outcome, now, &mut schedule)
                    {
                        break Err(error);
                    }
                    contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
                }
                EpochEvent::ScanDeadline => {
                    if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                        break Err(error);
                    }
                }
                EpochEvent::ScanIdleDeadline => {
                    let started_scan = match await_startup_platform(
                        expires_at,
                        config.open_timeout(),
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
                            break Err(owned_cleanup_unconfirmed(error));
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
    }

    let contact_termination = if matches!(result, Err(SupervisorError::Controller(_))) {
        EpochContactTermination::LocalEpochLoss
    } else {
        EpochContactTermination::Cancelled
    };
    if result.is_err()
        && let Err(error) = signals.publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
    {
        result = Err(error);
    }
    if result.is_err() && owner_loss_required {
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
            Some(mut advertisement) => release_advertisement(advertisement.as_mut()).await,
            None => Ok(()),
        }
    };
    let (contact_outcome, scan_stop, advertisement_release) =
        tokio::join!(contact_join, scan_cleanup, advertisement_cleanup);
    complete_interrupted_contact(contact_outcome, contact_termination);
    drop(listener);
    if scan_stop.is_err() || advertisement_release.is_err() {
        discovery.force_owner_loss();
        return Err(SupervisorError::PlatformCleanupUnconfirmed);
    }
    result?;
    Ok(())
}

struct OutboundSchedule<'a> {
    delay: &'a mut OutboundDelay,
    candidate_pending: &'a mut bool,
    backoff: &'a mut CappedBackoff,
    self_schedule: bool,
}

fn finish_contact_attempt(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    outcome: ContactAttemptOutcome,
    now: Instant,
    schedule: &mut OutboundSchedule<'_>,
) -> Result<(), SupervisorError> {
    match outcome {
        ContactAttemptOutcome::Opened { .. } => {
            unreachable!("opened contact is handled in the epoch")
        }
        ContactAttemptOutcome::CoordinatorCompleted => {
            unreachable!("coordinator completion is handled in the epoch")
        }
        ContactAttemptOutcome::OpenFailed(failure) => {
            let ContactOpenFailure {
                candidate,
                error,
                owner,
            } = *failure;
            if error.kind() == DriverErrorKind::Configuration {
                if let OutboundAttemptOwner::Coordinator(attempt) = owner {
                    attempt.cancel_carrier_open();
                }
                return Err(SupervisorError::Configuration);
            }
            if error.kind() == DriverErrorKind::Cancelled {
                if let OutboundAttemptOwner::Coordinator(attempt) = owner {
                    attempt.cancel_carrier_open();
                }
                return Ok(());
            }
            admission.invalidate_after_open_failure(candidate, now);
            match owner {
                OutboundAttemptOwner::FixedEvaluation => {
                    if schedule.self_schedule && config.role() == FixedRole::Initiator {
                        *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                        if *schedule.candidate_pending {
                            *schedule.delay =
                                OutboundDelay::PeerRetryUntil(now + schedule.backoff.next_delay());
                        }
                    }
                }
                OutboundAttemptOwner::Coordinator(attempt) => {
                    *schedule.candidate_pending = false;
                    let failure = if error.kind() == DriverErrorKind::Timeout {
                        aster_node::UnauthenticatedCarrierOpenFailure::TimedOut
                    } else {
                        aster_node::UnauthenticatedCarrierOpenFailure::Interrupted
                    };
                    attempt.fail_unauthenticated_carrier_open(failure);
                }
            }
        }
        ContactAttemptOutcome::Cancelled => {}
        ContactAttemptOutcome::Completed(result) => match *result {
            Ok(_receipt) => {
                if schedule.self_schedule && config.role() == FixedRole::Initiator {
                    schedule.backoff.reset();
                    *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                    *schedule.delay = OutboundDelay::CadenceUntil(now + config.contact_cadence());
                }
            }
            Err(outcome) if outcome.reason() == ContactReason::AdmissionClosed => {
                return Err(SupervisorError::AdmissionClosed);
            }
            Err(outcome) if outcome.reason() == ContactReason::ActorUnavailable => {
                return Err(SupervisorError::ActorUnavailable);
            }
            Err(outcome) if outcome.reason() == ContactReason::ActorStopped => {
                return Err(SupervisorError::ActorStopped);
            }
            Err(outcome) => finish_contact_disposition(
                config,
                admission,
                outcome.disposition(),
                outcome.reason(),
                now,
                schedule,
            )?,
        },
    }
    Ok(())
}

fn finish_contact_disposition(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    disposition: ContactDisposition,
    reason: ContactReason,
    now: Instant,
    schedule: &mut OutboundSchedule<'_>,
) -> Result<(), SupervisorError> {
    match contact_schedule_effect(disposition) {
        ContactScheduleEffect::RetryLater => {
            if schedule.self_schedule && config.role() == FixedRole::Initiator {
                *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                if *schedule.candidate_pending {
                    *schedule.delay =
                        OutboundDelay::PeerRetryUntil(now + schedule.backoff.next_delay());
                }
            }
            Ok(())
        }
        ContactScheduleEffect::Reselect => {
            if schedule.self_schedule && config.role() == FixedRole::Initiator {
                *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                *schedule.delay = OutboundDelay::Ready;
            }
            Ok(())
        }
        ContactScheduleEffect::Suppress => Err(SupervisorError::ContactSuppressed(reason)),
        ContactScheduleEffect::Cancelled => Ok(()),
        ContactScheduleEffect::Terminal => Err(SupervisorError::ContactTerminal(reason)),
    }
}

async fn begin_outbound_contact<S>(
    config: &Arc<ValidatedRosteredSupervisorConfig>,
    sockets: &Arc<S>,
    admission: &mut DiscoveryAdmission,
    scan_phase: &mut ScanPhase,
    candidate_pending: &mut bool,
    outbound_delay: &mut OutboundDelay,
    mode: &mut EpochContactMode,
) -> Result<Option<ContactPhase>, SupervisorError>
where
    S: RosteredSocketFactory + 'static,
{
    let now = lifecycle_now();
    if !mode.can_open_outbound(config)
        || now >= config.epoch_discovery_credentials().expires_at()
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
    let owner = mode.take_outbound();
    Ok(Some(ContactPhase::opening(
        config.clone(),
        sockets.clone(),
        candidate,
        owner,
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
) -> Result<(), SupervisorError> {
    let now = lifecycle_now();
    let idle = ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    };
    let ScanPhase::Active { mut scan, .. } = std::mem::replace(phase, idle) else {
        return Ok(());
    };
    let result = stop_scan(scan.owner.as_mut()).await;
    admission.stop_scan(now);
    result.map_err(owned_cleanup_unconfirmed)
}

fn owned_cleanup_unconfirmed(_: DriverError) -> SupervisorError {
    SupervisorError::PlatformCleanupUnconfirmed
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
    mode: &EpochContactMode,
) -> InboundContactAdmission {
    if admission.candidate(locator, now).is_none()
        || !mode.accepts_inbound(config)
        || now >= config.epoch_discovery_credentials().expires_at()
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

async fn run_coordinator_contact(
    attempt: Box<dyn CoordinatorAttempt>,
    opened: OpenedContact,
    cancellation: &LifecycleCancellation,
) -> ContactAttemptOutcome {
    let contact: Arc<dyn OrderedContact> = opened.into_contact();
    let mut completion = attempt.run(contact.clone());
    let outcome = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            contact.close();
            let _ = timeout(CONTACT_DRAIN_DEADLINE, &mut completion).await;
            ContactAttemptOutcome::Cancelled
        }
        () = &mut completion => {
            contact.close();
            ContactAttemptOutcome::CoordinatorCompleted
        }
    };
    drop(completion);
    drop(contact);
    outcome
}

async fn release_advertisement(
    owner: &mut dyn crate::platform::discovery::OwnedAdvertisement,
) -> Result<(), DriverError> {
    let terminated = owner.terminated();
    let release = owner.release();
    stop_with_barrier(
        release,
        terminated,
        "owned roster advertisement release timed out",
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
        config.epoch_discovery_credentials(),
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
        config.epoch_discovery_credentials(),
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AutomaticRosteredSupervisorConfig, ContactLimits, ControllerAdmissionPolicy,
        ControllerConfig, ControllerProbeLimits, DiscoveryCredential, DiscoveryGeneration,
        DiscoverySecret, LeasedDiscoveryCredentialSet, RING1_MAXIMUM_EXCHANGE_BYTES,
        RING1_MAXIMUM_FRAME_BYTES, RosteredAdapterConfig, RosteredDiscoveryConfig,
        RosteredSupervisorConfig, ValidatedControllerConfig, ValidatedRosteredSupervisorConfig,
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
        AutomaticEventTransportHandle, ContactOutcome, MissionPeerExpectation,
        OrderedEventContactRole, PeerReceipt,
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

    fn assert_legacy_automatic_spawn_signature(
        _spawn: fn(
            ValidatedRosteredSupervisorConfig,
            OrderedEventContactHandle,
            EventAdapterRegistration,
            crate::BtleOperatorOutput,
        )
            -> Result<LinuxRosteredBtleEventSupervisor, AutomaticBtleRegistrationError>,
    ) {
    }

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

    fn automatic_config() -> ValidatedAutomaticRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        AutomaticRosteredSupervisorConfig {
            controller_policy: ControllerAdmissionPolicy::default(),
            controller_probe_limits: ControllerProbeLimits::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(3),
            ),
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id: [0x11; 32],
            peer_mission_id: [0x22; 32],
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }
        .validate()
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
        fn release(&mut self) -> PlatformFuture<'_, ()> {
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
                stop_event: "advertisement-release",
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

    struct PendingBindSockets {
        started: Arc<Notify>,
    }

    struct ConnectingSockets {
        connected: Mutex<Vec<(crate::CanonicalLocator, u16)>>,
    }

    struct FailingConnectSockets {
        connected: Mutex<Vec<(crate::CanonicalLocator, u16)>>,
        kind: DriverErrorKind,
    }

    struct PendingConnectSockets {
        connected: Mutex<Vec<(crate::CanonicalLocator, u16)>>,
        started: Arc<Notify>,
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
        connected: AtomicU8,
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
                result
                    .map(|()| PeerReceipt::default())
                    .map_err(|_| ContactOutcome::admission_busy())
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
            self.connected.fetch_add(1, Ordering::AcqRel);
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

    impl RosteredSocketFactory for PendingBindSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            self.started.notify_one();
            Box::pin(pending())
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            unreachable!("listener bind never completes")
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            unreachable!("listener bind never completes")
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

    impl RosteredSocketFactory for FailingConnectSockets {
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
            let kind = self.kind;
            Box::pin(async move { Err(DriverError::new(kind, "test connect failure")) })
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    impl RosteredSocketFactory for PendingConnectSockets {
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
            self.started.notify_one();
            Box::pin(pending())
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

    struct FailingAdvertisementDiscovery;

    struct GatedScanDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        scan_entered: Arc<Notify>,
        allow_scan: Arc<Notify>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    struct PendingAdvertisementDiscovery {
        started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
    }

    struct PendingScanDiscovery {
        scan_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct OneScanThenPendingDiscovery {
        starts: AtomicU8,
        restart_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        events: Arc<Mutex<Vec<&'static str>>>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for PendingAdvertisementDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.started.notify_one();
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

    impl DiscoveryPlatform for PendingScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.scan_started.notify_one();
            Box::pin(pending())
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(1, Ordering::Release);
        }
    }

    impl DiscoveryPlatform for OneScanThenPendingDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            if self.starts.fetch_add(1, Ordering::AcqRel) > 0 {
                self.restart_started.notify_one();
                return Box::pin(pending());
            }
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(StartedScan::new(Box::new(owner), observations)) })
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
                stop_event: "advertisement-release",
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

    impl DiscoveryPlatform for FailingAdvertisementDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            Box::pin(async {
                Err(DriverError::new(
                    DriverErrorKind::Unavailable,
                    "test advertisement unavailable",
                ))
            })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            unreachable!("advertisement denial never starts scanning")
        }
    }

    impl DiscoveryPlatform for GatedScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            self.events.lock().unwrap().push("advertise");
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan-starting");
            self.scan_entered.notify_one();
            let allow_scan = self.allow_scan.clone();
            let events = self.events.clone();
            Box::pin(async move {
                allow_scan.notified().await;
                let (sender, observations) = mpsc::channel(1);
                *self.observation_sender.lock().unwrap() = Some(sender);
                Ok(StartedScan::new(
                    Box::new(FakeOwner {
                        stop_event: "scan-stop",
                        events,
                    }),
                    observations,
                ))
            })
        }
    }

    struct BlockingAdvertisementOwner {
        events: Arc<Mutex<Vec<&'static str>>>,
        release_completed: Option<Arc<Notify>>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for BlockingAdvertisementOwner {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.events
                    .lock()
                    .unwrap()
                    .push("advertisement-release-started");
                match &self.release_completed {
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
        advertisement_release_completed: Option<Arc<Notify>>,
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
                release_completed: self.advertisement_release_completed.clone(),
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

    struct RecordDrop(Arc<AtomicU8>);

    impl Drop for RecordDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
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
            output: crate::BtleOperatorOutput::discard(),
            failure_park: None,
            task: Some(task),
            abort_on_unconfirmed_cleanup: true,
        }
    }

    fn test_unavailable_publisher() -> UnavailableAvailabilityPublisher {
        let (updates, _availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        AdapterAvailabilityPublisher::fixed(updates, crate::BtleOperatorOutput::discard())
            .unavailable_only()
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

    #[tokio::test(start_paused = true)]
    async fn automatic_shutdown_is_bounded_without_claiming_or_aborting_cleanup() {
        let force_count = Arc::new(AtomicU8::new(0));
        let drop_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let guard = RecordDrop(drop_count.clone());
        let mut supervisor = test_supervisor(
            tokio::spawn(async move {
                let _guard = guard;
                pending::<Result<(), SupervisorError>>().await
            }),
            platform_owner,
        );
        supervisor.abort_on_unconfirmed_cleanup = false;
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER + OWNER_LOSS_JOIN_DEADLINE).await;
        assert_eq!(
            shutdown.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert_eq!(drop_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dropping_supervisor_cancels_and_retains_task_until_cleanup_finishes() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let cancellation_seen = Arc::new(AtomicU8::new(0));
        let task_cancellation_seen = cancellation_seen.clone();
        let release = Arc::new(Notify::new());
        let task_release = release.clone();
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let (_availability_updates, availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
        let (_completion_updates, completion) = watch::channel(false);
        let supervisor = LinuxRosteredBtleEventSupervisor {
            availability,
            completion,
            cancellation,
            platform_owner: Arc::new(PlatformOwner::default()),
            output: crate::BtleOperatorOutput::discard(),
            failure_park: None,
            task: Some(tokio::spawn(async move {
                let _secret_owner = secret_owner;
                task_cancellation.cancelled().await;
                task_cancellation_seen.store(1, Ordering::Release);
                task_release.notified().await;
                Ok(())
            })),
            abort_on_unconfirmed_cleanup: true,
        };
        tokio::task::yield_now().await;

        drop(supervisor);
        tokio::time::timeout(Duration::from_secs(1), async {
            while cancellation_seen.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop must synchronously signal supervisor cancellation");
        assert_eq!(secret_drops.load(Ordering::Acquire), 0);

        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while secret_drops.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup custody releases secrets only after task completion");
    }

    #[tokio::test]
    async fn operational_cleanup_error_forces_retained_owner_and_propagates() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let (_updates, status) = watch::channel(OperationalEpochState::Unavailable);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: LifecycleCancellation::new(),
            task: Some(tokio::spawn(async {
                OperationalEpochOutcome::Terminal(DriverError::new(
                    DriverErrorKind::Transport,
                    "test platform cleanup unconfirmed",
                ))
            })),
            platform_owner,
            unavailable: test_unavailable_publisher(),
        };

        assert!(matches!(
            Box::new(epoch).join().await,
            OperationalEpochOutcome::Terminal(_)
        ));
        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn operational_suppression_releases_retained_owner_without_forcing() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let (_updates, status) = watch::channel(OperationalEpochState::Unavailable);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: LifecycleCancellation::new(),
            task: Some(tokio::spawn(async { OperationalEpochOutcome::Suppressed })),
            platform_owner: platform_owner.clone(),
            unavailable: test_unavailable_publisher(),
        };

        assert!(matches!(
            Box::new(epoch).join().await,
            OperationalEpochOutcome::Suppressed
        ));
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(!platform_owner.force_loss());
    }

    #[tokio::test]
    async fn operational_epoch_containment_forces_owner_on_prompt_terminal_outcome() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let task = tokio::spawn(async {
            OperationalEpochOutcome::Terminal(DriverError::new(
                DriverErrorKind::Transport,
                "test terminal operational outcome",
            ))
        });

        contain_operational_epoch_task(task, platform_owner).await;

        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn operational_epoch_containment_forces_owner_on_prompt_join_error() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let task: JoinHandle<OperationalEpochOutcome> = tokio::spawn(async {
            panic!("test operational epoch panic");
        });

        contain_operational_epoch_task(task, platform_owner).await;

        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_operational_epoch_bounds_credential_config_custody() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let epoch_cancellation = LifecycleCancellation::new();
        let cancellation = epoch_cancellation.observer();
        let config = Arc::new(
            automatic_config()
                .for_controller(
                    "hci0".to_owned(),
                    Address::new([2, 0, 0, 0, 0, 1]),
                    AddressType::LeRandom,
                    1,
                    LifecycleCancellation::new().observer(),
                )
                .unwrap(),
        );
        let config_weak = Arc::downgrade(&config);
        let (availability_updates, availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        );
        let (_updates, status) = watch::channel(OperationalEpochState::Available);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: epoch_cancellation,
            task: Some(tokio::spawn(async move {
                let _config = config;
                pending::<OperationalEpochOutcome>().await
            })),
            platform_owner,
            unavailable: publisher.unavailable_only(),
        };
        tokio::task::yield_now().await;

        drop(epoch);
        tokio::task::yield_now().await;
        assert!(cancellation.is_cancelled());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(OWNER_LOSS_AFTER - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(OWNER_LOSS_JOIN_DEADLINE).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while config_weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abortable operational cleanup must release credential custody after the bound");
    }

    #[test]
    fn dropping_operational_epoch_without_an_entered_runtime_fails_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let cancellation = LifecycleCancellation::new();
        let cancellation_observer = cancellation.observer();
        let (availability_updates, availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        );
        let (_updates, status) = watch::channel(OperationalEpochState::Available);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation,
            task: Some(runtime.spawn(pending::<OperationalEpochOutcome>())),
            platform_owner,
            unavailable: publisher.unavailable_only(),
        };

        drop(epoch);

        assert!(cancellation_observer.is_cancelled());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        runtime.block_on(tokio::task::yield_now());
    }

    #[tokio::test]
    async fn spontaneous_resolver_failure_wakes_automatic_completion_without_shutdown() {
        let cancellation = LifecycleCancellation::new();
        let (status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (completion_updates, mut completion) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _completion = CompletionOnDrop(completion_updates);
            run_automatic_resolver_owner(
                status,
                cancellation,
                Instant::now() + Duration::from_secs(60),
                Arc::new(AvailabilityFence::default()),
                test_unavailable_publisher(),
                async {
                    Err(DriverError::new(
                        DriverErrorKind::Transport,
                        "test spontaneous resolver failure",
                    ))
                },
            )
            .await
        });

        drop(status_updates);
        completion.changed().await.unwrap();
        assert!(*completion.borrow_and_update());
        assert_eq!(
            task.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_expiry_publishes_unavailable_releases_config_and_parks() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (availability_updates, mut availability) =
            watch::channel(crate::BtleAvailability::Available);
        let unavailable = AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        )
        .unavailable_only();
        let config = Arc::new(automatic_config());
        let config_weak = Arc::downgrade(&config);
        let task = tokio::spawn(async move {
            run_automatic_resolver_owner(
                status,
                task_cancellation,
                Instant::now() + Duration::from_secs(5),
                Arc::new(AvailabilityFence::default()),
                unavailable,
                async move {
                    drop(config);
                    Ok(())
                },
            )
            .await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;
        availability.changed().await.unwrap();

        assert_eq!(
            *availability.borrow_and_update(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert!(
            config_weak.upgrade().is_none(),
            "expired automatic configuration must release credential custody"
        );
        assert!(
            !task.is_finished(),
            "expired supervisor remains nonterminal"
        );

        cancellation.cancel();
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_publication_rejection_still_completes_resolver_shutdown() {
        let cancellation = LifecycleCancellation::new();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: false,
        });
        let (availability_updates, _availability) =
            watch::channel(crate::BtleAvailability::Available);
        let unavailable = AdapterAvailabilityPublisher::automatic(
            control,
            availability_updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        )
        .unavailable_only();
        let shutdown_completed = Arc::new(AtomicU8::new(0));
        let task_shutdown_completed = shutdown_completed.clone();
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let task = tokio::spawn(run_automatic_resolver_owner(
            status,
            cancellation,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AvailabilityFence::default()),
            unavailable,
            async move {
                let _secret_owner = secret_owner;
                task_shutdown_completed.store(1, Ordering::Release);
                Ok(())
            },
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(task.await.unwrap(), Err(SupervisorError::TaskStopped));
        assert_eq!(shutdown_completed.load(Ordering::Acquire), 1);
        assert_eq!(secret_drops.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_bounds_hung_resolver_cleanup_and_releases_custody() {
        let cancellation = LifecycleCancellation::new();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let shutdown_started = Arc::new(AtomicU8::new(0));
        let task_shutdown_started = shutdown_started.clone();
        let task = tokio::spawn(run_automatic_resolver_owner(
            status,
            cancellation,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AvailabilityFence::default()),
            test_unavailable_publisher(),
            async move {
                let _secret_owner = secret_owner;
                task_shutdown_started.store(1, Ordering::Release);
                pending::<Result<(), DriverError>>().await
            },
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5) + Duration::from_millis(1)).await;
        while shutdown_started.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(OWNER_LOSS_AFTER + Duration::from_millis(1)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("expiry bounds resolver cleanup custody")
                .unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(secret_drops.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_fences_a_concurrent_late_available_publication() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (availability_updates, mut availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = Arc::new(AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        ));
        let expiry_fence = Arc::new(AvailabilityFence::default());
        let (operational, _operational_updates) = watch::channel(OperationalEpochState::Starting);
        let signals = EpochSignals::operational(
            publisher.clone(),
            operational,
            Arc::new(AvailabilityFence::default()),
            expiry_fence.clone(),
        );
        let (late_result_updates, late_result) = oneshot::channel();
        let task = tokio::spawn(run_automatic_resolver_owner(
            status,
            task_cancellation,
            Instant::now() + Duration::from_secs(5),
            expiry_fence,
            publisher.unavailable_only(),
            async move {
                let _ =
                    late_result_updates.send(signals.publish(crate::BtleAvailability::Available));
                Ok(())
            },
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            late_result.await.unwrap(),
            Err(SupervisorError::TaskStopped)
        );
        assert_eq!(
            *availability.borrow_and_update(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        cancellation.cancel();
        assert_eq!(task.await.unwrap(), Ok(()));
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
        let publisher =
            AdapterAvailabilityPublisher::fixed(updates, crate::BtleOperatorOutput::discard());
        let task = tokio::spawn(async move {
            park_expired_adapter(config, &publisher, &task_cancellation).await
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
                ContactOutcome::admission_closed(),
                SupervisorError::AdmissionClosed,
            ),
            (
                ContactOutcome::actor_unavailable(),
                SupervisorError::ActorUnavailable,
            ),
            (
                ContactOutcome::actor_stopped(),
                SupervisorError::ActorStopped,
            ),
        ];

        for (contact_error, expected) in cases {
            let now = Instant::now();
            let mut admission = DiscoveryAdmission::new();
            let mut outbound_delay = OutboundDelay::Ready;
            let mut outbound_candidate_pending = false;
            let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
            let mut schedule = OutboundSchedule {
                delay: &mut outbound_delay,
                candidate_pending: &mut outbound_candidate_pending,
                backoff: &mut backoff,
                self_schedule: true,
            };
            let error = finish_contact_attempt(
                &config(),
                &mut admission,
                ContactAttemptOutcome::Completed(Box::new(Err(contact_error))),
                now,
                &mut schedule,
            )
            .unwrap_err();

            assert_eq!(error, expected);
        }
    }

    #[test]
    fn rostered_contact_dispositions_drive_distinct_scheduler_effects() {
        let config = config();
        let now = Instant::now();
        let admission_with_candidate = || {
            let record = AsterRosterBeaconV1::encode(
                0x0081,
                [0x6d; 16],
                config.discovery_credentials(),
                now,
            )
            .unwrap();
            let locator = crate::CanonicalLocator::new(
                Address::new([2, 0, 0, 0, 0, 0x6d]),
                AddressType::LeRandom,
            )
            .unwrap();
            let observation =
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap();
            let mut admission = DiscoveryAdmission::new();
            assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);
            assert_eq!(
                admit_platform_observation(&mut admission, &config, observation, now),
                ObservationOutcome::Accepted
            );
            admission
        };

        let run = |disposition| {
            let mut admission = admission_with_candidate();
            let mut delay = OutboundDelay::Ready;
            let mut pending = false;
            let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
            let mut schedule = OutboundSchedule {
                delay: &mut delay,
                candidate_pending: &mut pending,
                backoff: &mut backoff,
                self_schedule: true,
            };
            let result = finish_contact_disposition(
                &config,
                &mut admission,
                disposition,
                ContactReason::ProtocolViolation,
                now,
                &mut schedule,
            );
            (result, pending, delay.deadline(now))
        };

        let (retry, retry_pending, retry_deadline) = run(ContactDisposition::RetryLater);
        assert_eq!(retry, Ok(()));
        assert!(retry_pending);
        assert!(retry_deadline > now);

        let (reselect, reselect_pending, reselect_deadline) = run(ContactDisposition::Reselect);
        assert_eq!(reselect, Ok(()));
        assert!(reselect_pending);
        assert_eq!(reselect_deadline, now);

        let (cancelled, cancelled_pending, cancelled_deadline) = run(ContactDisposition::Cancelled);
        assert_eq!(cancelled, Ok(()));
        assert!(!cancelled_pending);
        assert_eq!(cancelled_deadline, now);

        assert!(matches!(
            run(ContactDisposition::Suppress).0,
            Err(SupervisorError::ContactSuppressed(
                ContactReason::ProtocolViolation
            ))
        ));
        assert!(matches!(
            run(ContactDisposition::Terminal).0,
            Err(SupervisorError::ContactTerminal(
                ContactReason::ProtocolViolation
            ))
        ));
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
                "advertisement-release"
            ]
        );
    }

    #[tokio::test]
    async fn scan_start_failure_releases_the_local_advertisement_owner() {
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
            ["bind", "advertise", "scan-failed", "advertisement-release"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_platform_open() {
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.observer();
        let task = tokio::spawn(async move {
            await_startup_platform(
                Instant::now() + Duration::from_secs(60),
                Duration::from_secs(5),
                &observer,
                pending::<Result<(), DriverError>>(),
            )
            .await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_listener_bind() {
        let bind_started = Arc::new(Notify::new());
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(PendingBindSockets {
                started: bind_started.clone(),
            }),
            Arc::new(FakeDiscovery {
                events: Arc::new(Mutex::new(Vec::new())),
                advertisements: Arc::new(Mutex::new(Vec::new())),
                scan_started: Arc::new(Notify::new()),
                observation_sender: Mutex::new(None),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        bind_started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("local deadline ends a hung listener bind")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_advertisement() {
        let started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingAdvertisementDiscovery {
                started: started.clone(),
                owner_loss_forced: owner_loss_forced.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("local deadline ends hung advertisement startup")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_initial_scan() {
        let scan_started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingScanDiscovery {
                scan_started: scan_started.clone(),
                owner_loss_forced: owner_loss_forced.clone(),
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        scan_started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("local deadline ends hung initial scan")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_scan_restart() {
        let restart_started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let discovery = Arc::new(OneScanThenPendingDiscovery {
            starts: AtomicU8::new(0),
            restart_started: restart_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            events: Arc::new(Mutex::new(Vec::new())),
            observation_sender: Mutex::new(None),
        });
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            discovery.clone(),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(SCAN_ACTIVE_INTERVAL).await;
        tokio::task::yield_now().await;
        tokio::time::advance(SCAN_IDLE_INTERVAL).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), restart_started.notified())
                .await
                .is_ok(),
            "scan restart begins after active and idle windows: {:?}",
            discovery.events.lock().unwrap()
        );

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("local deadline ends a hung scan restart")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
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
                started: Arc::new(Notify::new()),
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
            connected: AtomicU8::new(0),
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
    async fn scan_owner_runs_ten_seconds_then_remains_idle_until_epoch_rotation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
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
                LifecycleCancellation::new(),
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

        tokio::time::advance(Duration::from_secs(14)).await;
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
        assert!(!task.is_finished());

        tokio::time::advance(Duration::from_secs(1)).await;
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
        assert!(task.is_finished(), "rotation must end the current epoch");

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
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
                "advertisement-release"
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
            advertisement_release_completed: None,
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
            advertisement_release_completed: None,
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

        assert_eq!(outcome, SupervisorError::PlatformCleanupUnconfirmed);
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_releases_the_local_advertisement_and_ends_the_epoch() {
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

        assert!(
            task.is_finished(),
            "rotation must leave replacement registration to a fresh epoch"
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-release"
            ]
        );
        {
            let records = advertisements.lock().unwrap();
            assert_eq!(records.len(), 1);
        }

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
        cancellation.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_rotation_release_forces_owner_loss_without_replacement() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: None,
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
                "advertisement-release-started"
            ]
        );

        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert!(task.is_finished(), "owner loss must release the epoch");
        assert_eq!(
            task.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
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
    async fn local_release_before_deadline_ends_epoch_without_forced_owner_loss() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let release_completed = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: Some(release_completed.clone()),
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
        tokio::time::advance(Duration::from_secs(4)).await;
        release_completed.notify_one();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "advertise")
                .count(),
            1
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 0);
        assert!(task.is_finished(), "local release must end the epoch");

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
    }

    struct TestCoordinatorAttempt {
        mission: [u8; 32],
        peer: [u8; 32],
        kind: aster_node::EventTransportKind,
        runs: Arc<AtomicU8>,
        carrier_failures: Arc<AtomicU8>,
        ambiguous_failures: Arc<AtomicU8>,
        cancellations: Arc<AtomicU8>,
        started: Option<Arc<Notify>>,
        release: Option<Arc<Notify>>,
        completed: Arc<AtomicU8>,
    }

    impl CoordinatorAttempt for TestCoordinatorAttempt {
        fn transport_kind(&self) -> aster_node::EventTransportKind {
            self.kind
        }

        fn mission(&self) -> [u8; 32] {
            self.mission
        }

        fn peer(&self) -> [u8; 32] {
            self.peer
        }

        fn run(self: Box<Self>, _contact: Arc<dyn OrderedContact>) -> CoordinatorAttemptFuture {
            Box::pin(async move {
                self.runs.fetch_add(1, Ordering::AcqRel);
                if let Some(started) = &self.started {
                    started.notify_one();
                }
                if let Some(release) = &self.release {
                    release.notified().await;
                }
                self.completed.store(1, Ordering::Release);
            })
        }

        fn fail_carrier_open(self: Box<Self>) {
            self.carrier_failures.fetch_add(1, Ordering::AcqRel);
        }

        fn fail_unauthenticated_carrier_open(
            self: Box<Self>,
            _failure: aster_node::UnauthenticatedCarrierOpenFailure,
        ) {
            self.ambiguous_failures.fetch_add(1, Ordering::AcqRel);
        }

        fn cancel_carrier_open(self: Box<Self>) {
            self.cancellations.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct TestCoordinatorAttemptSource {
        attempts: mpsc::Receiver<Box<dyn CoordinatorAttempt>>,
        received: Option<Arc<Notify>>,
    }

    impl CoordinatorAttemptSource for TestCoordinatorAttemptSource {
        fn recv(&mut self) -> CoordinatorAttemptReceiveFuture<'_> {
            Box::pin(async move {
                let attempt = self.attempts.recv().await;
                if attempt.is_some()
                    && let Some(received) = &self.received
                {
                    received.notify_one();
                }
                attempt
            })
        }
    }

    fn test_attempt(
        mission: [u8; 32],
        peer: [u8; 32],
        runs: Arc<AtomicU8>,
        carrier_failures: Arc<AtomicU8>,
        completed: Arc<AtomicU8>,
    ) -> Box<dyn CoordinatorAttempt> {
        Box::new(TestCoordinatorAttempt {
            mission,
            peer,
            kind: aster_node::EventTransportKind::BLE_L2CAP_V1,
            runs,
            carrier_failures,
            ambiguous_failures: Arc::new(AtomicU8::new(0)),
            cancellations: Arc::new(AtomicU8::new(0)),
            started: None,
            release: None,
            completed,
        })
    }

    #[derive(Default)]
    struct TestAttemptCounters {
        runs: Arc<AtomicU8>,
        carrier_failures: Arc<AtomicU8>,
        ambiguous_failures: Arc<AtomicU8>,
        cancellations: Arc<AtomicU8>,
        completed: Arc<AtomicU8>,
    }

    fn instrumented_attempt(
        mission: [u8; 32],
        peer: [u8; 32],
        counters: &TestAttemptCounters,
    ) -> Box<dyn CoordinatorAttempt> {
        Box::new(TestCoordinatorAttempt {
            mission,
            peer,
            kind: aster_node::EventTransportKind::BLE_L2CAP_V1,
            runs: counters.runs.clone(),
            carrier_failures: counters.carrier_failures.clone(),
            ambiguous_failures: counters.ambiguous_failures.clone(),
            cancellations: counters.cancellations.clone(),
            started: None,
            release: None,
            completed: counters.completed.clone(),
        })
    }

    fn coordinator_attempt_channel() -> (
        mpsc::Sender<Box<dyn CoordinatorAttempt>>,
        Box<dyn CoordinatorAttemptSource>,
    ) {
        let (sender, attempts) = mpsc::channel(1);
        (
            sender,
            Box::new(TestCoordinatorAttemptSource {
                attempts,
                received: None,
            }),
        )
    }

    async fn send_observation(
        discovery: &FakeDiscovery,
        config: &ValidatedRosteredSupervisorConfig,
        locator: crate::CanonicalLocator,
    ) {
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x73; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
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
    }

    async fn send_observation_to_barrier(
        discovery: &BarrierDiscovery,
        config: &ValidatedRosteredSupervisorConfig,
        locator: crate::CanonicalLocator,
    ) {
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x74; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
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
    }

    #[tokio::test]
    async fn automatic_inbound_listening_is_independently_bounded_without_a_ticket() {
        let config = config_with_ids([0x11; 32], [0x22; 32]);
        assert_eq!(config.role(), FixedRole::Initiator);
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x71]),
            AddressType::LeRandom,
        )
        .unwrap();
        let (accept_sender, accept_receiver) = oneshot::channel();
        let sockets = Arc::new(InboundSockets {
            accepted: tokio::sync::Mutex::new(Some(accept_receiver)),
            connected: AtomicU8::new(0),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let (_attempt_sender, attempts) = coordinator_attempt_channel();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config),
            sockets,
            discovery.clone(),
            Arc::new(FixedNonce([0x31; 16])),
            contacts.clone(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        let config = config_with_ids([0x11; 32], [0x22; 32]);
        send_observation(&discovery, &config, locator).await;
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
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Responder]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [[0x22; 32]]);
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn automatic_inbound_admission_exhausts_its_bound_without_a_ticket() {
        let config = config();
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x76]),
            AddressType::LeRandom,
        )
        .unwrap();
        let now = Instant::now();
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);
        let record =
            AsterRosterBeaconV1::encode(0x0083, [0x76; 16], config.discovery_credentials(), now)
                .unwrap();
        assert_eq!(
            admit_platform_observation(
                &mut admission,
                &config,
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
                now,
            ),
            ObservationOutcome::Accepted
        );
        let (_attempt_sender, attempts) = coordinator_attempt_channel();
        let mode = EpochContactMode::automatic(attempts);

        for _ in 0..4 {
            assert!(matches!(
                admit_inbound_contact(&config, &mut admission, locator, now, &mode),
                InboundContactAdmission::Admitted
            ));
        }
        assert!(matches!(
            admit_inbound_contact(&config, &mut admission, locator, now, &mode),
            InboundContactAdmission::BackoffUntil(_)
        ));
    }

    #[tokio::test]
    async fn automatic_outbound_open_requires_a_matching_coordinator_ticket() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x72]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x32; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &config(), locator).await;
        tokio::task::yield_now().await;
        assert!(sockets.connected.lock().unwrap().is_empty());

        let mismatched_runs = Arc::new(AtomicU8::new(0));
        attempt_sender
            .send(test_attempt(
                [0x11; 32],
                [0x44; 32],
                mismatched_runs.clone(),
                Arc::new(AtomicU8::new(0)),
                Arc::new(AtomicU8::new(0)),
            ))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(sockets.connected.lock().unwrap().is_empty());
        assert_eq!(mismatched_runs.load(Ordering::Acquire), 0);

        let matching_runs = Arc::new(AtomicU8::new(0));
        let completed = Arc::new(AtomicU8::new(0));
        attempt_sender
            .send(test_attempt(
                [0x11; 32],
                [0x22; 32],
                matching_runs.clone(),
                Arc::new(AtomicU8::new(0)),
                completed.clone(),
            ))
            .await
            .unwrap();
        for _ in 0..8 {
            if completed.load(Ordering::Acquire) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(*sockets.connected.lock().unwrap(), [(locator, 0x0083)]);
        assert_eq!(matching_runs.load(Ordering::Acquire), 1);
        assert_eq!(completed.load(Ordering::Acquire), 1);
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn roster_discovery_never_creates_outbound_peer_eligibility() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x73]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (_attempt_sender, attempts) = coordinator_attempt_channel();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &config(), locator).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert!(sockets.connected.lock().unwrap().is_empty());
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    struct RecordingEventAdapterControl {
        snapshots: Mutex<Vec<aster_node::EventAdapterSnapshot>>,
        accepts: bool,
    }

    #[test]
    fn legacy_automatic_supervisor_entry_retains_its_fixed_config_signature() {
        assert_legacy_automatic_spawn_signature(
            spawn_automatic_linux_rostered_btle_event_supervisor,
        );
    }

    #[test]
    fn authenticated_terminal_operational_result_remains_terminal() {
        let platform_owner = PlatformOwner::default();

        assert!(matches!(
            finish_operational_epoch_result(
                Err(SupervisorError::ContactTerminal(
                    ContactReason::ProtocolViolation,
                )),
                &platform_owner,
            ),
            OperationalEpochOutcome::Terminal(_)
        ));
        assert!(matches!(
            finish_operational_epoch_result(Err(SupervisorError::AdmissionClosed), &platform_owner),
            OperationalEpochOutcome::Terminal(_)
        ));
    }

    #[test]
    fn authenticated_suppression_is_a_distinct_operational_outcome() {
        let platform_owner = PlatformOwner::default();
        let force_count = Arc::new(AtomicU8::new(0));
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });

        assert!(matches!(
            finish_operational_epoch_result(
                Err(SupervisorError::ContactSuppressed(
                    ContactReason::PolicyRejected,
                )),
                &platform_owner,
            ),
            OperationalEpochOutcome::Suppressed
        ));
        assert!(!platform_owner.force_loss());
        assert_eq!(force_count.load(Ordering::Acquire), 0);
    }

    impl EventAvailabilityControl for RecordingEventAdapterControl {
        fn publish_availability(&self, snapshot: aster_node::EventAdapterSnapshot) -> bool {
            self.snapshots.lock().unwrap().push(snapshot);
            self.accepts
        }
    }

    struct BlockingFirstAvailabilityControl {
        snapshots: Mutex<Vec<EventAdapterSnapshot>>,
        entered: std::sync::mpsc::Sender<()>,
        release_first: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl EventAvailabilityControl for BlockingFirstAvailabilityControl {
        fn publish_availability(&self, snapshot: EventAdapterSnapshot) -> bool {
            let release = self.release_first.lock().unwrap().take();
            self.entered.send(()).unwrap();
            if let Some(release) = release {
                release.recv().unwrap();
            }
            let mut snapshots = self.snapshots.lock().unwrap();
            if snapshots
                .iter()
                .any(|current| current.availability_epoch() == snapshot.availability_epoch())
            {
                return false;
            }
            snapshots.push(snapshot);
            true
        }
    }

    #[test]
    fn expiry_waits_for_an_in_flight_available_transaction_before_publishing_unavailable() {
        let (entered_send, entered) = std::sync::mpsc::channel();
        let (release_send, release) = std::sync::mpsc::channel();
        let control = Arc::new(BlockingFirstAvailabilityControl {
            snapshots: Mutex::new(Vec::new()),
            entered: entered_send,
            release_first: Mutex::new(Some(release)),
        });
        let (updates, availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::ControllerUnpowered,
        ));
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            control.clone(),
            updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        ));
        let supervisor_fence = Arc::new(AvailabilityFence::default());
        let (operational, _operational_status) = watch::channel(OperationalEpochState::Starting);
        let signals = EpochSignals::operational(
            publisher.clone(),
            operational,
            Arc::new(AvailabilityFence::default()),
            supervisor_fence.clone(),
        );

        let available =
            std::thread::spawn(move || signals.publish(crate::BtleAvailability::Available));
        entered.recv().unwrap();
        assert!(matches!(
            supervisor_fence.0.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));

        let (expiry_started_send, expiry_started) = std::sync::mpsc::channel();
        let (expiry_finished_send, expiry_finished) = std::sync::mpsc::channel();
        let expiry_fence = supervisor_fence.clone();
        let unavailable = publisher.unavailable_only();
        let expiry = std::thread::spawn(move || {
            expiry_started_send.send(()).unwrap();
            expiry_fence.quiesce();
            expiry_finished_send.send(unavailable.publish()).unwrap();
        });
        expiry_started.recv().unwrap();
        assert!(matches!(
            expiry_finished.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(control.snapshots.lock().unwrap().is_empty());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::ControllerUnpowered)
        );

        release_send.send(()).unwrap();

        assert_eq!(available.join().unwrap(), Ok(()));
        expiry.join().unwrap();
        entered.recv().unwrap();
        assert_eq!(expiry_finished.recv().unwrap(), Ok(()));
        let snapshots = control.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots[0].availability_epoch(),
            crate::AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH + 1
        );
        assert_eq!(snapshots[0].state(), EventAdapterState::Available);
        assert_eq!(
            snapshots[1].availability_epoch(),
            crate::AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH + 2
        );
        assert_eq!(snapshots[1].state(), EventAdapterState::Unavailable);
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
    }

    #[test]
    fn automatic_registration_validation_rejects_unpaired_initial_state_and_unregisters() {
        let cases = [
            (
                EventAdapterSnapshot::new(
                    EventTransportKind::IROH_QUIC_V1,
                    0,
                    EventAdapterState::Unavailable,
                    true,
                    7,
                ),
                AutomaticBtleRegistrationError::WrongTransport,
            ),
            (
                EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    1,
                    EventAdapterState::Unavailable,
                    true,
                    7,
                ),
                AutomaticBtleRegistrationError::InitialEpoch,
            ),
            (
                EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    0,
                    EventAdapterState::Available,
                    true,
                    7,
                ),
                AutomaticBtleRegistrationError::InitialState,
            ),
            (
                EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    0,
                    EventAdapterState::Unavailable,
                    false,
                    7,
                ),
                AutomaticBtleRegistrationError::NotEventCapable,
            ),
        ];

        for (snapshot, expected) in cases {
            let handle = AutomaticEventTransportHandle::new();
            let registration = handle.register_paired(snapshot).unwrap();

            assert_eq!(
                validate_automatic_registration(registration).err(),
                Some(expected)
            );
            assert!(
                handle.register_paired(snapshot).is_some(),
                "rejected registration must release its lease"
            );
        }
    }

    #[test]
    fn controller_loss_publishes_a_new_unavailable_adapter_epoch() {
        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: true,
        });
        let output = crate::BtleOperatorOutput::discard();
        let (updates, _availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        let publisher = AdapterAvailabilityPublisher::automatic(
            control.clone(),
            updates,
            output,
            FixedRole::Initiator,
        );

        publisher
            .publish(crate::BtleAvailability::Available)
            .unwrap();
        publisher
            .publish(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::ControllerAbsent,
            ))
            .unwrap();

        let snapshots = control.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].availability_epoch(), 1);
        assert_eq!(
            snapshots[0].state(),
            aster_node::EventAdapterState::Available
        );
        assert_eq!(snapshots[1].availability_epoch(), 2);
        assert_eq!(
            snapshots[1].state(),
            aster_node::EventAdapterState::Unavailable
        );
    }

    #[test]
    fn rejected_or_exhausted_availability_epoch_fails_closed_without_divergence() {
        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: false,
        });
        let output = crate::BtleOperatorOutput::discard();
        let (updates, availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        let publisher =
            AdapterAvailabilityPublisher::automatic(control, updates, output, FixedRole::Initiator);

        assert_eq!(
            publisher.publish(crate::BtleAvailability::Available),
            Err(AvailabilityPublishError::RegistrationRejected)
        );
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );

        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: true,
        });
        let (updates, availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        let publisher = AdapterAvailabilityPublisher {
            publication: Arc::new(AvailabilityPublication {
                control: Some(control.clone()),
                updates,
                output: crate::BtleOperatorOutput::discard(),
                epoch: Mutex::new(u64::MAX),
            }),
            selector_can_originate: true,
        };

        assert_eq!(
            publisher.publish(crate::BtleAvailability::Available),
            Err(AvailabilityPublishError::EpochExhausted)
        );
        assert!(control.snapshots.lock().unwrap().is_empty());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
    }

    mod automatic_controller {
        use super::*;

        struct OrderedAvailabilityControl {
            events: Arc<Mutex<Vec<&'static str>>>,
        }

        impl EventAvailabilityControl for OrderedAvailabilityControl {
            fn publish_availability(&self, snapshot: EventAdapterSnapshot) -> bool {
                self.events.lock().unwrap().push(match snapshot.state() {
                    EventAdapterState::Available => "available",
                    EventAdapterState::Unavailable => "unavailable",
                });
                true
            }
        }

        struct OrderedOwnerLoss {
            events: Arc<Mutex<Vec<&'static str>>>,
        }

        impl PlatformOwnerLoss for OrderedOwnerLoss {
            fn force(&self) {
                self.events.lock().unwrap().push("force");
            }
        }

        #[tokio::test]
        async fn operational_panic_publishes_unavailable_before_forcing_owner_loss() {
            let events = Arc::new(Mutex::new(Vec::new()));
            let control = Arc::new(OrderedAvailabilityControl {
                events: events.clone(),
            });
            let (updates, availability) = watch::channel(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ));
            let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
                control,
                updates,
                crate::BtleOperatorOutput::discard(),
                FixedRole::Initiator,
            ));
            publisher
                .publish(crate::BtleAvailability::Available)
                .unwrap();
            let platform_owner = Arc::new(PlatformOwner::default());
            platform_owner.replace(OrderedOwnerLoss {
                events: events.clone(),
            });
            let (_updates, status) = watch::channel(OperationalEpochState::Available);
            let (quiesce, _requests) = mpsc::channel(1);
            let epoch = RosteredOperationalEpoch {
                status,
                quiesce,
                availability_fence: Arc::new(AvailabilityFence::default()),
                cancellation: LifecycleCancellation::new(),
                task: Some(tokio::spawn(async { panic!("test operational panic") })),
                platform_owner,
                unavailable: publisher.unavailable_only(),
            };

            assert!(matches!(
                Box::new(epoch).join().await,
                OperationalEpochOutcome::Terminal(_)
            ));
            assert_eq!(
                *availability.borrow(),
                crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable,)
            );
            assert_eq!(
                *events.lock().unwrap(),
                ["available", "unavailable", "force"]
            );
        }

        #[tokio::test(start_paused = true)]
        async fn operational_wrapper_retains_force_loss_after_owned_cleanup_timeout() {
            let discovery = Arc::new(BarrierDiscovery {
                events: Arc::new(Mutex::new(Vec::new())),
                advertisement_release_completed: None,
                advertisement_terminated: Arc::new(Notify::new()),
                scan_started: Arc::new(Notify::new()),
                owner_loss_forced: Arc::new(AtomicU8::new(0)),
                observation_sender: Mutex::new(None),
            });
            let (control, publisher, availability, available_started) = publisher();
            let force_count = Arc::new(AtomicU8::new(0));
            let platform_owner = Arc::new(PlatformOwner::default());
            platform_owner.replace(RecordingOwnerLoss {
                force_count: force_count.clone(),
                release: None,
            });
            let cancellation = LifecycleCancellation::new();
            let task_cancellation = cancellation.clone();
            let task_owner = platform_owner.clone();
            let task_publisher = publisher.clone();
            let task_discovery = discovery.clone();
            let (_attempt_sender, attempts) = coordinator_attempt_channel();
            let task = tokio::spawn(async move {
                let result = run_automatic_available_epoch(
                    Arc::new(config()),
                    Arc::new(FakeSockets {
                        events: Arc::new(Mutex::new(Vec::new())),
                    }),
                    task_discovery,
                    Arc::new(FixedNonce([0x5d; 16])),
                    recording_admission(),
                    attempts,
                    EpochSignals::with_publisher(task_publisher, available_started),
                    task_cancellation,
                )
                .await;
                finish_operational_epoch_result(result, task_owner.as_ref())
            });
            let (_updates, status) = watch::channel(OperationalEpochState::Available);
            let (quiesce, _requests) = mpsc::channel(1);
            let epoch = RosteredOperationalEpoch {
                status,
                quiesce,
                availability_fence: Arc::new(AvailabilityFence::default()),
                cancellation: cancellation.clone(),
                task: Some(task),
                platform_owner,
                unavailable: publisher.unavailable_only(),
            };

            discovery.scan_started.notified().await;
            cancellation.cancel();
            tokio::task::yield_now().await;
            tokio::time::advance(OWNED_STOP_DEADLINE + Duration::from_millis(1)).await;

            assert!(matches!(
                Box::new(epoch).join().await,
                OperationalEpochOutcome::Terminal(_)
            ));
            assert_eq!(force_count.load(Ordering::Acquire), 1);
            assert_eq!(
                *availability.borrow(),
                crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable,)
            );
            assert_eq!(
                control
                    .snapshots
                    .lock()
                    .unwrap()
                    .iter()
                    .map(EventAdapterSnapshot::state)
                    .collect::<Vec<_>>(),
                [EventAdapterState::Available, EventAdapterState::Unavailable]
            );
        }

        fn publisher() -> (
            Arc<RecordingEventAdapterControl>,
            Arc<AdapterAvailabilityPublisher>,
            watch::Receiver<crate::BtleAvailability>,
            oneshot::Sender<Instant>,
        ) {
            let control = Arc::new(RecordingEventAdapterControl {
                snapshots: Mutex::new(Vec::new()),
                accepts: true,
            });
            let (updates, availability) = watch::channel(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ));
            let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
                control.clone(),
                updates,
                crate::BtleOperatorOutput::discard(),
                FixedRole::Initiator,
            ));
            let (available_started, _available_started_at) = oneshot::channel();
            (control, publisher, availability, available_started)
        }

        async fn assert_startup_denial_stays_unavailable<D>(discovery: Arc<D>)
        where
            D: DiscoveryPlatform,
        {
            let (control, publisher, availability, available_started) = publisher();
            let result = run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: Arc::new(Mutex::new(Vec::new())),
                }),
                discovery,
                Arc::new(FixedNonce([0x52; 16])),
                recording_admission(),
                EpochSignals::with_publisher(publisher, available_started),
                LifecycleCancellation::new(),
            )
            .await;

            assert_eq!(
                result,
                Err(SupervisorError::Controller(DriverErrorKind::Unavailable))
            );
            assert!(control.snapshots.lock().unwrap().is_empty());
            assert_eq!(
                *availability.borrow(),
                crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
            );
        }

        #[tokio::test]
        async fn probe_pass_stays_unavailable_until_required_owners_start() {
            let events = Arc::new(Mutex::new(Vec::new()));
            let scan_entered = Arc::new(Notify::new());
            let allow_scan = Arc::new(Notify::new());
            let discovery = Arc::new(GatedScanDiscovery {
                events,
                scan_entered: scan_entered.clone(),
                allow_scan: allow_scan.clone(),
                observation_sender: Mutex::new(None),
            });
            let (control, publisher, mut availability, available_started) = publisher();
            let cancellation = LifecycleCancellation::new();
            let task = tokio::spawn(run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: Arc::new(Mutex::new(Vec::new())),
                }),
                discovery,
                Arc::new(FixedNonce([0x51; 16])),
                recording_admission(),
                EpochSignals::with_publisher(publisher, available_started),
                cancellation.clone(),
            ));

            scan_entered.notified().await;
            assert!(control.snapshots.lock().unwrap().is_empty());
            assert_eq!(
                *availability.borrow(),
                crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
            );

            allow_scan.notify_one();
            availability.changed().await.unwrap();
            assert_eq!(*availability.borrow(), crate::BtleAvailability::Available);
            cancellation.cancel();
            task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn scan_denial_stays_unavailable() {
            let events = Arc::new(Mutex::new(Vec::new()));
            assert_startup_denial_stays_unavailable(Arc::new(FailingScanDiscovery { events }))
                .await;
        }

        #[tokio::test]
        async fn advertisement_denial_stays_unavailable() {
            assert_startup_denial_stays_unavailable(Arc::new(FailingAdvertisementDiscovery)).await;
        }

        #[tokio::test]
        async fn acknowledged_quiesce_fences_available_after_startup_resolves() {
            let (control, publisher, availability, _available_started) = publisher();
            let (updates, status) = watch::channel(OperationalEpochState::Starting);
            let fence = Arc::new(AvailabilityFence::default());
            let signals = EpochSignals::operational(
                publisher.clone(),
                updates.clone(),
                fence.clone(),
                Arc::new(AvailabilityFence::default()),
            );
            let cancellation = LifecycleCancellation::new();
            let task_cancellation = cancellation.clone();
            let (quiesce, mut requests) = mpsc::channel(1);
            let task_publisher = publisher.clone();
            let task_updates = updates.clone();
            let task = tokio::spawn(async move {
                let Some(acknowledged) = requests.recv().await else {
                    return OperationalEpochOutcome::Retryable;
                };
                acknowledge_operational_quiesce(&task_publisher, &task_updates, acknowledged);
                task_cancellation.cancel();
                OperationalEpochOutcome::Retryable
            });
            let mut epoch = RosteredOperationalEpoch {
                status,
                quiesce,
                availability_fence: fence,
                cancellation,
                task: Some(task),
                platform_owner: Arc::new(PlatformOwner::default()),
                unavailable: publisher.unavailable_only(),
            };

            epoch.quiesce().await.unwrap();
            assert_eq!(
                signals.publish(crate::BtleAvailability::Available),
                Err(SupervisorError::TaskStopped)
            );
            assert!(control.snapshots.lock().unwrap().is_empty());
            assert_eq!(*epoch.status.borrow(), OperationalEpochState::Unavailable);
            assert_eq!(
                *availability.borrow(),
                crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
            );
            epoch.cancel();
            assert!(matches!(
                Box::new(epoch).join().await,
                OperationalEpochOutcome::Retryable
            ));
        }

        #[tokio::test]
        async fn operational_event_path_publishes_available_once() {
            let discovery = Arc::new(FakeDiscovery {
                events: Arc::new(Mutex::new(Vec::new())),
                advertisements: Arc::new(Mutex::new(Vec::new())),
                scan_started: Arc::new(Notify::new()),
                observation_sender: Mutex::new(None),
            });
            let (control, publisher, mut availability, available_started) = publisher();
            let cancellation = LifecycleCancellation::new();
            let task = tokio::spawn(run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: Arc::new(Mutex::new(Vec::new())),
                }),
                discovery.clone(),
                Arc::new(FixedNonce([0x53; 16])),
                recording_admission(),
                EpochSignals::with_publisher(publisher, available_started),
                cancellation.clone(),
            ));

            discovery.scan_started.notified().await;
            availability.changed().await.unwrap();
            assert_eq!(*availability.borrow(), crate::BtleAvailability::Available);
            assert_eq!(
                control
                    .snapshots
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|snapshot| snapshot.state() == EventAdapterState::Available)
                    .count(),
                1
            );
            cancellation.cancel();
            task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn selected_loss_publishes_unavailable_before_child_drain() {
            let events = Arc::new(Mutex::new(Vec::new()));
            let advertisement_terminated = Arc::new(Notify::new());
            let discovery = Arc::new(BarrierDiscovery {
                events: events.clone(),
                advertisement_release_completed: None,
                advertisement_terminated: advertisement_terminated.clone(),
                scan_started: Arc::new(Notify::new()),
                owner_loss_forced: Arc::new(AtomicU8::new(0)),
                observation_sender: Mutex::new(None),
            });
            let (updates, mut availability) = watch::channel(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ));
            let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
                Arc::new(OrderedAvailabilityControl {
                    events: events.clone(),
                }),
                updates,
                crate::BtleOperatorOutput::discard(),
                FixedRole::Initiator,
            ));
            let (available_started, _available_started_at) = oneshot::channel();
            let task = tokio::spawn(run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: Arc::new(Mutex::new(Vec::new())),
                }),
                discovery.clone(),
                Arc::new(FixedNonce([0x54; 16])),
                recording_admission(),
                EpochSignals::with_publisher(publisher, available_started),
                LifecycleCancellation::new(),
            ));

            discovery.scan_started.notified().await;
            availability.changed().await.unwrap();
            advertisement_terminated.notify_one();
            let result = task.await.unwrap();
            let events = events.lock().unwrap();
            let unavailable = events
                .iter()
                .position(|event| *event == "unavailable")
                .unwrap();
            let child_drain = events
                .iter()
                .position(|event| *event == "scan-stop")
                .unwrap_or_else(|| panic!("missing child drain event: {events:?}"));
            assert!(unavailable < child_drain);
            drop(events);

            assert_eq!(
                result,
                Err(SupervisorError::Controller(DriverErrorKind::Transport))
            );
        }

        #[test]
        fn unrelated_adapter_addition_does_not_flap_availability() {
            let (control, publisher, _availability, _available_started) = publisher();

            publisher
                .publish(crate::BtleAvailability::Available)
                .unwrap();
            publisher
                .publish(crate::BtleAvailability::Available)
                .unwrap();

            assert_eq!(control.snapshots.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn remote_pre_auth_ticket_completion_never_self_selects_an_alternate() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x74]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let runs = Arc::new(AtomicU8::new(0));
        let completed = Arc::new(AtomicU8::new(0));
        attempt_sender
            .send(test_attempt(
                [0x11; 32],
                [0x22; 32],
                runs.clone(),
                Arc::new(AtomicU8::new(0)),
                completed.clone(),
            ))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x34; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &config(), locator).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        // Remote pre-auth classification belongs to the coordinator-owned
        // runner. The adapter observes only terminal ticket completion and
        // must not turn that completion into another carrier open.
        assert_eq!(runs.load(Ordering::Acquire), 1);
        assert_eq!(completed.load(Ordering::Acquire), 1);
        assert_eq!(sockets.connected.lock().unwrap().len(), 1);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(sockets.connected.lock().unwrap().len(), 1);
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn remote_socket_open_error_completes_ticket_without_alternate_selection() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x77]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(FailingConnectSockets {
            connected: Mutex::new(Vec::new()),
            kind: DriverErrorKind::Transport,
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let counters = TestAttemptCounters::default();
        attempt_sender
            .send(instrumented_attempt([0x11; 32], [0x22; 32], &counters))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x37; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &config(), locator).await;
        for _ in 0..8 {
            if counters.ambiguous_failures.load(Ordering::Acquire) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(*sockets.connected.lock().unwrap(), [(locator, 0x0083)]);
        assert_eq!(counters.ambiguous_failures.load(Ordering::Acquire), 1);
        assert_eq!(counters.carrier_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.cancellations.load(Ordering::Acquire), 0);
        assert_eq!(counters.runs.load(Ordering::Acquire), 0);
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn automatic_listener_is_locally_available_but_selector_stays_unavailable() {
        let listener_config = Arc::new(config_with_ids([0x22; 32], [0x11; 32]));
        assert_eq!(listener_config.role(), FixedRole::Listener);
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x7a]),
            AddressType::LeRandom,
        )
        .unwrap();
        let (accept_sender, accept_receiver) = oneshot::channel();
        let sockets = Arc::new(InboundSockets {
            accepted: tokio::sync::Mutex::new(Some(accept_receiver)),
            connected: AtomicU8::new(0),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: true,
        });
        let (updates, mut local_availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            control.clone(),
            updates,
            crate::BtleOperatorOutput::discard(),
            listener_config.role(),
        ));
        let (_attempt_sender, attempts) = coordinator_attempt_channel();
        let cancellation = LifecycleCancellation::new();
        let (available_started, _available_started_at) = oneshot::channel();
        let task = tokio::spawn(run_automatic_available_epoch(
            listener_config.clone(),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x3a; 16])),
            contacts.clone(),
            attempts,
            EpochSignals::with_publisher(publisher, available_started),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        local_availability.changed().await.unwrap();
        assert_eq!(
            *local_availability.borrow_and_update(),
            crate::BtleAvailability::Available
        );
        send_observation(&discovery, &listener_config, locator).await;
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

        assert_eq!(sockets.connected.load(Ordering::Acquire), 0);
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Responder]
        );
        assert!(
            control
                .snapshots
                .lock()
                .unwrap()
                .iter()
                .all(|snapshot| snapshot.state() == EventAdapterState::Unavailable)
        );

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn listener_rejects_matching_outbound_ticket_without_opening_or_spinning() {
        let listener_config = Arc::new(config_with_ids([0x22; 32], [0x11; 32]));
        assert_eq!(listener_config.role(), FixedRole::Listener);
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x78]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let counters = TestAttemptCounters::default();
        attempt_sender
            .send(instrumented_attempt([0x22; 32], [0x11; 32], &counters))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            listener_config.clone(),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x38; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &listener_config, locator).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert!(sockets.connected.lock().unwrap().is_empty());
        assert_eq!(counters.carrier_failures.load(Ordering::Acquire), 1);
        assert_eq!(counters.ambiguous_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.runs.load(Ordering::Acquire), 0);
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn controller_loss_mid_open_completes_ticket_as_local_carrier_loss() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x79]),
            AddressType::LeRandom,
        )
        .unwrap();
        let connect_started = Arc::new(Notify::new());
        let sockets = Arc::new(PendingConnectSockets {
            connected: Mutex::new(Vec::new()),
            started: connect_started.clone(),
        });
        let advertisement_release_completed = Arc::new(Notify::new());
        let advertisement_terminated = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisement_release_completed: Some(advertisement_release_completed.clone()),
            advertisement_terminated: advertisement_terminated.clone(),
            scan_started: Arc::new(Notify::new()),
            owner_loss_forced: Arc::new(AtomicU8::new(0)),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let counters = TestAttemptCounters::default();
        attempt_sender
            .send(instrumented_attempt([0x11; 32], [0x22; 32], &counters))
            .await
            .unwrap();
        let control = Arc::new(RecordingEventAdapterControl {
            snapshots: Mutex::new(Vec::new()),
            accepts: true,
        });
        let (updates, _availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            control.clone(),
            updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        ));
        let (available_started, _available) = oneshot::channel();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets,
            discovery.clone(),
            Arc::new(FixedNonce([0x39; 16])),
            recording_admission(),
            attempts,
            EpochSignals::with_publisher(publisher, available_started),
            LifecycleCancellation::new(),
        ));

        discovery.scan_started.notified().await;
        send_observation_to_barrier(&discovery, &config(), locator).await;
        connect_started.notified().await;
        advertisement_terminated.notify_one();
        advertisement_release_completed.notify_one();

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
        assert_eq!(counters.carrier_failures.load(Ordering::Acquire), 1);
        assert_eq!(counters.ambiguous_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.cancellations.load(Ordering::Acquire), 0);
        let snapshots = control.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].availability_epoch(), 1);
        assert_eq!(snapshots[0].state(), EventAdapterState::Available);
        assert_eq!(snapshots[1].availability_epoch(), 2);
        assert_eq!(snapshots[1].state(), EventAdapterState::Unavailable);
    }

    #[tokio::test(start_paused = true)]
    async fn owned_cleanup_timeout_overrides_cancellation_as_unconfirmed() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x7a]),
            AddressType::LeRandom,
        )
        .unwrap();
        let connect_started = Arc::new(Notify::new());
        let sockets = Arc::new(PendingConnectSockets {
            connected: Mutex::new(Vec::new()),
            started: connect_started.clone(),
        });
        let discovery = Arc::new(BarrierDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisement_release_completed: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: Arc::new(Notify::new()),
            owner_loss_forced: Arc::new(AtomicU8::new(0)),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let counters = TestAttemptCounters::default();
        attempt_sender
            .send(instrumented_attempt([0x11; 32], [0x22; 32], &counters))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets,
            discovery.clone(),
            Arc::new(FixedNonce([0x3a; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation_to_barrier(&discovery, &config(), locator).await;
        connect_started.notified().await;
        cancellation.cancel();
        tokio::task::yield_now().await;
        tokio::time::advance(OWNED_STOP_DEADLINE + Duration::from_millis(1)).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
        assert_eq!(counters.cancellations.load(Ordering::Acquire), 1);
        assert_eq!(counters.carrier_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.ambiguous_failures.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_ticket_cancellation_survives_cleanup_failure() {
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(BarrierDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisement_release_completed: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: Arc::new(Notify::new()),
            owner_loss_forced: Arc::new(AtomicU8::new(0)),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = mpsc::channel(1);
        let received = Arc::new(Notify::new());
        let counters = TestAttemptCounters::default();
        attempt_sender
            .send(instrumented_attempt([0x11; 32], [0x22; 32], &counters))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn({
            let sockets = sockets.clone();
            let discovery = discovery.clone();
            let received = received.clone();
            async move {
                let mut mode =
                    EpochContactMode::automatic(Box::new(TestCoordinatorAttemptSource {
                        attempts,
                        received: Some(received),
                    }));
                let result = run_available_epoch_with_mode(
                    Arc::new(config()),
                    sockets,
                    discovery,
                    Arc::new(FixedNonce([0x3b; 16])),
                    recording_admission(),
                    &mut mode,
                    EpochSignals::default(),
                    task_cancellation.observer(),
                )
                .await;
                complete_pending_after_epoch(&mut mode, &task_cancellation.observer(), &result);
                result
            }
        });

        discovery.scan_started.notified().await;
        received.notified().await;
        cancellation.cancel();
        tokio::task::yield_now().await;
        tokio::time::advance(OWNED_STOP_DEADLINE + Duration::from_millis(1)).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
        assert_eq!(counters.cancellations.load(Ordering::Acquire), 1);
        assert_eq!(counters.carrier_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.ambiguous_failures.load(Ordering::Acquire), 0);
        assert_eq!(counters.runs.load(Ordering::Acquire), 0);
        assert!(sockets.connected.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn automatic_cancellation_joins_ticket_scan_and_advertisement_work() {
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x75]),
            AddressType::LeRandom,
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (attempt_sender, attempts) = coordinator_attempt_channel();
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let completed = Arc::new(AtomicU8::new(0));
        attempt_sender
            .send(Box::new(TestCoordinatorAttempt {
                mission: [0x11; 32],
                peer: [0x22; 32],
                kind: aster_node::EventTransportKind::BLE_L2CAP_V1,
                runs: Arc::new(AtomicU8::new(0)),
                carrier_failures: Arc::new(AtomicU8::new(0)),
                ambiguous_failures: Arc::new(AtomicU8::new(0)),
                cancellations: Arc::new(AtomicU8::new(0)),
                started: Some(started.clone()),
                release: Some(release.clone()),
                completed: completed.clone(),
            }))
            .await
            .unwrap();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            Arc::new(config()),
            sockets,
            discovery.clone(),
            Arc::new(FixedNonce([0x35; 16])),
            recording_admission(),
            attempts,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_observation(&discovery, &config(), locator).await;
        started.notified().await;
        cancellation.cancel();
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "shutdown must join the owned ticket");
        release.notify_one();
        task.await.unwrap().unwrap();

        assert_eq!(completed.load(Ordering::Acquire), 1);
        assert!(events.lock().unwrap().contains(&"scan-stop"));
        assert!(events.lock().unwrap().contains(&"advertisement-release"));
    }
}
