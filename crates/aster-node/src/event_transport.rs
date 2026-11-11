//! Closed outcomes shared by Event transport admission and selection.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::SystemTime,
};

use aster_contact::OrderedContact;
use aster_mesh::NodeId;
use tokio::sync::{mpsc, watch};

/// Maximum distinct peer cohorts retained by the in-memory wake mailbox.
pub const MAX_PENDING_EVENT_COHORTS: usize = 64;
/// Maximum exact-peer eligibility entries retained by the selector.
pub const MAX_EVENT_PEER_ELIGIBILITY: usize = 256;

/// Stable in-process identity for an admitted Event transport adapter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventTransportKind(u16);

impl EventTransportKind {
    /// Iroh QUIC adapter using the existing ordered-contact contract.
    pub const IROH_QUIC_V1: Self = Self(1);
    /// Bluetooth LE L2CAP CoC adapter using the existing ordered-contact contract.
    pub const BLE_L2CAP_V1: Self = Self(2);

    /// Returns the stable local kind identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Sanitized availability reported by one adapter-owned lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAdapterState {
    /// The adapter cannot originate a contact in this epoch.
    Unavailable,
    /// The adapter can originate an Event contact in this epoch.
    Available,
}

/// Bounded adapter-owned input to local Event selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventAdapterSnapshot {
    kind: EventTransportKind,
    availability_epoch: u64,
    state: EventAdapterState,
    event_capable: bool,
    configured_priority: u16,
}

impl EventAdapterSnapshot {
    /// Creates one sanitized snapshot without locator or mission authority.
    pub const fn new(
        kind: EventTransportKind,
        availability_epoch: u64,
        state: EventAdapterState,
        event_capable: bool,
        configured_priority: u16,
    ) -> Self {
        Self {
            kind,
            availability_epoch,
            state,
            event_capable,
            configured_priority,
        }
    }

    /// Returns the stable adapter kind.
    pub const fn kind(&self) -> EventTransportKind {
        self.kind
    }

    /// Returns the adapter-owned lifecycle epoch.
    pub const fn availability_epoch(&self) -> u64 {
        self.availability_epoch
    }

    /// Returns the sanitized availability state.
    pub const fn state(&self) -> EventAdapterState {
        self.state
    }

    /// Returns whether this adapter is qualified for Event contacts.
    pub const fn event_capable(&self) -> bool {
        self.event_capable
    }

    /// Returns the local configured ranking priority; larger values rank first.
    pub const fn configured_priority(&self) -> u16 {
        self.configured_priority
    }
}

/// Exact authority that established one peer-indexed eligibility entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerEligibilitySource {
    /// Local provisioning named the exact mission peer.
    ProvisionedExactPeer,
    /// A prior complete mission transcript authenticated the exact peer.
    MissionAuthenticated,
}

/// Host-owned authority permitting one adapter kind for one exact mission peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPeerEligibility {
    mission: NodeId,
    peer: NodeId,
    kind: EventTransportKind,
    event_capable: bool,
    source: EventPeerEligibilitySource,
    authority_generation: u64,
    revocation_generation: u64,
    expires_at: Option<SystemTime>,
}

impl EventPeerEligibility {
    /// Creates locally provisioned exact-peer authority.
    #[allow(clippy::too_many_arguments)]
    pub const fn provisioned_exact_peer(
        mission: NodeId,
        peer: NodeId,
        kind: EventTransportKind,
        event_capable: bool,
        authority_generation: u64,
        revocation_generation: u64,
        expires_at: Option<SystemTime>,
    ) -> Self {
        Self {
            mission,
            peer,
            kind,
            event_capable,
            source: EventPeerEligibilitySource::ProvisionedExactPeer,
            authority_generation,
            revocation_generation,
            expires_at,
        }
    }

    /// Creates authority learned from a prior exact-peer mission transcript.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // Runtime mission-authenticated binding is wired in Task 3.
    pub(crate) const fn mission_authenticated(
        mission: NodeId,
        peer: NodeId,
        kind: EventTransportKind,
        event_capable: bool,
        authority_generation: u64,
        revocation_generation: u64,
        expires_at: Option<SystemTime>,
    ) -> Self {
        Self {
            mission,
            peer,
            kind,
            event_capable,
            source: EventPeerEligibilitySource::MissionAuthenticated,
            authority_generation,
            revocation_generation,
            expires_at,
        }
    }

    /// Returns the authority source; there is deliberately no locator source.
    pub const fn source(&self) -> EventPeerEligibilitySource {
        self.source
    }

    pub(crate) const fn mission(&self) -> NodeId {
        self.mission
    }

    pub(crate) const fn peer(&self) -> NodeId {
        self.peer
    }
}

fn select_event_adapter(
    adapters: &[EventAdapterSnapshot],
    eligibility: &[EventPeerEligibility],
    mission: NodeId,
    peer: NodeId,
    now: SystemTime,
) -> Option<EventTransportKind> {
    adapters
        .iter()
        .filter(|adapter| {
            adapter.state == EventAdapterState::Available
                && adapter.event_capable
                && eligibility.iter().any(|entry| {
                    entry.mission == mission
                        && entry.peer == peer
                        && entry.kind == adapter.kind
                        && entry.event_capable
                        && entry.authority_generation > entry.revocation_generation
                        && entry.expires_at.is_none_or(|expiry| now < expiry)
                })
        })
        .min_by_key(|adapter| (Reverse(adapter.configured_priority), adapter.kind))
        .map(|adapter| adapter.kind)
}

type EventAttemptFuture =
    Pin<Box<dyn Future<Output = Result<(), ContactOutcome>> + Send + 'static>>;
type EventAttemptRunner =
    Arc<dyn Fn(Arc<dyn OrderedContact>) -> EventAttemptFuture + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventCohortKey {
    mission: NodeId,
    peer: NodeId,
}

struct PendingEventCohort {
    key: EventCohortKey,
    runner: EventAttemptRunner,
    failed_instances: BTreeMap<EventTransportKind, (u64, u64)>,
    mailbox_full_instances: BTreeMap<EventTransportKind, (u64, u64)>,
}

struct RegisteredEventAdapter {
    registration_id: u64,
    snapshot: EventAdapterSnapshot,
    attempts: mpsc::Sender<EventOutboundAttempt>,
}

struct EventAttemptIdentity;

struct InFlightEventAttempt {
    identity: Arc<EventAttemptIdentity>,
    key: EventCohortKey,
}

struct AutomaticEventTransportState {
    adapters: BTreeMap<EventTransportKind, RegisteredEventAdapter>,
    eligibility: Vec<EventPeerEligibility>,
    pending: VecDeque<PendingEventCohort>,
    attempt_in_flight: Option<InFlightEventAttempt>,
    next_registration_id: u64,
    transition_count: u64,
}

impl Default for AutomaticEventTransportState {
    fn default() -> Self {
        Self {
            adapters: BTreeMap::new(),
            eligibility: Vec::new(),
            pending: VecDeque::new(),
            attempt_in_flight: None,
            next_registration_id: 1,
            transition_count: 0,
        }
    }
}

struct AutomaticEventTransportShared {
    state: Mutex<AutomaticEventTransportState>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync + 'static>,
    capacity_progress: watch::Sender<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventAttemptAdmission {
    Accepted,
    CapacityFull,
}

/// Cloneable host handle for exact-peer Event adapter selection.
#[derive(Clone)]
pub struct AutomaticEventTransportHandle {
    shared: Arc<AutomaticEventTransportShared>,
}

impl Default for AutomaticEventTransportHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl AutomaticEventTransportHandle {
    /// Creates an empty application-ready registry.
    pub fn new() -> Self {
        let (capacity_progress, _) = watch::channel(0);
        Self {
            shared: Arc::new(AutomaticEventTransportShared {
                state: Mutex::new(AutomaticEventTransportState::default()),
                clock: Arc::new(SystemTime::now),
                capacity_progress,
            }),
        }
    }

    #[cfg(test)]
    fn with_clock<F>(clock: F) -> Self
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        let (capacity_progress, _) = watch::channel(0);
        Self {
            shared: Arc::new(AutomaticEventTransportShared {
                state: Mutex::new(AutomaticEventTransportState::default()),
                clock: Arc::new(clock),
                capacity_progress,
            }),
        }
    }

    /// Registers one adapter-owned attempt mailbox.
    ///
    /// A duplicate live kind is rejected. Dropping the returned control removes
    /// the registration; the receiver remains single-owner and bounded to one.
    pub fn register(
        &self,
        snapshot: EventAdapterSnapshot,
    ) -> Option<(EventAdapterControl, EventAttemptReceiver)> {
        let (sender, receiver) = mpsc::channel(1);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.adapters.contains_key(&snapshot.kind) {
            return None;
        }
        let registration_id = state.next_registration_id;
        state.next_registration_id = state.next_registration_id.saturating_add(1);
        state.adapters.insert(
            snapshot.kind,
            RegisteredEventAdapter {
                registration_id,
                snapshot,
                attempts: sender,
            },
        );
        transition(&self.shared, &mut state);
        Some((
            EventAdapterControl {
                shared: Arc::downgrade(&self.shared),
                kind: snapshot.kind,
                registration_id,
            },
            EventAttemptReceiver {
                receiver,
                shared: Arc::downgrade(&self.shared),
                kind: snapshot.kind,
                registration_id,
            },
        ))
    }

    /// Atomically replaces host-owned exact-peer eligibility.
    ///
    /// Returns `false` and preserves the prior authority when the replacement
    /// exceeds [`MAX_EVENT_PEER_ELIGIBILITY`].
    pub fn replace_eligibility(&self, eligibility: Vec<EventPeerEligibility>) -> bool {
        if eligibility.len() > MAX_EVENT_PEER_ELIGIBILITY {
            return false;
        }
        let current_cohorts = eligibility
            .iter()
            .map(|entry| EventCohortKey {
                mission: entry.mission,
                peer: entry.peer,
            })
            .collect::<BTreeSet<_>>();
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.eligibility = eligibility;
        let pending_before = state.pending.len();
        state
            .pending
            .retain(|cohort| current_cohorts.contains(&cohort.key));
        let revoked_in_flight = state
            .attempt_in_flight
            .as_ref()
            .is_some_and(|attempt| !current_cohorts.contains(&attempt.key));
        if revoked_in_flight {
            state.attempt_in_flight = None;
        }
        let released_capacity = state.pending.len() < pending_before || revoked_in_flight;
        transition(&self.shared, &mut state);
        drop(state);
        if released_capacity {
            notify_capacity_progress(&self.shared);
        }
        true
    }

    #[cfg(test)]
    fn request_attempt<F, Fut>(&self, mission: NodeId, peer: NodeId, runner: F) -> bool
    where
        F: Fn(Arc<dyn OrderedContact>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ContactOutcome>> + Send + 'static,
    {
        matches!(
            self.request_attempt_admission(mission, peer, runner),
            EventAttemptAdmission::Accepted
        )
    }

    pub(crate) fn request_attempt_admission<F, Fut>(
        &self,
        mission: NodeId,
        peer: NodeId,
        runner: F,
    ) -> EventAttemptAdmission
    where
        F: Fn(Arc<dyn OrderedContact>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ContactOutcome>> + Send + 'static,
    {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.pending.len() + usize::from(state.attempt_in_flight.is_some())
            >= MAX_PENDING_EVENT_COHORTS
        {
            return EventAttemptAdmission::CapacityFull;
        }
        let runner: EventAttemptRunner = Arc::new(move |contact| Box::pin(runner(contact)));
        state.pending.push_back(PendingEventCohort {
            key: EventCohortKey { mission, peer },
            runner,
            failed_instances: BTreeMap::new(),
            mailbox_full_instances: BTreeMap::new(),
        });
        transition(&self.shared, &mut state);
        EventAttemptAdmission::Accepted
    }

    pub(crate) fn subscribe_capacity_progress(&self) -> watch::Receiver<u64> {
        self.shared.capacity_progress.subscribe()
    }

    #[allow(dead_code)] // Task 3 uses this deterministic no-spin observation in runtime tests.
    pub(crate) fn transition_count(&self) -> u64 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .transition_count
    }
}

/// Adapter-owned availability publisher and registration lease.
pub struct EventAdapterControl {
    shared: Weak<AutomaticEventTransportShared>,
    kind: EventTransportKind,
    registration_id: u64,
}

impl EventAdapterControl {
    /// Publishes a strictly newer sanitized lifecycle snapshot.
    ///
    /// A different kind, stale epoch, or replaced registration is rejected.
    /// The registration's core-owned configured priority remains immutable.
    pub fn publish_availability(&self, snapshot: EventAdapterSnapshot) -> bool {
        if snapshot.kind != self.kind {
            return false;
        }
        let Some(shared) = self.shared.upgrade() else {
            return false;
        };
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(adapter) = state.adapters.get_mut(&self.kind) else {
            return false;
        };
        if adapter.registration_id != self.registration_id
            || snapshot.availability_epoch <= adapter.snapshot.availability_epoch
        {
            return false;
        }
        adapter.snapshot = EventAdapterSnapshot::new(
            snapshot.kind,
            snapshot.availability_epoch,
            snapshot.state,
            snapshot.event_capable,
            adapter.snapshot.configured_priority,
        );
        transition(&shared, &mut state);
        true
    }
}

impl Drop for EventAdapterControl {
    fn drop(&mut self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state
            .adapters
            .get(&self.kind)
            .is_some_and(|adapter| adapter.registration_id == self.registration_id)
        {
            state.adapters.remove(&self.kind);
            transition(&shared, &mut state);
        }
    }
}

/// Single-owner receiver for one adapter's bounded outbound attempt lane.
pub struct EventAttemptReceiver {
    receiver: mpsc::Receiver<EventOutboundAttempt>,
    shared: Weak<AutomaticEventTransportShared>,
    kind: EventTransportKind,
    registration_id: u64,
}

impl EventAttemptReceiver {
    /// Waits without polling for the next selected outbound attempt.
    pub async fn recv(&mut self) -> Option<EventOutboundAttempt> {
        let attempt = self.receiver.recv().await;
        if attempt.is_some()
            && let Some(shared) = self.shared.upgrade()
        {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            for pending in &mut state.pending {
                if pending
                    .mailbox_full_instances
                    .get(&self.kind)
                    .is_some_and(|(registration_id, _)| *registration_id == self.registration_id)
                {
                    pending.mailbox_full_instances.remove(&self.kind);
                }
            }
            transition(&shared, &mut state);
        }
        attempt
    }
}

/// One globally admitted fresh Event contact attempt.
pub struct EventOutboundAttempt {
    shared: Arc<AutomaticEventTransportShared>,
    identity: Arc<EventAttemptIdentity>,
    key: EventCohortKey,
    kind: EventTransportKind,
    registration_id: u64,
    availability_epoch: u64,
    runner: EventAttemptRunner,
    failed_instances: BTreeMap<EventTransportKind, (u64, u64)>,
    completed: bool,
}

impl EventOutboundAttempt {
    /// Returns the selected stable transport kind.
    pub const fn transport_kind(&self) -> EventTransportKind {
        self.kind
    }

    /// Returns the mission authority bound to the pending cohort.
    pub const fn mission(&self) -> NodeId {
        self.key.mission
    }

    /// Returns the exact expected mission peer.
    pub const fn peer(&self) -> NodeId {
        self.key.peer
    }

    /// Runs this fresh contact through the node-owned ordered Event admission.
    pub async fn run(mut self, contact: Arc<dyn OrderedContact>) -> Result<(), ContactOutcome> {
        let result = (Arc::clone(&self.runner))(contact).await;
        self.complete(&result);
        result
    }

    /// Completes carrier opening with locally proven adapter unavailability.
    pub fn fail_carrier_open(mut self) -> ContactOutcome {
        let outcome = ContactOutcome::carrier_open_unavailable();
        self.complete(&Err(outcome));
        outcome
    }

    fn owns_in_flight_slot(&self, state: &AutomaticEventTransportState) -> bool {
        state.attempt_in_flight.as_ref().is_some_and(|attempt| {
            Arc::ptr_eq(&attempt.identity, &self.identity) && attempt.key == self.key
        })
    }

    fn complete(&mut self, result: &Result<(), ContactOutcome>) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.completed = true;
        if !self.owns_in_flight_slot(&state) {
            return;
        }
        state.attempt_in_flight = None;
        let released_capacity = match result {
            Ok(()) => {
                transition(&self.shared, &mut state);
                true
            }
            Err(outcome) if outcome.permits_reselection() => {
                let still_current = state
                    .eligibility
                    .iter()
                    .any(|entry| entry.mission == self.key.mission && entry.peer == self.key.peer);
                if still_current {
                    self.failed_instances
                        .insert(self.kind, (self.registration_id, self.availability_epoch));
                    state.pending.push_front(PendingEventCohort {
                        key: self.key,
                        runner: Arc::clone(&self.runner),
                        failed_instances: std::mem::take(&mut self.failed_instances),
                        mailbox_full_instances: BTreeMap::new(),
                    });
                }
                transition(&self.shared, &mut state);
                !still_current
            }
            Err(_) => {
                transition(&self.shared, &mut state);
                true
            }
        };
        drop(state);
        if released_capacity {
            notify_capacity_progress(&self.shared);
        }
    }
}

impl Drop for EventOutboundAttempt {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.completed = true;
        if !self.owns_in_flight_slot(&state) {
            return;
        }
        state.attempt_in_flight = None;
        transition(&self.shared, &mut state);
        drop(state);
        notify_capacity_progress(&self.shared);
    }
}

fn notify_capacity_progress(shared: &AutomaticEventTransportShared) {
    shared
        .capacity_progress
        .send_modify(|generation| *generation = generation.saturating_add(1));
}

fn transition(
    shared: &Arc<AutomaticEventTransportShared>,
    state: &mut AutomaticEventTransportState,
) {
    state.transition_count = state.transition_count.saturating_add(1);
    if state.attempt_in_flight.is_some() {
        return;
    }
    let now = (shared.clock)();
    let pending_count = state.pending.len();
    for _ in 0..pending_count {
        let Some(mut pending) = state.pending.pop_front() else {
            break;
        };
        loop {
            let snapshots: Vec<_> = state
                .adapters
                .values()
                .filter(|adapter| {
                    let instance = (adapter.registration_id, adapter.snapshot.availability_epoch);
                    pending.failed_instances.get(&adapter.snapshot.kind) != Some(&instance)
                        && pending.mailbox_full_instances.get(&adapter.snapshot.kind)
                            != Some(&instance)
                })
                .map(|adapter| adapter.snapshot)
                .collect();
            let Some(kind) = select_event_adapter(
                &snapshots,
                &state.eligibility,
                pending.key.mission,
                pending.key.peer,
                now,
            ) else {
                break;
            };
            let Some((registration_id, availability_epoch, attempts)) =
                state.adapters.get(&kind).map(|adapter| {
                    (
                        adapter.registration_id,
                        adapter.snapshot.availability_epoch,
                        adapter.attempts.clone(),
                    )
                })
            else {
                continue;
            };
            let identity = Arc::new(EventAttemptIdentity);
            let attempt = EventOutboundAttempt {
                shared: Arc::clone(shared),
                identity: Arc::clone(&identity),
                key: pending.key,
                kind,
                registration_id,
                availability_epoch,
                runner: Arc::clone(&pending.runner),
                failed_instances: pending.failed_instances.clone(),
                completed: false,
            };
            match attempts.try_send(attempt) {
                Ok(()) => {
                    state.attempt_in_flight = Some(InFlightEventAttempt {
                        identity,
                        key: pending.key,
                    });
                    return;
                }
                Err(mpsc::error::TrySendError::Full(mut attempt)) => {
                    attempt.completed = true;
                    pending
                        .mailbox_full_instances
                        .insert(kind, (registration_id, availability_epoch));
                }
                Err(mpsc::error::TrySendError::Closed(mut attempt)) => {
                    attempt.completed = true;
                    if state
                        .adapters
                        .get(&kind)
                        .is_some_and(|adapter| adapter.registration_id == registration_id)
                    {
                        state.adapters.remove(&kind);
                    }
                }
            }
        }
        state.pending.push_back(pending);
    }
}

/// Last trusted transition reached by one Event contact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactStage {
    /// The candidate has not opened a carrier contact.
    Candidate,
    /// The adapter is opening the carrier contact.
    CarrierOpen,
    /// The carrier is open but the mission transcript is not authenticated.
    MissionHandshake,
    /// The exact expected mission peer has authenticated.
    AuthenticatedSession,
}

/// Authority scope affected by one contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactScope {
    /// One unauthenticated transient carrier locator.
    Locator,
    /// One locally observed adapter lifecycle epoch.
    AdapterEpoch,
    /// The exact mission peer authenticated by the completed transcript.
    ExpectedPeer,
    /// The authenticated mission session.
    Mission,
    /// Local or authenticated mission policy.
    Policy,
    /// Only this scheduled attempt.
    Attempt,
}

/// Trusted source of the outcome's scope classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactProvenance {
    /// Local admission or cancellation state.
    Local,
    /// Local adapter lifecycle state.
    Adapter,
    /// Remote or ambiguous evidence observed before mission authentication.
    UnauthenticatedRemote,
    /// A completed transcript authenticating the exact expected mission peer.
    AuthenticatedMission,
}

/// Scheduler action authorized by one terminal contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactDisposition {
    /// End the operation without an automatic retry.
    Terminal,
    /// Keep durable work pending for a later independently selected operation.
    RetryLater,
    /// Wake selection because local evidence proves this carrier is unavailable.
    Reselect,
    /// Suppress authenticated peer, mission, or policy work until authority changes.
    Suppress,
    /// Preserve caller cancellation as cancellation.
    Cancelled,
}

/// Sanitized closed reason for one contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactReason {
    /// Contact admission is closed.
    AdmissionClosed,
    /// The bounded contact lane is occupied.
    AdmissionBusy,
    /// The node actor cannot receive another command.
    ActorUnavailable,
    /// The node actor stopped before contact completion.
    ActorStopped,
    /// The contact caller cancelled its response wait.
    CallerCancelled,
    /// Local adapter state proves carrier opening is unavailable.
    CarrierUnavailable,
    /// An established carrier was interrupted.
    TransportInterrupted,
    /// A bounded carrier or session deadline elapsed.
    TransportTimeout,
    /// The authenticated mission identity differed from the expected identity.
    IdentityMismatch,
    /// The mission transcript failed authentication before exact peer admission.
    AuthenticationFailed,
    /// Authenticated policy rejected or invalidated the session.
    PolicyRejected,
    /// Authenticated protocol or integrity processing rejected the session.
    ProtocolViolation,
    /// A local invariant failed and the node cannot safely retry the contact.
    LocalInvariant,
}

/// Closed terminal result for one Event contact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactOutcome {
    stage: ContactStage,
    scope: ContactScope,
    provenance: ContactProvenance,
    disposition: ContactDisposition,
    reason: ContactReason,
}

impl ContactOutcome {
    /// Creates the fixed local outcome for closed node admission.
    pub const fn admission_closed() -> Self {
        Self::local_admission(ContactDisposition::Terminal, ContactReason::AdmissionClosed)
    }

    /// Creates the fixed local outcome for an occupied bounded admission lane.
    pub const fn admission_busy() -> Self {
        Self::local_admission(ContactDisposition::RetryLater, ContactReason::AdmissionBusy)
    }

    /// Creates the fixed local outcome for an unavailable node actor mailbox.
    pub const fn actor_unavailable() -> Self {
        Self::local_admission(
            ContactDisposition::RetryLater,
            ContactReason::ActorUnavailable,
        )
    }

    /// Creates the fixed local outcome for actor loss before completion.
    pub const fn actor_stopped() -> Self {
        Self::local_admission(ContactDisposition::Terminal, ContactReason::ActorStopped)
    }

    /// Creates the fixed local outcome for a proven unavailable adapter epoch.
    #[allow(dead_code)] // Consumed by the automatic attempt ticket in Task 2.
    pub(crate) const fn carrier_open_unavailable() -> Self {
        Self {
            stage: ContactStage::CarrierOpen,
            scope: ContactScope::AdapterEpoch,
            provenance: ContactProvenance::Adapter,
            disposition: ContactDisposition::Reselect,
            reason: ContactReason::CarrierUnavailable,
        }
    }

    pub(crate) const fn caller_cancelled(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::Cancelled,
            reason: ContactReason::CallerCancelled,
        }
    }

    pub(crate) const fn pre_auth_remote(reason: ContactReason) -> Self {
        Self {
            stage: ContactStage::MissionHandshake,
            scope: ContactScope::Locator,
            provenance: ContactProvenance::UnauthenticatedRemote,
            disposition: ContactDisposition::RetryLater,
            reason,
        }
    }

    pub(crate) const fn pre_auth_transport(
        scope: ContactScope,
        provenance: ContactProvenance,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::AdapterEpoch | ContactScope::Attempt
        ));
        debug_assert!(matches!(
            provenance,
            ContactProvenance::Adapter | ContactProvenance::UnauthenticatedRemote
        ));
        Self {
            stage: ContactStage::MissionHandshake,
            scope,
            provenance,
            disposition,
            reason,
        }
    }

    pub(crate) const fn authenticated_session(
        scope: ContactScope,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::ExpectedPeer
                | ContactScope::Mission
                | ContactScope::Policy
                | ContactScope::Attempt
        ));
        Self {
            stage: ContactStage::AuthenticatedSession,
            scope,
            provenance: ContactProvenance::AuthenticatedMission,
            disposition,
            reason,
        }
    }

    pub(crate) const fn authenticated_transport(
        scope: ContactScope,
        provenance: ContactProvenance,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::AdapterEpoch | ContactScope::Attempt
        ));
        debug_assert!(matches!(
            provenance,
            ContactProvenance::Adapter | ContactProvenance::AuthenticatedMission
        ));
        Self {
            stage: ContactStage::AuthenticatedSession,
            scope,
            provenance,
            disposition,
            reason,
        }
    }

    pub(crate) const fn local_invariant(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::Terminal,
            reason: ContactReason::LocalInvariant,
        }
    }

    pub(crate) const fn local_policy(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Policy,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::RetryLater,
            reason: ContactReason::PolicyRejected,
        }
    }

    const fn local_admission(disposition: ContactDisposition, reason: ContactReason) -> Self {
        Self {
            stage: ContactStage::Candidate,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition,
            reason,
        }
    }

    /// Returns the last trusted transition reached by the attempt.
    pub const fn stage(&self) -> ContactStage {
        self.stage
    }

    /// Returns the authority scope affected by the outcome.
    pub const fn scope(&self) -> ContactScope {
        self.scope
    }

    /// Returns the trusted provenance of the scope classification.
    pub const fn provenance(&self) -> ContactProvenance {
        self.provenance
    }

    /// Returns the scheduler disposition authorized by the outcome.
    pub const fn disposition(&self) -> ContactDisposition {
        self.disposition
    }

    /// Returns the sanitized closed reason.
    pub const fn reason(&self) -> ContactReason {
        self.reason
    }

    /// Returns whether this exact outcome authorizes immediate adapter reselection.
    pub const fn permits_reselection(&self) -> bool {
        matches!(self.disposition, ContactDisposition::Reselect)
    }
}

impl fmt::Display for ContactOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Event contact {:?} at {:?} ({:?}/{:?})",
            self.reason, self.stage, self.scope, self.disposition
        )
    }
}

impl Error for ContactOutcome {}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_contact::{
        CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler,
        TransientLocator,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    const MISSION: [u8; 32] = [0x11; 32];
    const PEER: [u8; 32] = [0x22; 32];

    struct TestOrderedContact;

    impl OrderedContact for TestOrderedContact {
        fn peer_evidence(&self) -> CarrierPeerEvidence {
            CarrierPeerEvidence::UnauthenticatedLocator {
                transient_locator: TransientLocator::new(vec![1]).unwrap(),
            }
        }

        fn max_frame_bytes(&self) -> usize {
            1024
        }

        fn request_with_total_limit<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(async { unreachable!("test runner does not use the contact") })
        }

        fn request_with_total_limit_checked<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
            _before_write: ContactPreflight<'a>,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(async { unreachable!("test runner does not use the contact") })
        }

        fn respond_once_with_total_limit<'a>(
            &'a self,
            _total_limit: usize,
            _handler: ContactRequestHandler<'a>,
        ) -> ContactFuture<'a, bool> {
            Box::pin(async { unreachable!("test runner does not use the contact") })
        }

        fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn close(&self) {}
    }

    #[test]
    fn selector_returns_none_for_empty_or_unavailable_registry() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        assert_eq!(select_event_adapter(&[], &[], MISSION, PEER, now), None);

        let unavailable = EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Unavailable,
            true,
            10,
        );
        let eligible = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        assert_eq!(
            select_event_adapter(&[unavailable], &[eligible], MISSION, PEER, now),
            None
        );
    }

    #[test]
    fn selector_requires_local_eligibility_for_the_exact_mission_peer() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let available = EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Available,
            true,
            10,
        );
        let eligible = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );

        assert_eq!(
            select_event_adapter(&[available], &[eligible], MISSION, PEER, now),
            Some(EventTransportKind::IROH_QUIC_V1)
        );
        assert_eq!(
            select_event_adapter(&[available], &[eligible], MISSION, [0x23; 32], now),
            None
        );
        assert_eq!(
            select_event_adapter(&[available], &[], MISSION, PEER, now),
            None
        );
    }

    #[test]
    fn selector_rejects_expired_or_revoked_peer_authority() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let available = EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Available,
            true,
            10,
        );
        let expired = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            2,
            0,
            Some(now),
        );
        let revoked = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            2,
            2,
            None,
        );

        assert_eq!(
            select_event_adapter(&[available], &[expired], MISSION, PEER, now),
            None
        );
        assert_eq!(
            select_event_adapter(&[available], &[revoked], MISSION, PEER, now),
            None
        );
    }

    #[test]
    fn selector_requires_event_capability_from_adapter_and_peer_authority() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let unavailable_for_event = EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Available,
            false,
            10,
        );
        let adapter_capable = EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Available,
            true,
            10,
        );
        let event_eligible = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        let not_event_eligible = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            false,
            1,
            0,
            None,
        );

        assert_eq!(
            select_event_adapter(
                &[unavailable_for_event],
                &[event_eligible],
                MISSION,
                PEER,
                now,
            ),
            None
        );
        assert_eq!(
            select_event_adapter(
                &[adapter_capable],
                &[not_event_eligible],
                MISSION,
                PEER,
                now,
            ),
            None
        );
    }

    #[test]
    fn selector_ranks_configured_priority_then_stable_kind() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let eligibility = [
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
        ];
        let tied = [
            EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ),
            EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ),
        ];
        let ble_preferred = [
            tied[1],
            EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                11,
            ),
        ];

        assert_eq!(
            select_event_adapter(&tied, &eligibility, MISSION, PEER, now),
            Some(EventTransportKind::IROH_QUIC_V1)
        );
        assert_eq!(
            select_event_adapter(&ble_preferred, &eligibility, MISSION, PEER, now),
            Some(EventTransportKind::BLE_L2CAP_V1)
        );
    }

    #[test]
    fn selector_accepts_authenticated_exact_peer_without_locator_input() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let available = EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            7,
            EventAdapterState::Available,
            true,
            10,
        );
        let eligible = EventPeerEligibility::mission_authenticated(
            MISSION,
            PEER,
            EventTransportKind::BLE_L2CAP_V1,
            true,
            9,
            2,
            None,
        );

        assert_eq!(
            eligible.source(),
            EventPeerEligibilitySource::MissionAuthenticated
        );
        assert_eq!(
            select_event_adapter(&[available], &[eligible], MISSION, PEER, now),
            Some(EventTransportKind::BLE_L2CAP_V1)
        );
    }

    #[tokio::test]
    async fn pending_work_is_retained_until_an_eligible_adapter_registers() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        )]);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("first registration is admitted");
        let attempt = attempts.recv().await.expect("retained work wakes");
        assert_eq!(attempt.transport_kind(), EventTransportKind::IROH_QUIC_V1);
        assert_eq!(attempt.mission(), MISSION);
        assert_eq!(attempt.peer(), PEER);
    }

    #[tokio::test]
    async fn capacity_release_emits_progress_after_explicit_full_admission() {
        let handle = AutomaticEventTransportHandle::new();
        assert!(
            handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),])
        );
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("adapter registration");
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        let in_flight = attempts.recv().await.expect("one in-flight attempt");
        for _ in 1..MAX_PENDING_EVENT_COHORTS {
            assert_eq!(
                handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
                EventAttemptAdmission::Accepted
            );
        }
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::CapacityFull
        );
        let mut progress = handle.subscribe_capacity_progress();

        drop(in_flight);
        progress
            .changed()
            .await
            .expect("capacity release is an event-driven progress wake");
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
    }

    #[tokio::test]
    async fn newer_availability_epoch_wakes_selection_and_stale_epoch_is_ignored() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        )]);
        let (control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Unavailable,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(attempts.receiver.try_recv().is_err());

        assert!(!control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            1,
            EventAdapterState::Available,
            true,
            10,
        )));
        assert!(attempts.receiver.try_recv().is_err());

        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            2,
            EventAdapterState::Available,
            true,
            10,
        )));
        assert_eq!(
            attempts.recv().await.unwrap().transport_kind(),
            EventTransportKind::IROH_QUIC_V1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn availability_publication_cannot_rewrite_configured_priority() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
        ]));
        let (_iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        let (ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                9,
            ))
            .unwrap();

        assert!(ble_control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Available,
            true,
            100,
        )));
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), iroh_attempts.recv())
                .await
                .expect("configured priority remains core-owned")
                .unwrap()
                .transport_kind(),
            EventTransportKind::IROH_QUIC_V1
        );
        assert!(ble_attempts.receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn one_global_attempt_rotates_fairly_to_the_next_peer_after_completion() {
        let second_peer = [0x33; 32];
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                second_peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
        ]);
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, second_peer, |_contact| async { Ok(()) }));

        let first = attempts.recv().await.unwrap();
        assert_eq!(first.peer(), PEER);
        assert!(attempts.receiver.try_recv().is_err());
        assert_eq!(first.run(Arc::new(TestOrderedContact)).await, Ok(()));

        let second = attempts.recv().await.unwrap();
        assert_eq!(second.peer(), second_peer);
    }

    #[tokio::test]
    async fn locally_proven_carrier_open_failure_reselects_an_alternate_kind() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
        ]);
        let (_iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        let (_ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        let selected = iroh_attempts.recv().await.unwrap();
        let outcome = selected.fail_carrier_open();
        assert_eq!(outcome, ContactOutcome::carrier_open_unavailable());
        assert!(outcome.permits_reselection());
        assert_eq!(
            ble_attempts.recv().await.unwrap().transport_kind(),
            EventTransportKind::BLE_L2CAP_V1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_old_registration_does_not_exclude_replacement_at_same_epoch() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(
            handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),])
        );
        let (old_control, mut old_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let old_attempt = old_attempts.recv().await.unwrap();

        drop(old_control);
        assert!(old_attempt.fail_carrier_open().permits_reselection());

        let (_new_control, mut new_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("replacement registration is admitted");
        let replacement_attempt = tokio::time::timeout(Duration::from_secs(1), new_attempts.recv())
            .await
            .expect("old registration evidence does not suppress its replacement")
            .unwrap();
        assert_eq!(
            replacement_attempt.transport_kind(),
            EventTransportKind::IROH_QUIC_V1
        );
    }

    #[tokio::test]
    async fn remote_pre_auth_outcome_does_not_immediately_try_an_alternate_carrier() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
        ]);
        let (_iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        let (_ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async {
            Err(ContactOutcome::pre_auth_remote(
                ContactReason::AuthenticationFailed,
            ))
        }));

        let outcome = iroh_attempts
            .recv()
            .await
            .unwrap()
            .run(Arc::new(TestOrderedContact))
            .await
            .unwrap_err();
        assert_eq!(
            outcome.provenance(),
            ContactProvenance::UnauthenticatedRemote
        );
        assert!(!outcome.permits_reselection());
        assert!(ble_attempts.receiver.try_recv().is_err());
        assert!(iroh_attempts.receiver.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_remote_outcome_immediately_admits_the_next_peer() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let next_peer = [0x33; 32];
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                next_peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
        ]));
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async {
            Err(ContactOutcome::pre_auth_remote(
                ContactReason::AuthenticationFailed,
            ))
        }));
        assert!(handle.request_attempt(MISSION, next_peer, |_contact| async { Ok(()) }));

        let failed = attempts.recv().await.unwrap();
        assert_eq!(failed.peer(), PEER);
        assert!(failed.run(Arc::new(TestOrderedContact)).await.is_err());

        let next = tokio::time::timeout(Duration::from_secs(1), attempts.recv())
            .await
            .expect("terminal completion wakes the next unrelated cohort")
            .unwrap();
        assert_eq!(next.peer(), next_peer);
        assert!(attempts.receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn empty_registry_retains_work_without_spinning() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        )]);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let transitions_after_enqueue = handle.transition_count();

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert_eq!(handle.transition_count(), transitions_after_enqueue);
        assert_eq!(
            handle
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pending
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_registration_makes_that_kind_unavailable() {
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
        ]);
        let (iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        drop(iroh_control);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(iroh_attempts.receiver.try_recv().is_err());

        let (_ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert_eq!(
            ble_attempts.recv().await.unwrap().transport_kind(),
            EventTransportKind::BLE_L2CAP_V1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_attempt_releases_the_single_global_lane() {
        let second_peer = [0x33; 32];
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                second_peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
        ]);
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, second_peer, |_contact| async { Ok(()) }));

        drop(attempts.recv().await.unwrap());

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempts.recv())
                .await
                .expect("dropping a ticket releases admission")
                .unwrap()
                .peer(),
            second_peer
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ineligible_front_cohort_does_not_strand_a_later_eligible_peer() {
        let eligible_peer = [0x33; 32];
        let handle = AutomaticEventTransportHandle::new();
        handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            eligible_peer,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        )]);
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, eligible_peer, |_contact| async { Ok(()) }));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempts.recv())
                .await
                .expect("fair rotation reaches an eligible cohort")
                .unwrap()
                .peer(),
            eligible_peer
        );
    }

    #[tokio::test]
    async fn mailbox_bound_counts_in_flight_and_survives_reselection() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(
            handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),])
        );
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let admitted = attempts.recv().await.unwrap();

        for _ in 1..MAX_PENDING_EVENT_COHORTS {
            assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        }
        let overflow_was_accepted =
            handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert!(admitted.fail_carrier_open().permits_reselection());

        let state = handle
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            state.pending.len() + usize::from(state.attempt_in_flight.is_some())
                <= MAX_PENDING_EVENT_COHORTS,
            "reselection must not grow the admitted cohort population"
        );
        assert!(!overflow_was_accepted);
    }

    #[test]
    fn eligibility_replacement_is_bounded_and_preserves_last_valid_authority() {
        let handle = AutomaticEventTransportHandle::new();
        let eligible = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        assert!(handle.replace_eligibility(vec![eligible]));
        assert!(!handle.replace_eligibility(vec![eligible; MAX_EVENT_PEER_ELIGIBILITY + 1]));
        assert_eq!(
            handle
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .eligibility,
            vec![eligible]
        );
    }

    #[test]
    fn eligibility_replacement_purges_removed_cohorts_and_keeps_current_peers() {
        let removed_peer = [0x33; 32];
        let current = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        let removed = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            removed_peer,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![current, removed]));
        for index in 0..MAX_PENDING_EVENT_COHORTS {
            let peer = if index % 2 == 0 { removed_peer } else { PEER };
            assert!(handle.request_attempt(MISSION, peer, |_contact| async { Ok(()) }));
        }
        assert!(!handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        assert!(handle.replace_eligibility(vec![current]));
        assert!(
            handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }),
            "purging the removed peer must release bounded admission for a current peer"
        );

        let state = handle
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.pending.len(), MAX_PENDING_EVENT_COHORTS / 2 + 1);
        assert!(state.pending.iter().all(|cohort| cohort.key.peer == PEER));
    }

    #[tokio::test]
    async fn removed_in_flight_peer_is_not_requeued_after_reselection_failure() {
        let handle = AutomaticEventTransportHandle::new();
        assert!(
            handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),])
        );
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("adapter registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let in_flight = attempts.recv().await.expect("one in-flight attempt");

        assert!(handle.replace_eligibility(Vec::new()));
        in_flight.fail_carrier_open();

        let state = handle
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            state.pending.is_empty(),
            "a peer removed while in flight must not return as an obsolete pending cohort"
        );
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test]
    async fn removed_in_flight_attempt_releases_slot_before_obsolete_ticket_drop() {
        let replacement_peer = [0x33; 32];
        let eligibility = |peer| {
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            )
        };
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![eligibility(PEER), eligibility(replacement_peer)]));
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("adapter registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, replacement_peer, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, replacement_peer, |_contact| async { Ok(()) }));
        let obsolete = attempts.recv().await.expect("obsolete peer ticket");
        assert_eq!(obsolete.peer(), PEER);

        assert!(handle.replace_eligibility(vec![eligibility(replacement_peer)]));
        let current = attempts
            .receiver
            .try_recv()
            .expect("removal releases the sole slot before the obsolete ticket resolves");
        assert_eq!(current.peer(), replacement_peer);

        drop(obsolete);
        assert!(
            attempts.receiver.try_recv().is_err(),
            "late obsolete drop must not release the newer in-flight owner"
        );
        drop(current);
        assert_eq!(
            attempts
                .receiver
                .try_recv()
                .expect("current owner drop releases the next cohort")
                .peer(),
            replacement_peer
        );
    }

    #[tokio::test]
    async fn dequeue_of_buffered_obsolete_attempt_wakes_replacement_without_other_event() {
        let replacement_peer = [0x33; 32];
        let eligibility = |peer| {
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            )
        };
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![eligibility(PEER), eligibility(replacement_peer)]));
        let (_control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("adapter registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, replacement_peer, |_contact| async { Ok(()) }));

        assert!(handle.replace_eligibility(vec![eligibility(replacement_peer)]));
        let obsolete = attempts
            .recv()
            .await
            .expect("buffered obsolete ticket remains adapter-visible");
        assert_eq!(obsolete.peer(), PEER);
        let replacement = attempts
            .receiver
            .try_recv()
            .expect("dequeue alone must wake the replacement cohort");
        assert_eq!(replacement.peer(), replacement_peer);
    }

    #[tokio::test]
    async fn full_obsolete_mailbox_falls_through_to_available_alternate_adapter() {
        let replacement_peer = [0x33; 32];
        let eligibility = |peer, kind| {
            EventPeerEligibility::provisioned_exact_peer(MISSION, peer, kind, true, 1, 0, None)
        };
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![
            eligibility(PEER, EventTransportKind::IROH_QUIC_V1),
            eligibility(replacement_peer, EventTransportKind::IROH_QUIC_V1),
            eligibility(replacement_peer, EventTransportKind::BLE_L2CAP_V1),
        ]));
        let (_iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("Iroh registration");
        let (_ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                5,
            ))
            .expect("BLE registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, replacement_peer, |_contact| async { Ok(()) }));

        assert!(handle.replace_eligibility(vec![
            eligibility(replacement_peer, EventTransportKind::IROH_QUIC_V1),
            eligibility(replacement_peer, EventTransportKind::BLE_L2CAP_V1),
        ]));
        let alternate = ble_attempts
            .receiver
            .try_recv()
            .expect("a full stale Iroh mailbox must not block available BLE");
        assert_eq!(alternate.peer(), replacement_peer);
        assert_eq!(alternate.transport_kind(), EventTransportKind::BLE_L2CAP_V1);
        assert_eq!(
            iroh_attempts
                .receiver
                .try_recv()
                .expect("obsolete Iroh ticket remains buffered")
                .peer(),
            PEER
        );
    }

    #[tokio::test]
    async fn remove_and_readd_does_not_resurrect_obsolete_in_flight_cohort() {
        let eligibility = |kind| {
            EventPeerEligibility::provisioned_exact_peer(MISSION, PEER, kind, true, 1, 0, None)
        };
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![eligibility(EventTransportKind::IROH_QUIC_V1)]));
        let (_iroh_control, mut iroh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("Iroh registration");
        let (_ble_control, mut ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("BLE registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let obsolete = iroh_attempts.recv().await.expect("obsolete Iroh ticket");

        assert!(handle.replace_eligibility(Vec::new()));
        assert!(handle.replace_eligibility(vec![
            eligibility(EventTransportKind::IROH_QUIC_V1),
            eligibility(EventTransportKind::BLE_L2CAP_V1),
        ]));
        assert!(obsolete.fail_carrier_open().permits_reselection());

        assert!(
            iroh_attempts.receiver.try_recv().is_err(),
            "re-added peer needs new work rather than the obsolete cohort"
        );
        assert!(
            ble_attempts.receiver.try_recv().is_err(),
            "old adapter failure must not resurrect work under the re-added roster"
        );
        assert!(
            handle
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pending
                .is_empty()
        );
    }

    async fn same_key_ownership_scenario() -> (
        EventAdapterControl,
        EventAttemptReceiver,
        EventOutboundAttempt,
        EventOutboundAttempt,
    ) {
        let eligibility = EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            EventTransportKind::IROH_QUIC_V1,
            true,
            1,
            0,
            None,
        );
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![eligibility]));
        let (control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("adapter registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let obsolete = attempts.recv().await.expect("obsolete ticket");

        assert!(handle.replace_eligibility(Vec::new()));
        assert!(handle.replace_eligibility(vec![eligibility]));
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let fresh = attempts.recv().await.expect("fresh same-key ticket");
        assert!(
            !Arc::ptr_eq(&obsolete.identity, &fresh.identity),
            "attempt ownership identities must never be reused"
        );
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        (control, attempts, obsolete, fresh)
    }

    #[tokio::test]
    async fn obsolete_completion_cannot_release_fresh_same_key_owner() {
        let (_control, mut attempts, obsolete, fresh) = same_key_ownership_scenario().await;

        assert!(obsolete.fail_carrier_open().permits_reselection());
        assert!(
            attempts.receiver.try_recv().is_err(),
            "obsolete completion must not clear or requeue over the fresh owner"
        );
        drop(fresh);
        assert_eq!(
            attempts
                .recv()
                .await
                .expect("fresh owner drop releases queued work")
                .peer(),
            PEER
        );
    }

    #[tokio::test]
    async fn obsolete_drop_cannot_release_fresh_same_key_owner() {
        let (_control, mut attempts, obsolete, fresh) = same_key_ownership_scenario().await;

        drop(obsolete);
        assert!(
            attempts.receiver.try_recv().is_err(),
            "obsolete drop must not clear, requeue, or release the fresh owner"
        );
        drop(fresh);
        assert_eq!(
            attempts
                .recv()
                .await
                .expect("fresh owner drop releases queued work")
                .peer(),
            PEER
        );
    }

    #[tokio::test]
    async fn retained_work_rechecks_expiry_at_availability_wake() {
        let seconds = Arc::new(AtomicU64::new(100));
        let clock_seconds = Arc::clone(&seconds);
        let handle = AutomaticEventTransportHandle::with_clock(move || {
            UNIX_EPOCH + Duration::from_secs(clock_seconds.load(Ordering::SeqCst))
        });
        assert!(
            handle.replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                PEER,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                Some(UNIX_EPOCH + Duration::from_secs(150)),
            ),])
        );
        let (control, mut attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Unavailable,
                true,
                10,
            ))
            .unwrap();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) },));

        seconds.store(200, Ordering::SeqCst);
        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            2,
            EventAdapterState::Available,
            true,
            10,
        )));

        assert!(attempts.receiver.try_recv().is_err());
        assert_eq!(
            handle
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pending
                .len(),
            1
        );
    }
}
