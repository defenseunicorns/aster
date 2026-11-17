//! Closed outcomes shared by Event transport admission and selection.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};

use aster_contact::OrderedContact;
use aster_mesh::NodeId;
use tokio::sync::{mpsc, watch};

mod outcome;

pub use outcome::{
    ContactDisposition, ContactOutcome, ContactProvenance, ContactReason, ContactScope,
    ContactStage,
};

/// Maximum distinct peer cohorts retained by the in-memory wake mailbox.
pub const MAX_PENDING_EVENT_COHORTS: usize = 64;
/// Maximum exact-peer eligibility entries retained by the selector.
pub const MAX_EVENT_PEER_ELIGIBILITY: usize = 256;

// Match the node's smallest automatic-contact reopen backoff. One retained
// cohort can therefore wake at most four times per second, and the private
// policy remains a single easy-to-change constant.
const RETRY_LATER_READINESS_DELAY: Duration = Duration::from_millis(250);

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
                && select_event_eligibility(eligibility, mission, peer, adapter.kind, now).is_some()
        })
        .min_by_key(|adapter| (Reverse(adapter.configured_priority), adapter.kind))
        .map(|adapter| adapter.kind)
}

fn event_eligibility_is_current(entry: &EventPeerEligibility, now: SystemTime) -> bool {
    entry.event_capable
        && entry.authority_generation > entry.revocation_generation
        && entry.expires_at.is_none_or(|expiry| now < expiry)
}

fn select_event_eligibility(
    eligibility: &[EventPeerEligibility],
    mission: NodeId,
    peer: NodeId,
    kind: EventTransportKind,
    now: SystemTime,
) -> Option<EventPeerEligibility> {
    eligibility
        .iter()
        .copied()
        .filter(|entry| {
            entry.mission == mission
                && entry.peer == peer
                && entry.kind == kind
                && event_eligibility_is_current(entry, now)
        })
        .max_by_key(|entry| (entry.authority_generation, entry.revocation_generation))
}

type EventCohortAuthority = BTreeMap<EventTransportKind, EventPeerEligibility>;

fn event_cohort_authority(
    eligibility: &[EventPeerEligibility],
    key: EventCohortKey,
    now: SystemTime,
) -> EventCohortAuthority {
    let mut authority = EventCohortAuthority::new();
    for entry in eligibility.iter().copied().filter(|entry| {
        entry.mission == key.mission
            && entry.peer == key.peer
            && event_eligibility_is_current(entry, now)
    }) {
        let replace = authority.get(&entry.kind).is_none_or(|selected| {
            (selected.authority_generation, selected.revocation_generation)
                <= (entry.authority_generation, entry.revocation_generation)
        });
        if replace {
            authority.insert(entry.kind, entry);
        }
    }
    authority
}

fn event_cohort_authority_generation(authority: &EventCohortAuthority) -> u64 {
    authority
        .values()
        .map(|entry| entry.authority_generation.max(entry.revocation_generation))
        .max()
        .unwrap_or(0)
}

fn next_event_cohort_expiry(authority: &EventCohortAuthority) -> Option<SystemTime> {
    authority
        .values()
        .filter_map(|entry| entry.expires_at)
        .min()
}

fn event_authority_change_generation(
    eligibility: &[EventPeerEligibility],
    key: EventCohortKey,
) -> u64 {
    eligibility
        .iter()
        .filter(|entry| entry.mission == key.mission && entry.peer == key.peer)
        .map(|entry| entry.authority_generation.max(entry.revocation_generation))
        .max()
        .unwrap_or(0)
}

fn pending_event_cohort_is_current(
    cohort: &PendingEventCohort,
    eligibility: &[EventPeerEligibility],
    now: SystemTime,
) -> bool {
    event_cohort_authority(eligibility, cohort.key, now) == cohort.authority
}

fn revoke_attempt(attempt: &InFlightEventAttempt, outcome: ContactOutcome) {
    let first_revocation = attempt.revocation.send_if_modified(|current| {
        if current.is_some() {
            return false;
        }
        *current = Some(outcome);
        true
    });
    if first_revocation {
        complete_attempt(&attempt.completion, Err(outcome));
    }
}

fn prune_invalid_pending_cohorts(
    state: &mut AutomaticEventTransportState,
    now: SystemTime,
    previous_eligibility: Option<&[EventPeerEligibility]>,
) -> bool {
    let AutomaticEventTransportState {
        eligibility,
        pending,
        ..
    } = state;
    let pending_before = pending.len();
    pending.retain(|cohort| {
        let current = pending_event_cohort_is_current(cohort, eligibility, now);
        if !current {
            let previous_generation = previous_eligibility
                .map(|previous| event_authority_change_generation(previous, cohort.key))
                .unwrap_or_else(|| event_cohort_authority_generation(&cohort.authority));
            let generation = event_authority_change_generation(eligibility, cohort.key)
                .max(previous_generation);
            complete_attempt(
                &cohort.completion,
                Err(ContactOutcome::authority_changed(generation)),
            );
        }
        current
    });
    pending.len() < pending_before
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
    retention: EventAttemptRetention,
    authority: EventCohortAuthority,
    completion: EventAttemptCompletionSource,
    failed_instances: BTreeMap<EventTransportKind, EventAdapterInstance>,
    mailbox_full_instances: BTreeMap<EventTransportKind, EventAdapterInstance>,
    ready_at: Option<tokio::time::Instant>,
}

impl PendingEventCohort {
    fn excludes(
        &self,
        kind: EventTransportKind,
        registration_identity: &Arc<EventAdapterRegistrationIdentity>,
        availability_epoch: u64,
    ) -> bool {
        self.failed_instances
            .get(&kind)
            .is_some_and(|instance| instance.matches(registration_identity, availability_epoch))
            || self
                .mailbox_full_instances
                .get(&kind)
                .is_some_and(|instance| instance.matches(registration_identity, availability_epoch))
    }
}

struct EventAdapterRegistrationIdentity;

#[derive(Clone)]
struct EventAdapterInstance {
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
    availability_epoch: u64,
}

impl EventAdapterInstance {
    fn new(
        registration_identity: &Arc<EventAdapterRegistrationIdentity>,
        availability_epoch: u64,
    ) -> Self {
        Self {
            registration_identity: Arc::clone(registration_identity),
            availability_epoch,
        }
    }

    fn has_registration(
        &self,
        registration_identity: &Arc<EventAdapterRegistrationIdentity>,
    ) -> bool {
        Arc::ptr_eq(&self.registration_identity, registration_identity)
    }

    fn matches(
        &self,
        registration_identity: &Arc<EventAdapterRegistrationIdentity>,
        availability_epoch: u64,
    ) -> bool {
        self.has_registration(registration_identity)
            && self.availability_epoch == availability_epoch
    }
}

struct RegisteredEventAdapter {
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
    snapshot: EventAdapterSnapshot,
    attempts: mpsc::Sender<EventOutboundAttempt>,
}

struct EventAttemptIdentity;

struct InFlightEventAttempt {
    identity: Arc<EventAttemptIdentity>,
    key: EventCohortKey,
    kind: EventTransportKind,
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
    availability_epoch: u64,
    authority: EventCohortAuthority,
    completion: EventAttemptCompletionSource,
    revocation: watch::Sender<Option<ContactOutcome>>,
}

#[derive(Default)]
struct AutomaticEventTransportState {
    adapters: BTreeMap<EventTransportKind, RegisteredEventAdapter>,
    eligibility: Vec<EventPeerEligibility>,
    pending: VecDeque<PendingEventCohort>,
    attempt_in_flight: Option<InFlightEventAttempt>,
    outbound_suspended: bool,
    outbound_policy_generation: u64,
    shutdown: bool,
    authority_expiry_wake: Option<SystemTime>,
    transition_count: u64,
}

struct AutomaticEventTransportShared {
    state: Mutex<AutomaticEventTransportState>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync + 'static>,
    capacity_progress: watch::Sender<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventAttemptAdmission {
    /// A new bounded cohort owns custody.
    Accepted,
    /// The observer subscribed to an existing current cohort.
    Retained,
    /// Admission completed immediately without retaining custody.
    Closed,
    /// The bounded cohort lane has no free slot.
    CapacityFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventAttemptRetention {
    DurableGeneration,
    CallerOwned,
}

type EventAttemptResult = Result<(), ContactOutcome>;
type EventAttemptCompletionSource = watch::Sender<Option<EventAttemptResult>>;

pub(crate) struct EventAttemptObservation {
    receiver: watch::Receiver<Option<Result<(), ContactOutcome>>>,
}

impl EventAttemptObservation {
    pub(crate) async fn wait(mut self) -> Result<(), ContactOutcome> {
        loop {
            if let Some(result) = *self.receiver.borrow_and_update() {
                return result;
            }
            if self.receiver.changed().await.is_err() {
                return Err(ContactOutcome::shutdown());
            }
        }
    }
}

fn event_attempt_completion() -> (EventAttemptCompletionSource, EventAttemptObservation) {
    let (completion, receiver) = watch::channel(None);
    (completion, EventAttemptObservation { receiver })
}

fn observe_completion(completion: &EventAttemptCompletionSource) -> EventAttemptObservation {
    EventAttemptObservation {
        receiver: completion.subscribe(),
    }
}

fn complete_attempt(completion: &EventAttemptCompletionSource, result: EventAttemptResult) {
    completion.send_if_modified(|current| {
        if current.is_some() {
            return false;
        }
        *current = Some(result);
        true
    });
}

fn completed_observation(result: EventAttemptResult) -> EventAttemptObservation {
    let (_sender, receiver) = watch::channel(Some(result));
    EventAttemptObservation { receiver }
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
        self.register_paired(snapshot).map(|registration| {
            let (_, control, attempts) = registration.into_parts();
            (control, attempts)
        })
    }

    /// Registers one paired adapter lease, attempt lane, and initial snapshot.
    ///
    /// The opaque registration has no public constructor. Adapter owners that
    /// validate a transport-specific initial state consume it exactly once.
    pub fn register_paired(
        &self,
        snapshot: EventAdapterSnapshot,
    ) -> Option<EventAdapterRegistration> {
        let (sender, receiver) = mpsc::channel(1);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.adapters.contains_key(&snapshot.kind) {
            return None;
        }
        let registration_identity = Arc::new(EventAdapterRegistrationIdentity);
        state.adapters.insert(
            snapshot.kind,
            RegisteredEventAdapter {
                registration_identity: Arc::clone(&registration_identity),
                snapshot,
                attempts: sender,
            },
        );
        transition(&self.shared, &mut state);
        Some(EventAdapterRegistration {
            initial_snapshot: snapshot,
            control: EventAdapterControl {
                shared: Arc::downgrade(&self.shared),
                kind: snapshot.kind,
                registration_identity: Arc::clone(&registration_identity),
            },
            attempts: EventAttemptReceiver {
                receiver,
                shared: Arc::downgrade(&self.shared),
                kind: snapshot.kind,
                registration_identity,
            },
        })
    }

    /// Atomically replaces host-owned exact-peer eligibility.
    ///
    /// Returns `false` and preserves the prior authority when the replacement
    /// exceeds [`MAX_EVENT_PEER_ELIGIBILITY`].
    pub fn replace_eligibility(&self, eligibility: Vec<EventPeerEligibility>) -> bool {
        if eligibility.len() > MAX_EVENT_PEER_ELIGIBILITY {
            return false;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let old_eligibility = std::mem::replace(&mut state.eligibility, eligibility);
        let now = (self.shared.clock)();
        if let Some(attempt) = &state.attempt_in_flight
            && event_cohort_authority(&state.eligibility, attempt.key, now) != attempt.authority
        {
            let generation = event_authority_change_generation(&state.eligibility, attempt.key)
                .max(event_authority_change_generation(&old_eligibility, attempt.key));
            revoke_attempt(attempt, ContactOutcome::authority_changed(generation));
        }
        let released_capacity =
            prune_invalid_pending_cohorts(&mut state, now, Some(&old_eligibility));
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
        self.request_attempt_admission_inner(
            mission,
            peer,
            EventAttemptRetention::DurableGeneration,
            false,
            runner,
        )
        .0
    }

    pub(crate) fn request_observed_attempt<F, Fut>(
        &self,
        mission: NodeId,
        peer: NodeId,
        runner: F,
    ) -> (EventAttemptAdmission, EventAttemptObservation)
    where
        F: Fn(Arc<dyn OrderedContact>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ContactOutcome>> + Send + 'static,
    {
        let (admission, observation) = self.request_attempt_admission_inner(
            mission,
            peer,
            EventAttemptRetention::CallerOwned,
            true,
            runner,
        );
        (
            admission,
            observation.expect("observed attempts always return their completion observation"),
        )
    }

    fn request_attempt_admission_inner<F, Fut>(
        &self,
        mission: NodeId,
        peer: NodeId,
        retention: EventAttemptRetention,
        observed: bool,
        runner: F,
    ) -> (EventAttemptAdmission, Option<EventAttemptObservation>)
    where
        F: Fn(Arc<dyn OrderedContact>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ContactOutcome>> + Send + 'static,
    {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let key = EventCohortKey { mission, peer };
        if state.shutdown {
            let observation =
                observed.then(|| completed_observation(Err(ContactOutcome::shutdown())));
            return (EventAttemptAdmission::Closed, observation);
        }
        let now = (self.shared.clock)();
        if prune_invalid_pending_cohorts(&mut state, now, None) {
            notify_capacity_progress(&self.shared);
        }
        let authority = event_cohort_authority(&state.eligibility, key, now);
        if authority.is_empty() {
            let generation = event_authority_change_generation(&state.eligibility, key);
            let observation = observed.then(|| {
                completed_observation(Err(ContactOutcome::authority_changed(generation)))
            });
            return (EventAttemptAdmission::Closed, observation);
        }
        if retention == EventAttemptRetention::CallerOwned && state.outbound_suspended {
            let outcome = ContactOutcome::policy_suspended(state.outbound_policy_generation);
            let observation = observed.then(|| completed_observation(Err(outcome)));
            return (EventAttemptAdmission::Closed, observation);
        }
        if observed {
            if let Some(in_flight) = state
                .attempt_in_flight
                .as_ref()
                .filter(|attempt| {
                    attempt.key == key
                        && attempt.authority == authority
                        && attempt.revocation.borrow().is_none()
                })
            {
                return (
                    EventAttemptAdmission::Retained,
                    Some(observe_completion(&in_flight.completion)),
                );
            }
            if let Some(pending) = state
                .pending
                .iter()
                .find(|cohort| cohort.key == key && cohort.authority == authority)
            {
                return (
                    EventAttemptAdmission::Retained,
                    Some(observe_completion(&pending.completion)),
                );
            }
        }
        if state.pending.len() + usize::from(state.attempt_in_flight.is_some())
            >= MAX_PENDING_EVENT_COHORTS
        {
            let completion = observed
                .then(|| completed_observation(Err(ContactOutcome::admission_busy())));
            return (EventAttemptAdmission::CapacityFull, completion);
        }
        let runner: EventAttemptRunner = Arc::new(move |contact| Box::pin(runner(contact)));
        let (completion, observation) = event_attempt_completion();
        state.pending.push_back(PendingEventCohort {
            key,
            runner,
            retention,
            authority,
            completion,
            failed_instances: BTreeMap::new(),
            mailbox_full_instances: BTreeMap::new(),
            ready_at: None,
        });
        transition(&self.shared, &mut state);
        (
            EventAttemptAdmission::Accepted,
            observed.then_some(observation),
        )
    }

    pub(crate) fn subscribe_capacity_progress(&self) -> watch::Receiver<u64> {
        self.shared.capacity_progress.subscribe()
    }

    pub(crate) fn set_outbound_suspended(&self, suspended: bool) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.outbound_suspended == suspended {
            return;
        }
        state.outbound_suspended = suspended;
        state.outbound_policy_generation = state.outbound_policy_generation.saturating_add(1);
        let outcome = ContactOutcome::policy_suspended(state.outbound_policy_generation);
        let pending_before = state.pending.len();
        if suspended {
            if let Some(attempt) = &state.attempt_in_flight {
                revoke_attempt(attempt, outcome);
            }
            state.pending.retain_mut(|cohort| {
                complete_attempt(&cohort.completion, Err(outcome));
                if cohort.retention == EventAttemptRetention::DurableGeneration {
                    cohort.completion = event_attempt_completion().0;
                    true
                } else {
                    false
                }
            });
        }
        let released_capacity = state.pending.len() < pending_before;
        transition(&self.shared, &mut state);
        drop(state);
        if released_capacity {
            notify_capacity_progress(&self.shared);
        }
    }

    pub(crate) fn shutdown(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.shutdown {
            return;
        }
        state.shutdown = true;
        let outcome = ContactOutcome::shutdown();
        if let Some(attempt) = &state.attempt_in_flight {
            revoke_attempt(attempt, outcome);
        }
        state.authority_expiry_wake = None;
        let released_capacity = !state.pending.is_empty();
        for cohort in state.pending.drain(..) {
            complete_attempt(&cohort.completion, Err(outcome));
        }
        drop(state);
        if released_capacity {
            notify_capacity_progress(&self.shared);
        }
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

/// Opaque paired ownership returned by one adapter registration.
pub struct EventAdapterRegistration {
    initial_snapshot: EventAdapterSnapshot,
    control: EventAdapterControl,
    attempts: EventAttemptReceiver,
}

impl EventAdapterRegistration {
    /// Returns the exact snapshot atomically installed with this registration.
    pub const fn initial_snapshot(&self) -> EventAdapterSnapshot {
        self.initial_snapshot
    }

    /// Consumes the opaque pairing for one transport adapter owner.
    pub fn into_parts(
        self,
    ) -> (
        EventAdapterSnapshot,
        EventAdapterControl,
        EventAttemptReceiver,
    ) {
        (self.initial_snapshot, self.control, self.attempts)
    }
}

/// Adapter-owned availability publisher and registration lease.
pub struct EventAdapterControl {
    shared: Weak<AutomaticEventTransportShared>,
    kind: EventTransportKind,
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
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
        if !Arc::ptr_eq(&adapter.registration_identity, &self.registration_identity)
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
        if let Some(attempt) = &state.attempt_in_flight
            && attempt.kind == self.kind
            && Arc::ptr_eq(
                &attempt.registration_identity,
                &self.registration_identity,
            )
        {
            revoke_attempt(
                attempt,
                ContactOutcome::adapter_epoch_ended(attempt.availability_epoch),
            );
        }
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
        if state.adapters.get(&self.kind).is_some_and(|adapter| {
            Arc::ptr_eq(&adapter.registration_identity, &self.registration_identity)
        }) {
            if let Some(attempt) = &state.attempt_in_flight
                && attempt.kind == self.kind
                && Arc::ptr_eq(
                    &attempt.registration_identity,
                    &self.registration_identity,
                )
            {
                revoke_attempt(
                    attempt,
                    ContactOutcome::adapter_epoch_ended(attempt.availability_epoch),
                );
            }
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
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
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
                    .is_some_and(|instance| instance.has_registration(&self.registration_identity))
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
    registration_identity: Arc<EventAdapterRegistrationIdentity>,
    availability_epoch: u64,
    authority: EventCohortAuthority,
    runner: EventAttemptRunner,
    retention: EventAttemptRetention,
    completion: EventAttemptCompletionSource,
    revocation: watch::Receiver<Option<ContactOutcome>>,
    bound_revocation: Option<ContactOutcome>,
    failed_instances: BTreeMap<EventTransportKind, EventAdapterInstance>,
    completed: bool,
}

/// Closed ambiguous evidence available before a carrier contact opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnauthenticatedCarrierOpenFailure {
    /// The carrier open was interrupted without proving adapter loss.
    Interrupted,
    /// The carrier open exceeded its bounded deadline without proving adapter loss.
    TimedOut,
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

    /// Returns whether current authority still permits this carrier open.
    #[doc(hidden)]
    pub fn carrier_open_is_authorized(&self) -> bool {
        self.current_revocation_outcome().is_none()
    }

    fn current_revocation_outcome(&self) -> Option<ContactOutcome> {
        if let Some(outcome) = self.bound_revocation {
            return Some(outcome);
        }
        if let Some(outcome) = *self.revocation.borrow() {
            return Some(outcome);
        }
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !self.owns_in_flight_slot(&state) || state.shutdown {
            return Some(ContactOutcome::shutdown());
        }
        if state.outbound_suspended {
            return Some(ContactOutcome::policy_suspended(
                state.outbound_policy_generation,
            ));
        }
        if !state.adapters.get(&self.kind).is_some_and(|adapter| {
            Arc::ptr_eq(&adapter.registration_identity, &self.registration_identity)
                && adapter.snapshot.availability_epoch == self.availability_epoch
                && adapter.snapshot.state == EventAdapterState::Available
                && adapter.snapshot.event_capable
        })
        {
            return Some(ContactOutcome::adapter_epoch_ended(
                self.availability_epoch,
            ));
        }
        (event_cohort_authority(&state.eligibility, self.key, (self.shared.clock)())
            != self.authority)
            .then(|| {
                ContactOutcome::authority_changed(
                    event_authority_change_generation(&state.eligibility, self.key)
                        .max(event_cohort_authority_generation(&self.authority)),
                )
            })
    }

    fn bind_revocation_outcome(&mut self, proposed: ContactOutcome) -> ContactOutcome {
        if let Some(outcome) = self.bound_revocation.or(*self.revocation.borrow()) {
            self.bound_revocation = Some(outcome);
            return outcome;
        }
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.owns_in_flight_slot(&state)
            && let Some(attempt) = &state.attempt_in_flight
        {
            revoke_attempt(attempt, proposed);
        }
        let outcome = (*self.revocation.borrow()).unwrap_or(proposed);
        drop(state);
        self.bound_revocation = Some(outcome);
        outcome
    }

    /// Waits for the typed lifecycle outcome that revokes this issued attempt.
    #[doc(hidden)]
    pub async fn revocation_outcome(&mut self) -> ContactOutcome {
        loop {
            if let Some(outcome) = self.current_revocation_outcome() {
                return self.bind_revocation_outcome(outcome);
            }
            let Some(expiry) = next_event_cohort_expiry(&self.authority) else {
                if self.revocation.changed().await.is_err() {
                    return self.bind_revocation_outcome(ContactOutcome::shutdown());
                }
                continue;
            };
            let Ok(until_expiry) = expiry.duration_since((self.shared.clock)()) else {
                let outcome = ContactOutcome::authority_changed(
                    event_cohort_authority_generation(&self.authority),
                );
                return self.bind_revocation_outcome(outcome);
            };
            tokio::select! {
                _ = tokio::time::sleep(until_expiry) => {
                    let outcome = ContactOutcome::authority_changed(
                        event_cohort_authority_generation(&self.authority),
                    );
                    return self.bind_revocation_outcome(outcome);
                }
                changed = self.revocation.changed() => {
                    if changed.is_err() {
                        return self.bind_revocation_outcome(ContactOutcome::shutdown());
                    }
                }
            }
        }
    }

    /// Completes an issued ticket with the exact lifecycle revocation observed.
    #[doc(hidden)]
    pub fn finish_revoked(mut self, _observed_outcome: ContactOutcome) {
        if let Some(outcome) = self.current_revocation_outcome() {
            let _ = self.complete(&Err(outcome));
        }
    }

    /// Runs this fresh contact through the node-owned ordered Event admission.
    pub async fn run(mut self, contact: Arc<dyn OrderedContact>) -> Result<(), ContactOutcome> {
        if let Some(outcome) = self.current_revocation_outcome() {
            let outcome = self.bind_revocation_outcome(outcome);
            contact.close();
            return self.complete_run(&Err(outcome), contact.as_ref(), true);
        }
        let runner = (Arc::clone(&self.runner))(Arc::clone(&contact));
        tokio::pin!(runner);
        let (result, contact_closed) = tokio::select! {
            biased;
            outcome = self.revocation_outcome() => {
                contact.close();
                (Err(outcome), true)
            }
            result = &mut runner => (result, false),
        };
        self.complete_run(&result, contact.as_ref(), contact_closed)
    }

    /// Completes carrier opening with locally proven adapter unavailability.
    pub fn fail_carrier_open(mut self) -> ContactOutcome {
        let outcome = self
            .current_revocation_outcome()
            .unwrap_or_else(ContactOutcome::carrier_open_unavailable);
        self.complete_closed(outcome)
    }

    /// Completes an ambiguous or unauthenticated carrier-open failure.
    ///
    /// This never authorizes immediate alternate-carrier selection. Durable
    /// work remains retained only under the generic custody rules.
    pub fn fail_unauthenticated_carrier_open(
        mut self,
        failure: UnauthenticatedCarrierOpenFailure,
    ) -> ContactOutcome {
        let reason = match failure {
            UnauthenticatedCarrierOpenFailure::Interrupted => {
                ContactReason::TransportInterrupted
            }
            UnauthenticatedCarrierOpenFailure::TimedOut => ContactReason::TransportTimeout,
        };
        let outcome = self
            .current_revocation_outcome()
            .unwrap_or_else(|| ContactOutcome::unauthenticated_carrier_open(reason));
        self.complete_closed(outcome)
    }

    /// Completes caller cancellation while the carrier is still opening.
    pub fn cancel_carrier_open(mut self) -> ContactOutcome {
        let outcome = self
            .current_revocation_outcome()
            .unwrap_or_else(|| ContactOutcome::caller_cancelled(ContactStage::CarrierOpen));
        self.complete_closed(outcome)
    }

    fn owns_in_flight_slot(&self, state: &AutomaticEventTransportState) -> bool {
        state.attempt_in_flight.as_ref().is_some_and(|attempt| {
            Arc::ptr_eq(&attempt.identity, &self.identity) && attempt.key == self.key
        })
    }

    fn retain_durable_generation(
        &mut self,
        state: &mut AutomaticEventTransportState,
        ready_at: Option<tokio::time::Instant>,
        exclude_selected_instance: bool,
    ) -> bool {
        if self.retention != EventAttemptRetention::DurableGeneration
            || event_cohort_authority(&state.eligibility, self.key, (self.shared.clock)())
                != self.authority
        {
            return false;
        }
        if exclude_selected_instance {
            self.failed_instances.insert(
                self.kind,
                EventAdapterInstance::new(
                    &self.registration_identity,
                    self.availability_epoch,
                ),
            );
        }
        state.pending.push_back(PendingEventCohort {
            key: self.key,
            runner: Arc::clone(&self.runner),
            retention: self.retention,
            authority: self.authority.clone(),
            completion: event_attempt_completion().0,
            failed_instances: std::mem::take(&mut self.failed_instances),
            mailbox_full_instances: BTreeMap::new(),
            ready_at,
        });
        true
    }

    fn complete_closed(&mut self, outcome: ContactOutcome) -> ContactOutcome {
        self.complete(&Err(outcome))
            .expect_err("a closed attempt cannot replace a successful completion")
    }

    fn complete(&mut self, proposed: &EventAttemptResult) -> EventAttemptResult {
        self.complete_inner(proposed, None)
    }

    fn complete_run(
        &mut self,
        proposed: &EventAttemptResult,
        contact: &dyn OrderedContact,
        contact_closed: bool,
    ) -> EventAttemptResult {
        self.complete_inner(proposed, (!contact_closed).then_some(contact))
    }

    fn complete_inner(
        &mut self,
        proposed: &EventAttemptResult,
        close_on_revocation: Option<&dyn OrderedContact>,
    ) -> EventAttemptResult {
        let shared = Arc::clone(&self.shared);
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.completed = true;
        if !self.owns_in_flight_slot(&state) {
            if (self.bound_revocation.is_some() || self.revocation.borrow().is_some())
                && let Some(contact) = close_on_revocation
            {
                contact.close();
            }
            let completed = *self.completion.borrow();
            return completed.unwrap_or(*proposed);
        }
        let revocation = self.bound_revocation.or_else(|| {
            state
                .attempt_in_flight
                .as_ref()
                .and_then(|attempt| *attempt.revocation.borrow())
        });
        if revocation.is_some()
            && let Some(contact) = close_on_revocation
        {
            contact.close();
        }
        let result = revocation.map_or(*proposed, Err);
        state.attempt_in_flight = None;
        complete_attempt(&self.completion, result);
        let mut retry_deadline = None;
        let retained = match &result {
            Err(outcome) if outcome.permits_reselection() => {
                self.retain_durable_generation(&mut state, None, true)
            }
            Err(outcome) if outcome.disposition() == ContactDisposition::RetryLater => {
                let ready_at = tokio::time::Instant::now() + RETRY_LATER_READINESS_DELAY;
                let retained =
                    self.retain_durable_generation(&mut state, Some(ready_at), false);
                if retained {
                    retry_deadline = Some(ready_at);
                }
                retained
            }
            Err(outcome) if outcome.reason() == ContactReason::PolicySuspended => {
                self.retain_durable_generation(&mut state, None, false)
            }
            Ok(()) | Err(_) => false,
        };
        transition(&shared, &mut state);
        drop(state);
        if let Some(deadline) = retry_deadline {
            schedule_retry_later_readiness(&self.shared, deadline);
        } else if !retained {
            notify_capacity_progress(&self.shared);
        }
        result
    }
}

impl Drop for EventOutboundAttempt {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let outcome = self
            .current_revocation_outcome()
            .unwrap_or_else(|| ContactOutcome::caller_cancelled(ContactStage::Candidate));
        let _ = self.complete(&Err(outcome));
    }
}

fn notify_capacity_progress(shared: &AutomaticEventTransportShared) {
    shared
        .capacity_progress
        .send_modify(|generation| *generation = generation.saturating_add(1));
}

fn schedule_retry_later_readiness(
    shared: &Arc<AutomaticEventTransportShared>,
    deadline: tokio::time::Instant,
) {
    let shared = Arc::downgrade(shared);
    tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let now = tokio::time::Instant::now();
        if state
            .pending
            .iter()
            .any(|cohort| cohort.ready_at.is_some_and(|ready_at| ready_at <= now))
        {
            transition(&shared, &mut state);
        }
    });
}

fn schedule_authority_expiry(
    shared: &Arc<AutomaticEventTransportShared>,
    state: &mut AutomaticEventTransportState,
    now: SystemTime,
) {
    let pending_expiry = state
        .pending
        .iter()
        .filter_map(|cohort| next_event_cohort_expiry(&cohort.authority))
        .min();
    let in_flight_expiry = state
        .attempt_in_flight
        .as_ref()
        .and_then(|attempt| next_event_cohort_expiry(&attempt.authority));
    let next_expiry = pending_expiry.into_iter().chain(in_flight_expiry).min();
    let Some(next_expiry) = next_expiry else {
        state.authority_expiry_wake = None;
        return;
    };
    if state
        .authority_expiry_wake
        .is_some_and(|scheduled| scheduled <= next_expiry)
    {
        return;
    }
    let Ok(delay) = next_expiry.duration_since(now) else {
        state.authority_expiry_wake = None;
        return;
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        state.authority_expiry_wake = None;
        return;
    };
    state.authority_expiry_wake = Some(next_expiry);
    let shared = Arc::downgrade(shared);
    runtime.spawn(async move {
        tokio::time::sleep(delay).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.authority_expiry_wake != Some(next_expiry) {
            return;
        }
        state.authority_expiry_wake = None;
        transition(&shared, &mut state);
    });
}

fn transition(
    shared: &Arc<AutomaticEventTransportShared>,
    state: &mut AutomaticEventTransportState,
) {
    state.transition_count = state.transition_count.saturating_add(1);
    let now = (shared.clock)();
    if let Some(attempt) = &state.attempt_in_flight
        && event_cohort_authority(&state.eligibility, attempt.key, now) != attempt.authority
    {
        let generation = event_authority_change_generation(&state.eligibility, attempt.key)
            .max(event_cohort_authority_generation(&attempt.authority));
        revoke_attempt(attempt, ContactOutcome::authority_changed(generation));
    }
    if prune_invalid_pending_cohorts(state, now, None) {
        notify_capacity_progress(shared);
    }
    schedule_authority_expiry(shared, state, now);
    if state.attempt_in_flight.is_some() || state.outbound_suspended || state.shutdown {
        return;
    }
    let readiness_now = tokio::time::Instant::now();
    let pending_count = state.pending.len();
    for _ in 0..pending_count {
        let Some(mut pending) = state.pending.pop_front() else {
            break;
        };
        if pending
            .ready_at
            .is_some_and(|ready_at| ready_at > readiness_now)
        {
            state.pending.push_back(pending);
            continue;
        }
        pending.ready_at = None;
        loop {
            let snapshots: Vec<_> = state
                .adapters
                .values()
                .filter(|adapter| {
                    !pending.excludes(
                        adapter.snapshot.kind,
                        &adapter.registration_identity,
                        adapter.snapshot.availability_epoch,
                    )
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
            let Some((registration_identity, availability_epoch, attempts)) =
                state.adapters.get(&kind).map(|adapter| {
                    (
                        Arc::clone(&adapter.registration_identity),
                        adapter.snapshot.availability_epoch,
                        adapter.attempts.clone(),
                    )
                })
            else {
                continue;
            };
            let identity = Arc::new(EventAttemptIdentity);
            let (revocation, revocation_receiver) = watch::channel(None);
            let attempt = EventOutboundAttempt {
                shared: Arc::clone(shared),
                identity: Arc::clone(&identity),
                key: pending.key,
                kind,
                registration_identity: Arc::clone(&registration_identity),
                availability_epoch,
                authority: pending.authority.clone(),
                runner: Arc::clone(&pending.runner),
                retention: pending.retention,
                completion: pending.completion.clone(),
                revocation: revocation_receiver,
                bound_revocation: None,
                failed_instances: pending.failed_instances.clone(),
                completed: false,
            };
            match attempts.try_send(attempt) {
                Ok(()) => {
                    state.attempt_in_flight = Some(InFlightEventAttempt {
                        identity,
                        key: pending.key,
                        kind,
                        registration_identity,
                        availability_epoch,
                        authority: pending.authority,
                        completion: pending.completion,
                        revocation,
                    });
                    return;
                }
                Err(mpsc::error::TrySendError::Full(mut attempt)) => {
                    attempt.completed = true;
                    pending.mailbox_full_instances.insert(
                        kind,
                        EventAdapterInstance::new(&registration_identity, availability_epoch),
                    );
                }
                Err(mpsc::error::TrySendError::Closed(mut attempt)) => {
                    attempt.completed = true;
                    if state.adapters.get(&kind).is_some_and(|adapter| {
                        Arc::ptr_eq(&adapter.registration_identity, &registration_identity)
                    }) {
                        state.adapters.remove(&kind);
                    }
                }
            }
        }
        state.pending.push_back(pending);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_contact::{
        CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler,
        TransientLocator,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

    struct CloseTrackingContact {
        closed: Arc<AtomicBool>,
    }

    impl OrderedContact for CloseTrackingContact {
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

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }
    }

    fn provisioned_eligibility(
        kind: EventTransportKind,
        authority_generation: u64,
        revocation_generation: u64,
        expires_at: Option<SystemTime>,
    ) -> EventPeerEligibility {
        EventPeerEligibility::provisioned_exact_peer(
            MISSION,
            PEER,
            kind,
            true,
            authority_generation,
            revocation_generation,
            expires_at,
        )
    }

    fn register_available(
        handle: &AutomaticEventTransportHandle,
        kind: EventTransportKind,
        priority: u16,
    ) -> (EventAdapterControl, EventAttemptReceiver) {
        handle
            .register(EventAdapterSnapshot::new(
                kind,
                1,
                EventAdapterState::Available,
                true,
                priority,
            ))
            .expect("available test adapter")
    }

    fn eligible_ble_handle() -> (
        AutomaticEventTransportHandle,
        EventAdapterControl,
        EventAttemptReceiver,
    ) {
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            None,
        )]));
        let (control, attempts) =
            register_available(&handle, EventTransportKind::BLE_L2CAP_V1, 10);
        (handle, control, attempts)
    }

    #[tokio::test(start_paused = true)]
    async fn late_observer_receives_the_issued_attempt_completion() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        let ticket = attempts.recv().await.expect("durable attempt is issued");
        let unused_runner = Arc::new(AtomicU64::new(0));
        let observed_runner = Arc::clone(&unused_runner);

        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed_runner = Arc::clone(&observed_runner);
                async move {
                    observed_runner.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            });
        assert_eq!(admission, EventAttemptAdmission::Retained);
        assert_eq!(ticket.run(Arc::new(TestOrderedContact)).await, Ok(()));
        assert_eq!(observation.wait().await, Ok(()));
        assert_eq!(unused_runner.load(Ordering::Acquire), 0);

        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn caller_owned_attempt_is_one_shot_but_durable_generation_remains_pending() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        let caller_runs = Arc::new(AtomicU64::new(0));
        let observed_caller_runs = Arc::clone(&caller_runs);
        let retry_later = ContactOutcome::pre_auth_remote(ContactReason::AuthenticationFailed);
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed_caller_runs = Arc::clone(&observed_caller_runs);
                async move {
                    observed_caller_runs.fetch_add(1, Ordering::AcqRel);
                    Err(retry_later)
                }
            });
        assert_eq!(admission, EventAttemptAdmission::Accepted);

        let durable_runs = Arc::new(AtomicU64::new(0));
        let observed_durable_runs = Arc::clone(&durable_runs);
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, move |_contact| {
                let observed_durable_runs = Arc::clone(&observed_durable_runs);
                async move {
                    observed_durable_runs.fetch_add(1, Ordering::AcqRel);
                    Err(retry_later)
                }
            }),
            EventAttemptAdmission::Accepted
        );

        assert_eq!(
            attempts
                .recv()
                .await
                .expect("caller-owned attempt")
                .run(Arc::new(TestOrderedContact))
                .await,
            Err(retry_later)
        );
        assert_eq!(observation.wait().await, Err(retry_later));
        assert_eq!(caller_runs.load(Ordering::Acquire), 1);

        let durable = attempts
            .recv()
            .await
            .expect("durable generation retains independent custody");
        assert_eq!(
            durable.run(Arc::new(TestOrderedContact)).await,
            Err(retry_later)
        );
        assert_eq!(durable_runs.load(Ordering::Acquire), 1);
        let state = handle.shared.state.lock().unwrap();
        assert_eq!(state.pending.len(), 1);
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn adapter_epoch_revocation_releases_slot_and_retains_durable_generation() {
        let (handle, control, mut attempts) = eligible_ble_handle();
        let runs = Arc::new(AtomicU64::new(0));
        let observed_runs = Arc::clone(&runs);
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, move |_contact| {
                let observed_runs = Arc::clone(&observed_runs);
                async move {
                    observed_runs.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            }),
            EventAttemptAdmission::Accepted
        );
        let mut ticket = attempts.recv().await.expect("issued durable attempt");
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Retained);

        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Unavailable,
            true,
            10,
        )));
        let outcome = ticket.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::adapter_epoch_ended(1));
        ticket.finish_revoked(outcome);
        assert_eq!(observation.wait().await, Err(outcome));
        assert_eq!(runs.load(Ordering::Acquire), 0);
        {
            let state = handle.shared.state.lock().unwrap();
            assert_eq!(state.pending.len(), 1);
            assert!(state.attempt_in_flight.is_none());
        }

        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            3,
            EventAdapterState::Available,
            true,
            10,
        )));
        let replacement = attempts
            .recv()
            .await
            .expect("released slot admits the retained durable generation");
        assert_eq!(replacement.transport_kind(), EventTransportKind::BLE_L2CAP_V1);
        assert_eq!(replacement.peer(), PEER);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_authority_revocation_releases_capacity_without_running() {
        let handle = AutomaticEventTransportHandle::new();
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            None,
        )]));
        let runs = Arc::new(AtomicU64::new(0));
        let observed_runs = Arc::clone(&runs);
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed_runs = Arc::clone(&observed_runs);
                async move {
                    observed_runs.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            });
        assert_eq!(admission, EventAttemptAdmission::Accepted);
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

        assert!(handle.replace_eligibility(Vec::new()));
        progress
            .changed()
            .await
            .expect("authority pruning reports bounded-capacity progress");
        assert_eq!(
            observation.wait().await,
            Err(ContactOutcome::authority_changed(1))
        );
        assert_eq!(runs.load(Ordering::Acquire), 0);
        {
            let state = handle.shared.state.lock().unwrap();
            assert!(state.pending.is_empty());
            assert!(state.attempt_in_flight.is_none());
        }

        let replacement_peer = [0x33; 32];
        assert!(handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                replacement_peer,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                2,
                0,
                None,
            ),
        ]));
        assert_eq!(
            handle.request_attempt_admission(MISSION, replacement_peer, |_contact| async {
                Ok(())
            }),
            EventAttemptAdmission::Accepted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_and_revoked_peers_cannot_fill_pending_capacity() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        let expired_peer = [0x33; 32];
        let revoked_peer = [0x44; 32];
        assert!(handle.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                expired_peer,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                2,
                0,
                Some(now),
            ),
            EventPeerEligibility::provisioned_exact_peer(
                MISSION,
                revoked_peer,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                3,
                3,
                None,
            ),
        ]));
        let runs = Arc::new(AtomicU64::new(0));

        for (peer, generation) in [(expired_peer, 2), (revoked_peer, 3)]
            .into_iter()
            .cycle()
            .take(MAX_PENDING_EVENT_COHORTS * 2)
        {
            let observed_runs = Arc::clone(&runs);
            let (admission, observation) =
                handle.request_observed_attempt(MISSION, peer, move |_contact| {
                    let observed_runs = Arc::clone(&observed_runs);
                    async move {
                        observed_runs.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    }
                });
            assert_eq!(admission, EventAttemptAdmission::Closed);
            assert_eq!(
                observation.wait().await,
                Err(ContactOutcome::authority_changed(generation))
            );
        }
        assert_eq!(runs.load(Ordering::Acquire), 0);
        {
            let state = handle.shared.state.lock().unwrap();
            assert!(state.pending.is_empty());
            assert!(state.attempt_in_flight.is_none());
        }

        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            4,
            0,
            None,
        )]));
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        assert_eq!(handle.shared.state.lock().unwrap().pending.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn active_runner_revocation_closes_contact_and_completes_observer() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let started_sender = Arc::new(Mutex::new(Some(started_sender)));
        let runner_sender = Arc::clone(&started_sender);
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let runner_sender = Arc::clone(&runner_sender);
                async move {
                    if let Some(started_sender) = runner_sender
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .take()
                    {
                        let _ = started_sender.send(());
                    }
                    std::future::pending::<Result<(), ContactOutcome>>().await
                }
            });
        assert_eq!(admission, EventAttemptAdmission::Accepted);
        let ticket = attempts.recv().await.expect("caller-owned attempt");
        let closed = Arc::new(AtomicBool::new(false));
        let contact = Arc::new(CloseTrackingContact {
            closed: Arc::clone(&closed),
        });
        let run = tokio::spawn(async move { ticket.run(contact).await });
        started_receiver.await.expect("runner started");

        handle.set_outbound_suspended(true);
        let outcome = ContactOutcome::policy_suspended(1);
        assert_eq!(run.await.expect("attempt task"), Err(outcome));
        assert_eq!(observation.wait().await, Err(outcome));
        assert!(closed.load(Ordering::Acquire));
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pre_revoked_ticket_does_not_construct_the_runner_future() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        let constructions = Arc::new(AtomicU64::new(0));
        let observed_constructions = Arc::clone(&constructions);
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                observed_constructions.fetch_add(1, Ordering::AcqRel);
                std::future::ready(Ok(()))
            });
        assert_eq!(admission, EventAttemptAdmission::Accepted);
        let ticket = attempts.recv().await.expect("caller-owned attempt");
        handle.set_outbound_suspended(true);
        let outcome = ContactOutcome::policy_suspended(1);
        let closed = Arc::new(AtomicBool::new(false));

        assert_eq!(
            ticket
                .run(Arc::new(CloseTrackingContact {
                    closed: Arc::clone(&closed),
                }))
                .await,
            Err(outcome)
        );

        assert_eq!(observation.wait().await, Err(outcome));
        assert_eq!(constructions.load(Ordering::Acquire), 0);
        assert!(closed.load(Ordering::Acquire));
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn timer_revocation_stays_bound_when_wall_clock_does_not_advance() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            Some(now + Duration::from_secs(1)),
        )]));
        let (_control, mut attempts) =
            register_available(&handle, EventTransportKind::BLE_L2CAP_V1, 10);
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        let mut ticket = attempts.recv().await.expect("durable attempt");
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Retained);

        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            ticket.revocation_outcome(),
        )
        .await
        .expect("Tokio authority deadline fires");
        assert_eq!(outcome, ContactOutcome::authority_changed(1));
        ticket.finish_revoked(outcome);

        assert_eq!(observation.wait().await, Err(outcome));
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn finish_revoked_uses_the_ticket_bound_first_outcome() {
        let (handle, control, mut attempts) = eligible_ble_handle();
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        let mut ticket = attempts.recv().await.expect("durable attempt");
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Retained);
        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Unavailable,
            true,
            10,
        )));
        let actual = ticket.revocation_outcome().await;
        assert_eq!(actual, ContactOutcome::adapter_epoch_ended(1));

        ticket.finish_revoked(ContactOutcome::caller_cancelled(ContactStage::Candidate));

        assert_eq!(observation.wait().await, Err(actual));
        let state = handle.shared.state.lock().unwrap();
        assert_eq!(state.pending.len(), 1);
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn completion_custody_uses_the_first_ticket_revocation() {
        let (handle, control, mut attempts) = eligible_ble_handle();
        assert_eq!(
            handle.request_attempt_admission(MISSION, PEER, |_contact| async { Ok(()) }),
            EventAttemptAdmission::Accepted
        );
        let mut ticket = attempts.recv().await.expect("durable attempt");
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Retained);
        assert!(control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Unavailable,
            true,
            10,
        )));
        let actual = ContactOutcome::adapter_epoch_ended(1);
        let closed = Arc::new(AtomicBool::new(false));
        let contact = CloseTrackingContact {
            closed: Arc::clone(&closed),
        };

        let completed = ticket.complete_run(
            &Err(ContactOutcome::caller_cancelled(ContactStage::Candidate)),
            &contact,
            false,
        );

        assert_eq!(completed, Err(actual));
        assert_eq!(observation.wait().await, Err(actual));
        assert!(closed.load(Ordering::Acquire));
        let state = handle.shared.state.lock().unwrap();
        assert_eq!(state.pending.len(), 1);
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_authority_observer_does_not_coalesce_with_revoked_attempt() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        let (first_admission, first_observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(first_admission, EventAttemptAdmission::Accepted);
        let mut old_ticket = attempts.recv().await.expect("old authority attempt");
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            0,
            None,
        )]));

        let fresh_runs = Arc::new(AtomicU64::new(0));
        let observed_fresh_runs = Arc::clone(&fresh_runs);
        let (fresh_admission, fresh_observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed_fresh_runs = Arc::clone(&observed_fresh_runs);
                async move {
                    observed_fresh_runs.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            });
        assert_eq!(fresh_admission, EventAttemptAdmission::Accepted);

        let old_outcome = old_ticket.revocation_outcome().await;
        assert_eq!(old_outcome, ContactOutcome::authority_changed(2));
        old_ticket.finish_revoked(old_outcome);
        assert_eq!(first_observation.wait().await, Err(old_outcome));
        let fresh_ticket = attempts.recv().await.expect("fresh authority attempt");
        assert_eq!(fresh_ticket.run(Arc::new(TestOrderedContact)).await, Ok(()));
        assert_eq!(fresh_observation.wait().await, Ok(()));
        assert_eq!(fresh_runs.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn caller_owned_admission_during_suspension_closes_without_a_slot() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        handle.set_outbound_suspended(true);
        let runs = Arc::new(AtomicU64::new(0));
        let observed_runs = Arc::clone(&runs);

        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed_runs = Arc::clone(&observed_runs);
                async move {
                    observed_runs.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            });

        assert_eq!(admission, EventAttemptAdmission::Closed);
        assert_eq!(
            observation.wait().await,
            Err(ContactOutcome::policy_suspended(1))
        );
        assert_eq!(runs.load(Ordering::Acquire), 0);
        assert!(attempts.receiver.try_recv().is_err());
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn caller_owned_reselect_is_one_shot() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Accepted);

        let outcome = attempts
            .recv()
            .await
            .expect("caller-owned attempt")
            .fail_carrier_open();

        assert_eq!(outcome, ContactOutcome::carrier_open_unavailable());
        assert_eq!(observation.wait().await, Err(outcome));
        assert!(attempts.receiver.try_recv().is_err());
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_cohort_closes_when_exact_authority_changes() {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let handle = AutomaticEventTransportHandle::with_clock(move || now);
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            None,
        )]));
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Accepted);

        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            Some(now + Duration::from_secs(100)),
        )]));

        assert_eq!(
            observation.wait().await,
            Err(ContactOutcome::authority_changed(1))
        );
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_authority_expiry_completes_without_unrelated_transition() {
        let now = Arc::new(Mutex::new(UNIX_EPOCH + Duration::from_secs(100)));
        let clock = Arc::clone(&now);
        let handle = AutomaticEventTransportHandle::with_clock(move || {
            *clock.lock().unwrap_or_else(|error| error.into_inner())
        });
        assert!(handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            Some(UNIX_EPOCH + Duration::from_secs(101)),
        )]));
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, |_contact| async { Ok(()) });
        assert_eq!(admission, EventAttemptAdmission::Accepted);

        *now.lock().unwrap_or_else(|error| error.into_inner()) =
            UNIX_EPOCH + Duration::from_secs(101);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            observation.wait().await,
            Err(ContactOutcome::authority_changed(1))
        );
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
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

    fn stale_control_and_fresh_registration() -> (
        AutomaticEventTransportHandle,
        EventAdapterControl,
        EventAdapterControl,
        EventAttemptReceiver,
    ) {
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
        let (stale_control, stale_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("stale registration");
        drop(stale_attempts);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));

        let (fresh_control, fresh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("fresh registration");
        assert!(!Arc::ptr_eq(
            &stale_control.registration_identity,
            &fresh_control.registration_identity,
        ));
        (handle, stale_control, fresh_control, fresh_attempts)
    }

    #[test]
    fn stale_control_cannot_publish_to_fresh_same_kind_registration() {
        let (_handle, stale_control, fresh_control, _fresh_attempts) =
            stale_control_and_fresh_registration();

        assert!(
            !stale_control.publish_availability(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                2,
                EventAdapterState::Unavailable,
                true,
                10,
            ))
        );
        assert!(
            fresh_control.publish_availability(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                2,
                EventAdapterState::Available,
                true,
                10,
            ))
        );
    }

    #[test]
    fn stale_control_drop_cannot_remove_fresh_same_kind_registration() {
        let (_handle, stale_control, fresh_control, _fresh_attempts) =
            stale_control_and_fresh_registration();

        drop(stale_control);
        assert!(
            fresh_control.publish_availability(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                2,
                EventAdapterState::Available,
                true,
                10,
            ))
        );
    }

    #[tokio::test]
    async fn stale_receiver_dequeue_cannot_clear_fresh_registration_marker() {
        let fresh_ticket_peer = [0x33; 32];
        let pending_peer = [0x44; 32];
        let ble_ticket_peer = [0x55; 32];
        let eligibility = |peer, kind| {
            EventPeerEligibility::provisioned_exact_peer(MISSION, peer, kind, true, 1, 0, None)
        };
        let handle = AutomaticEventTransportHandle::new();
        assert!(
            handle.replace_eligibility(vec![eligibility(PEER, EventTransportKind::IROH_QUIC_V1,)])
        );
        let (stale_control, mut stale_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("stale Iroh registration");
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(handle.replace_eligibility(vec![
            eligibility(fresh_ticket_peer, EventTransportKind::IROH_QUIC_V1),
            eligibility(pending_peer, EventTransportKind::IROH_QUIC_V1),
            eligibility(ble_ticket_peer, EventTransportKind::BLE_L2CAP_V1),
        ]));
        drop(stale_control);

        let (fresh_control, _fresh_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("fresh Iroh registration");
        let (_ble_control, _ble_attempts) = handle
            .register(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Available,
                true,
                10,
            ))
            .expect("BLE registration");
        assert!(handle.request_attempt(MISSION, fresh_ticket_peer, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, pending_peer, |_contact| async { Ok(()) }));
        assert!(handle.request_attempt(MISSION, ble_ticket_peer, |_contact| async { Ok(()) }));
        assert!(handle.replace_eligibility(vec![
            eligibility(pending_peer, EventTransportKind::IROH_QUIC_V1),
            eligibility(ble_ticket_peer, EventTransportKind::BLE_L2CAP_V1),
        ]));

        let marker_matches_fresh = || {
            let state = handle
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state
                .pending
                .iter()
                .find(|cohort| cohort.key.peer == pending_peer)
                .and_then(|cohort| {
                    cohort
                        .mailbox_full_instances
                        .get(&EventTransportKind::IROH_QUIC_V1)
                })
                .is_some_and(|instance| instance.matches(&fresh_control.registration_identity, 1))
        };
        assert!(marker_matches_fresh(), "fresh Iroh full marker is present");

        assert_eq!(
            stale_attempts
                .recv()
                .await
                .expect("stale buffered attempt")
                .peer(),
            PEER
        );
        assert!(
            marker_matches_fresh(),
            "stale receiver dequeue must not clear the fresh Iroh marker"
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

    #[tokio::test]
    async fn ambiguous_carrier_open_completion_retries_later_without_alternate_selection() {
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
        let outcome = selected
            .fail_unauthenticated_carrier_open(UnauthenticatedCarrierOpenFailure::Interrupted);

        assert_eq!(outcome.stage(), ContactStage::CarrierOpen);
        assert_eq!(outcome.scope(), ContactScope::Locator);
        assert_eq!(
            outcome.provenance(),
            ContactProvenance::UnauthenticatedRemote
        );
        assert_eq!(outcome.disposition(), ContactDisposition::RetryLater);
        assert_eq!(outcome.reason(), ContactReason::TransportInterrupted);
        assert!(ble_attempts.receiver.try_recv().is_err());
        assert!(iroh_attempts.receiver.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn ambiguous_carrier_open_retries_once_after_private_readiness_deadline() {
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

        iroh_attempts
            .recv()
            .await
            .unwrap()
            .fail_unauthenticated_carrier_open(UnauthenticatedCarrierOpenFailure::Interrupted);

        assert!(iroh_attempts.receiver.try_recv().is_err());
        assert!(ble_attempts.receiver.try_recv().is_err());
        {
            let state = handle.shared.state.lock().unwrap();
            assert_eq!(
                state.pending.len() + usize::from(state.attempt_in_flight.is_some()),
                1,
                "RetryLater retains exactly the already-admitted cohort"
            );
        }

        tokio::time::advance(Duration::from_millis(249)).await;
        tokio::task::yield_now().await;
        assert!(iroh_attempts.receiver.try_recv().is_err());
        assert!(ble_attempts.receiver.try_recv().is_err());

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let fresh = iroh_attempts
            .receiver
            .try_recv()
            .expect("one normal selection runs when readiness matures");
        assert_eq!(fresh.transport_kind(), EventTransportKind::IROH_QUIC_V1);
        assert!(ble_attempts.receiver.try_recv().is_err());
        {
            let state = handle.shared.state.lock().unwrap();
            assert_eq!(
                state.pending.len() + usize::from(state.attempt_in_flight.is_some()),
                1,
                "the deferred retry consumes no additional cohort capacity"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_carrier_open_completion_never_selects_an_alternate() {
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
        let outcome = selected.cancel_carrier_open();

        assert_eq!(outcome.disposition(), ContactDisposition::Cancelled);
        assert_eq!(outcome.reason(), ContactReason::CallerCancelled);
        assert!(ble_attempts.receiver.try_recv().is_err());
        assert!(iroh_attempts.receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn same_peer_authority_replacement_revokes_issued_ticket() {
        let handle = AutomaticEventTransportHandle::new();
        let eligibility = |authority_generation, revocation_generation| {
            provisioned_eligibility(
                EventTransportKind::BLE_L2CAP_V1,
                authority_generation,
                revocation_generation,
                None,
            )
        };
        handle.replace_eligibility(vec![eligibility(1, 0)]);
        let (_control, mut attempts) =
            register_available(&handle, EventTransportKind::BLE_L2CAP_V1, 10);
        let runs = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&runs);
        let (admission, observation) =
            handle.request_observed_attempt(MISSION, PEER, move |_contact| {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            });
        assert_eq!(admission, EventAttemptAdmission::Accepted);
        let mut ticket = attempts.recv().await.unwrap();

        handle.replace_eligibility(vec![eligibility(1, 1)]);

        let outcome = ticket.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::authority_changed(1));
        ticket.finish_revoked(outcome);
        assert_eq!(observation.wait().await, Err(outcome));
        assert_eq!(runs.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn outbound_policy_suspension_revokes_and_reversibly_gates_selection() {
        let (handle, _control, mut attempts) = eligible_ble_handle();
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let mut ticket = attempts.recv().await.unwrap();

        handle.set_outbound_suspended(true);
        let outcome = ticket.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::policy_suspended(1));
        ticket.finish_revoked(outcome);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        assert!(attempts.receiver.try_recv().is_err());

        handle.set_outbound_suspended(false);
        attempts
            .recv()
            .await
            .expect("resuming outbound selection releases retained work");
    }

    #[tokio::test(start_paused = true)]
    async fn eligibility_expiry_after_issue_revokes_ticket_before_run() {
        let now = Arc::new(Mutex::new(UNIX_EPOCH + Duration::from_secs(100)));
        let clock = Arc::clone(&now);
        let handle = AutomaticEventTransportHandle::with_clock(move || {
            *clock.lock().unwrap_or_else(|error| error.into_inner())
        });
        handle.replace_eligibility(vec![provisioned_eligibility(
            EventTransportKind::BLE_L2CAP_V1,
            1,
            0,
            Some(UNIX_EPOCH + Duration::from_secs(101)),
        )]);
        let (_control, mut attempts) =
            register_available(&handle, EventTransportKind::BLE_L2CAP_V1, 10);
        assert!(handle.request_attempt(MISSION, PEER, |_contact| async { Ok(()) }));
        let mut ticket = attempts.recv().await.unwrap();

        *now.lock().unwrap_or_else(|error| error.into_inner()) =
            UNIX_EPOCH + Duration::from_secs(101);
        let outcome = ticket.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::authority_changed(1));
        ticket.finish_revoked(outcome);
        let state = handle.shared.state.lock().unwrap();
        assert!(state.pending.is_empty());
        assert!(state.attempt_in_flight.is_none());
    }

    #[test]
    fn paired_registration_retains_the_exact_initial_snapshot() {
        let handle = AutomaticEventTransportHandle::new();
        let initial = EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            0,
            EventAdapterState::Unavailable,
            true,
            7,
        );

        let registration = handle
            .register_paired(initial)
            .expect("first paired registration is admitted");

        assert_eq!(registration.initial_snapshot(), initial);
        let (snapshot, _control, _attempts) = registration.into_parts();
        assert_eq!(snapshot, initial);
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
    async fn removed_in_flight_attempt_retains_slot_until_obsolete_ticket_drops() {
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
        assert!(
            attempts.receiver.try_recv().is_err(),
            "revocation must not admit a concurrent carrier open while the obsolete ticket lives"
        );
        drop(obsolete);
        let current = attempts
            .recv()
            .await
            .expect("replacement runs after obsolete ticket custody is released");
        assert_eq!(current.peer(), replacement_peer);

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
    async fn finishing_buffered_revocation_wakes_replacement_without_other_event() {
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
        let mut obsolete = attempts
            .recv()
            .await
            .expect("buffered obsolete ticket remains adapter-visible");
        assert_eq!(obsolete.peer(), PEER);
        let outcome = obsolete.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::authority_changed(1));
        obsolete.finish_revoked(outcome);
        let replacement = attempts
            .recv()
            .await
            .expect("typed revocation completion wakes the replacement cohort");
        assert_eq!(replacement.peer(), replacement_peer);
    }

    #[tokio::test]
    async fn obsolete_mailbox_preserves_the_global_slot_until_revocation_finishes() {
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
        assert!(ble_attempts.receiver.try_recv().is_err());
        let mut obsolete = iroh_attempts
            .recv()
            .await
            .expect("obsolete Iroh ticket remains buffered");
        assert_eq!(obsolete.peer(), PEER);
        let outcome = obsolete.revocation_outcome().await;
        assert_eq!(outcome, ContactOutcome::authority_changed(1));
        obsolete.finish_revoked(outcome);
        let replacement = iroh_attempts
            .recv()
            .await
            .expect("ordinary selection resumes after typed revocation completion");
        assert_eq!(replacement.peer(), replacement_peer);
        assert_eq!(replacement.transport_kind(), EventTransportKind::IROH_QUIC_V1);
        assert!(ble_attempts.receiver.try_recv().is_err());
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
        assert_eq!(
            obsolete.fail_carrier_open(),
            ContactOutcome::authority_changed(1)
        );

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
            0
        );
    }
}
