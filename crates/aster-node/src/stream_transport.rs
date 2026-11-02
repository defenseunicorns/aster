//! Internal selection and recovery for one active streaming transport.

use aster_iroh::{BoundedReceiveStream, BoundedSendStream, Connection, SelectedPath};
use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct StreamTransportId(u16);

impl StreamTransportId {
    pub(crate) const IROH_QUIC_V1: Self = Self(1);

    pub(crate) const fn new(value: u16) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateHealth {
    Unavailable,
    Unknown,
    Degraded,
    Healthy,
}
impl CandidateHealth {
    const fn rank(self) -> u8 {
        match self {
            Self::Unavailable => 0,
            Self::Unknown => 1,
            Self::Degraded => 2,
            Self::Healthy => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedSupportSource {
    ProvisionedPeer,
    AuthenticatedConfiguration,
    AuthenticatedDiscovery,
    MissionSessionNegotiation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedPeerSupport {
    source: AuthenticatedSupportSource,
    stream_v1: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedTransportContext {
    pub locally_enabled: bool,
    pub policy_allowed: bool,
    pub peer_support: Option<AuthenticatedPeerSupport>,
    pub configured_priority: i16,
}
impl AuthenticatedPeerSupport {
    pub(crate) const fn new(source: AuthenticatedSupportSource, stream_v1: bool) -> Self {
        Self { source, stream_v1 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportCandidate {
    pub id: StreamTransportId,
    pub locally_enabled: bool,
    pub policy_allowed: bool,
    pub peer_support: Option<AuthenticatedPeerSupport>,
    pub reliable_ordered: bool,
    pub full_duplex: bool,
    pub health: CandidateHealth,
    pub configured_priority: i16,
}

pub(crate) struct TransportAdapterCandidate {
    pub candidate: TransportCandidate,
    pub adapter: Arc<dyn StreamTransportAdapter>,
}

struct RegisteredStreamTransport {
    context: AuthenticatedTransportContext,
    adapter: Arc<dyn StreamTransportAdapter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamTransportRegistrationError {
    DuplicateId(StreamTransportId),
}

#[derive(Default)]
pub(crate) struct StreamTransportRegistry {
    registrations: Vec<RegisteredStreamTransport>,
}

impl StreamTransportRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            registrations: Vec::new(),
        }
    }

    pub(crate) fn register(
        &mut self,
        adapter: Arc<dyn StreamTransportAdapter>,
        context: AuthenticatedTransportContext,
    ) -> Result<(), StreamTransportRegistrationError> {
        let id = adapter.id();
        if self
            .registrations
            .iter()
            .any(|registered| registered.adapter.id() == id)
        {
            return Err(StreamTransportRegistrationError::DuplicateId(id));
        }
        self.registrations
            .push(RegisteredStreamTransport { context, adapter });
        Ok(())
    }

    pub(crate) fn candidates(&self) -> Vec<TransportAdapterCandidate> {
        self.registrations
            .iter()
            .map(|registered| {
                let capabilities = registered.adapter.capabilities();
                TransportAdapterCandidate {
                    candidate: TransportCandidate {
                        id: registered.adapter.id(),
                        locally_enabled: registered.context.locally_enabled,
                        policy_allowed: registered.context.policy_allowed,
                        peer_support: registered.context.peer_support,
                        reliable_ordered: capabilities.reliable_ordered,
                        full_duplex: capabilities.full_duplex,
                        health: registered.adapter.health(),
                        configured_priority: registered.context.configured_priority,
                    },
                    adapter: Arc::clone(&registered.adapter),
                }
            })
            .collect()
    }

    pub(crate) fn select(
        &self,
        requirements: TransferRequirements,
    ) -> Option<Arc<dyn StreamTransportAdapter>> {
        TransportSelector::select_adapter(requirements, &self.candidates())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferRequirements {
    pub reliable_ordered: bool,
    pub full_duplex: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamTransportCapabilities {
    pub reliable_ordered: bool,
    pub full_duplex: bool,
}

impl StreamTransportCapabilities {
    const fn supports(self, requirements: TransferRequirements) -> bool {
        (!requirements.reliable_ordered || self.reliable_ordered)
            && (!requirements.full_duplex || self.full_duplex)
    }
}
impl Default for TransferRequirements {
    fn default() -> Self {
        Self {
            reliable_ordered: true,
            full_duplex: true,
        }
    }
}

pub(crate) struct TransportSelector;
impl TransportSelector {
    pub(crate) fn rank(
        requirements: TransferRequirements,
        candidates: &[TransportCandidate],
    ) -> Vec<TransportCandidate> {
        let mut ranked: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.locally_enabled
                    && candidate.policy_allowed
                    && candidate
                        .peer_support
                        .is_some_and(|support| support.stream_v1)
                    && (!requirements.reliable_ordered || candidate.reliable_ordered)
                    && (!requirements.full_duplex || candidate.full_duplex)
                    && candidate.health != CandidateHealth::Unavailable
            })
            .collect();
        ranked.sort_by(|left, right| {
            right
                .health
                .rank()
                .cmp(&left.health.rank())
                .then_with(|| right.configured_priority.cmp(&left.configured_priority))
                .then_with(|| left.id.cmp(&right.id))
        });
        ranked
    }

    pub(crate) fn select_adapter(
        requirements: TransferRequirements,
        candidates: &[TransportAdapterCandidate],
    ) -> Option<Arc<dyn StreamTransportAdapter>> {
        let descriptors = candidates
            .iter()
            .map(|candidate| candidate.candidate)
            .collect::<Vec<_>>();
        Self::rank(requirements, &descriptors)
            .into_iter()
            .find_map(|selected| {
                candidates
                    .iter()
                    .find(|candidate| {
                        candidate.candidate == selected
                            && candidate.adapter.id() == selected.id
                            && candidate.adapter.health() == selected.health
                            && candidate.adapter.eligibility(requirements)
                    })
                    .map(|candidate| Arc::clone(&candidate.adapter))
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportFailure {
    Closed,
    PositiveCreditStall,
    ControlLivenessExpired,
    Cancelled,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalOutcome {
    Protocol,
    Integrity,
    Lifecycle,
    Policy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttemptSignal {
    Transport(TransportFailure),
    ZeroCreditDataDeadline,
    Terminal(TerminalOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorAction {
    ContinueBackpressure,
    Retry {
        durable_offset: u64,
        checkpoint_generation: u64,
    },
    Terminal(TerminalOutcome),
    Exhausted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptAuthority {
    pub peer_authenticated: bool,
    pub mission_authenticated: bool,
    pub semantic_version: u16,
    pub profile_id: u16,
    pub transcript: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub custody_age_ms: Option<u64>,
    pub durable_offset: u64,
    pub checkpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorConfig {
    pub retry_budget: u8,
    pub positive_credit_stall: Duration,
    pub control_liveness: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorError {
    ActiveAttempt,
    Authentication,
    Replay,
    YoungerCustody,
    CheckpointRegression,
}

pub(crate) struct AttemptCoordinator {
    config: CoordinatorConfig,
    attempts: u8,
    active: bool,
    last_transcript: Option<[u8; 32]>,
    last_nonce: Option<[u8; 32]>,
    custody_age_ms: Option<u64>,
    durable_offset: u64,
    checkpoint_generation: u64,
}

impl AttemptCoordinator {
    pub(crate) const fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            attempts: 0,
            active: false,
            last_transcript: None,
            last_nonce: None,
            custody_age_ms: None,
            durable_offset: 0,
            checkpoint_generation: 0,
        }
    }

    pub(crate) fn begin(&mut self, authority: AttemptAuthority) -> Result<(), CoordinatorError> {
        if self.active {
            return Err(CoordinatorError::ActiveAttempt);
        }
        if !authority.peer_authenticated
            || !authority.mission_authenticated
            || authority.semantic_version != 9
            || authority.profile_id != 5
            || authority.transcript.iter().all(|byte| *byte == 0)
            || authority.attempt_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(CoordinatorError::Authentication);
        }
        if self.last_transcript == Some(authority.transcript)
            || self.last_nonce == Some(authority.attempt_nonce)
        {
            return Err(CoordinatorError::Replay);
        }
        if self
            .custody_age_ms
            .zip(authority.custody_age_ms)
            .is_some_and(|(previous, next)| next < previous)
        {
            return Err(CoordinatorError::YoungerCustody);
        }
        if authority.durable_offset < self.durable_offset
            || authority.checkpoint_generation < self.checkpoint_generation
        {
            return Err(CoordinatorError::CheckpointRegression);
        }
        self.attempts = self.attempts.saturating_add(1);
        self.active = true;
        self.last_transcript = Some(authority.transcript);
        self.last_nonce = Some(authority.attempt_nonce);
        self.custody_age_ms = match (self.custody_age_ms, authority.custody_age_ms) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        self.durable_offset = authority.durable_offset;
        self.checkpoint_generation = authority.checkpoint_generation;
        Ok(())
    }

    pub(crate) fn checkpoint(
        &mut self,
        offset: u64,
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        if offset < self.durable_offset
            || generation < self.checkpoint_generation
            || (offset > self.durable_offset) != (generation > self.checkpoint_generation)
        {
            return Err(CoordinatorError::CheckpointRegression);
        }
        self.durable_offset = offset;
        self.checkpoint_generation = generation;
        Ok(())
    }

    pub(crate) fn signal(&mut self, signal: AttemptSignal) -> CoordinatorAction {
        match signal {
            AttemptSignal::ZeroCreditDataDeadline => CoordinatorAction::ContinueBackpressure,
            AttemptSignal::Terminal(outcome) => {
                self.active = false;
                CoordinatorAction::Terminal(outcome)
            }
            AttemptSignal::Transport(TransportFailure::Cancelled) => {
                self.active = false;
                CoordinatorAction::Cancelled
            }
            AttemptSignal::Transport(TransportFailure::Exhausted) => {
                self.active = false;
                CoordinatorAction::Exhausted
            }
            AttemptSignal::Transport(_) => {
                self.active = false;
                if self.attempts > self.config.retry_budget {
                    CoordinatorAction::Exhausted
                } else {
                    CoordinatorAction::Retry {
                        durable_offset: self.durable_offset,
                        checkpoint_generation: self.checkpoint_generation,
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptOpenRequest {
    pub deadline: Instant,
    pub max_data_bytes: u64,
    pub max_control_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamTransportError {
    Ineligible,
    Timeout,
    Closed,
    Bounds,
}

impl std::fmt::Display for StreamTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StreamTransportError {}

pub(crate) type AdapterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, StreamTransportError>> + Send + 'a>>;

pub(crate) trait StreamAttempt: Send + Sync {
    fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn send_data_parts<'a>(&'a self, prefix: &'a [u8], body: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>>;
    fn finish_data(&self) -> AdapterFuture<'_, ()>;
    /// Synchronously signals cancellation of the DATA half.
    ///
    /// Every adapter must make an in-flight send cancellation-safe: dropping
    /// that send after this signal closes or resets the peer-visible DATA
    /// stream without requiring another async poll.
    fn cancel_data(&self);
}

pub(crate) trait StreamReceiveAttempt: Send + Sync {
    fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>>;
    fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn finish_control(&self) -> AdapterFuture<'_, ()>;
}

pub(crate) trait StreamTransportAdapter: Send + Sync {
    fn id(&self) -> StreamTransportId;
    fn capabilities(&self) -> StreamTransportCapabilities;
    fn eligibility(&self, requirements: TransferRequirements) -> bool {
        self.capabilities().supports(requirements)
    }
    fn health(&self) -> CandidateHealth;
    fn open_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>>;
    fn accept_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>>;
}

pub(crate) struct IrohQuicV1Adapter {
    connection: Connection,
}
impl IrohQuicV1Adapter {
    pub(crate) const fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

struct IrohSenderAttempt {
    data: Mutex<BoundedSendStream>,
    control: Mutex<BoundedReceiveStream>,
    data_cancelled: AtomicBool,
}

struct IrohDataOperation<'a> {
    stream: tokio::sync::MutexGuard<'a, BoundedSendStream>,
    complete: bool,
}

impl Deref for IrohDataOperation<'_> {
    type Target = BoundedSendStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for IrohDataOperation<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl Drop for IrohDataOperation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.stream.reset();
        }
    }
}

impl IrohSenderAttempt {
    async fn begin_data_operation(&self) -> Result<IrohDataOperation<'_>, StreamTransportError> {
        if self.data_cancelled.load(Ordering::Acquire) {
            return Err(StreamTransportError::Closed);
        }
        let stream = self.data.lock().await;
        if self.data_cancelled.load(Ordering::Acquire) {
            return Err(StreamTransportError::Closed);
        }
        Ok(IrohDataOperation {
            stream,
            complete: false,
        })
    }
}

struct IrohReceiverAttempt {
    data: Mutex<BoundedReceiveStream>,
    control: Mutex<BoundedSendStream>,
}

impl StreamReceiveAttempt for IrohReceiverAttempt {
    fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.data
                .lock()
                .await
                .read_frame()
                .await
                .map_err(map_iroh_error)
        })
    }
    fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .write_frame(frame)
                .await
                .map_err(map_iroh_error)
        })
    }
    fn finish_control(&self) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .finish()
                .await
                .map_err(map_iroh_error)
        })
    }
}
impl StreamAttempt for IrohSenderAttempt {
    fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let mut operation = self.begin_data_operation().await?;
            operation.write_frame(frame).await.map_err(map_iroh_error)?;
            operation.complete = true;
            Ok(())
        })
    }
    fn send_data_parts<'a>(&'a self, prefix: &'a [u8], body: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let mut operation = self.begin_data_operation().await?;
            operation
                .write_frame_parts(prefix, body)
                .await
                .map_err(map_iroh_error)?;
            operation.complete = true;
            Ok(())
        })
    }
    fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .read_frame()
                .await
                .map_err(map_iroh_error)
        })
    }
    fn finish_data(&self) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            let mut operation = self.begin_data_operation().await?;
            operation.finish().await.map_err(map_iroh_error)?;
            operation.complete = true;
            Ok(())
        })
    }

    fn cancel_data(&self) {
        self.data_cancelled.store(true, Ordering::Release);
        if let Ok(mut stream) = self.data.try_lock() {
            let _ = stream.reset();
        }
    }
}

impl StreamTransportAdapter for IrohQuicV1Adapter {
    fn id(&self) -> StreamTransportId {
        StreamTransportId::IROH_QUIC_V1
    }
    fn capabilities(&self) -> StreamTransportCapabilities {
        StreamTransportCapabilities {
            reliable_ordered: true,
            full_duplex: true,
        }
    }
    fn health(&self) -> CandidateHealth {
        match self.connection.path_witness().selected {
            SelectedPath::Unknown => CandidateHealth::Unknown,
            SelectedPath::Direct | SelectedPath::Relay => CandidateHealth::Healthy,
        }
    }
    fn open_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
        Box::pin(async move {
            let pair = self
                .connection
                .open_stream_pair(
                    request.deadline,
                    request.max_data_bytes,
                    request.max_control_bytes,
                )
                .await
                .map_err(map_iroh_error)?;
            Ok(Arc::new(IrohSenderAttempt {
                data: Mutex::new(pair.data),
                control: Mutex::new(pair.control),
                data_cancelled: AtomicBool::new(false),
            }) as Arc<dyn StreamAttempt>)
        })
    }

    fn accept_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
        Box::pin(async move {
            let pair = self
                .connection
                .accept_stream_pair(
                    request.deadline,
                    request.max_data_bytes,
                    request.max_control_bytes,
                )
                .await
                .map_err(map_iroh_error)?;
            Ok(Arc::new(IrohReceiverAttempt {
                data: Mutex::new(pair.data),
                control: Mutex::new(pair.control),
            }) as Arc<dyn StreamReceiveAttempt>)
        })
    }
}

fn map_iroh_error(error: aster_iroh::CarrierError) -> StreamTransportError {
    match error {
        aster_iroh::CarrierError::Timeout(_) => StreamTransportError::Timeout,
        aster_iroh::CarrierError::FrameTooLarge { .. }
        | aster_iroh::CarrierError::TurnTooLarge { .. } => StreamTransportError::Bounds,
        _ => StreamTransportError::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use std::collections::BTreeSet;

    fn candidate(priority: i16, health: CandidateHealth) -> TransportCandidate {
        TransportCandidate {
            id: StreamTransportId::IROH_QUIC_V1,
            locally_enabled: true,
            policy_allowed: true,
            peer_support: Some(AuthenticatedPeerSupport::new(
                AuthenticatedSupportSource::ProvisionedPeer,
                true,
            )),
            reliable_ordered: true,
            full_duplex: true,
            health,
            configured_priority: priority,
        }
    }

    #[test]
    fn stream_transport_ranking_is_deterministic_and_authenticated() {
        assert!(TransportSelector::rank(TransferRequirements::default(), &[]).is_empty());
        let mut disabled = candidate(9, CandidateHealth::Healthy);
        disabled.locally_enabled = false;
        let mut unauthenticated = candidate(8, CandidateHealth::Healthy);
        unauthenticated.peer_support = None;
        let degraded = candidate(100, CandidateHealth::Degraded);
        let healthy = candidate(1, CandidateHealth::Healthy);
        assert_eq!(
            TransportSelector::rank(
                TransferRequirements::default(),
                &[disabled, degraded, unauthenticated, healthy]
            ),
            vec![healthy, degraded]
        );
    }

    struct SelectionAdapter {
        id: StreamTransportId,
        health: CandidateHealth,
        reliable_ordered: bool,
        full_duplex: bool,
    }

    impl StreamTransportAdapter for SelectionAdapter {
        fn id(&self) -> StreamTransportId {
            self.id
        }

        fn capabilities(&self) -> StreamTransportCapabilities {
            StreamTransportCapabilities {
                reliable_ordered: self.reliable_ordered,
                full_duplex: self.full_duplex,
            }
        }

        fn health(&self) -> CandidateHealth {
            self.health
        }

        fn open_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
            Box::pin(async { Ok(Arc::new(SelectionAttempt) as Arc<dyn StreamAttempt>) })
        }

        fn accept_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
            Box::pin(async { Err(StreamTransportError::Closed) })
        }
    }

    struct SelectionAttempt;

    impl StreamAttempt for SelectionAttempt {
        fn send_data<'a>(&'a self, _frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn send_data_parts<'a>(
            &'a self,
            _prefix: &'a [u8],
            _body: &'a [u8],
        ) -> AdapterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async { Ok(None) })
        }

        fn finish_data(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn cancel_data(&self) {}
    }

    #[test]
    fn stream_transport_selector_returns_best_eligible_adapter() {
        let unavailable = Arc::new(SelectionAdapter {
            id: StreamTransportId::IROH_QUIC_V1,
            health: CandidateHealth::Healthy,
            reliable_ordered: true,
            full_duplex: true,
        });
        let degraded: Arc<dyn StreamTransportAdapter> = Arc::new(SelectionAdapter {
            id: StreamTransportId::IROH_QUIC_V1,
            health: CandidateHealth::Degraded,
            reliable_ordered: true,
            full_duplex: true,
        });
        let healthy: Arc<dyn StreamTransportAdapter> = Arc::new(SelectionAdapter {
            id: StreamTransportId::IROH_QUIC_V1,
            health: CandidateHealth::Healthy,
            reliable_ordered: true,
            full_duplex: true,
        });

        let selected = TransportSelector::select_adapter(
            TransferRequirements::default(),
            &[
                TransportAdapterCandidate {
                    candidate: TransportCandidate {
                        policy_allowed: false,
                        ..candidate(100, CandidateHealth::Healthy)
                    },
                    adapter: unavailable,
                },
                TransportAdapterCandidate {
                    candidate: candidate(10, CandidateHealth::Degraded),
                    adapter: Arc::clone(&degraded),
                },
                TransportAdapterCandidate {
                    candidate: candidate(1, CandidateHealth::Healthy),
                    adapter: Arc::clone(&healthy),
                },
            ],
        )
        .expect("one adapter is eligible");

        assert!(Arc::ptr_eq(&selected, &healthy));
        assert!(!Arc::ptr_eq(&selected, &degraded));
    }

    #[tokio::test]
    async fn registry_selects_independent_adapter_by_authenticated_requirements_and_rank() {
        let registered_id = |value| StreamTransportId::new(value).expect("nonzero stable ID");
        let context = |policy_allowed, priority| AuthenticatedTransportContext {
            locally_enabled: true,
            policy_allowed,
            peer_support: Some(AuthenticatedPeerSupport::new(
                AuthenticatedSupportSource::MissionSessionNegotiation,
                true,
            )),
            configured_priority: priority,
        };
        let adapter = |id, health, reliable_ordered, full_duplex| {
            Arc::new(SelectionAdapter {
                id,
                health,
                reliable_ordered,
                full_duplex,
            }) as Arc<dyn StreamTransportAdapter>
        };
        let mut registry = StreamTransportRegistry::new();
        registry
            .register(
                adapter(registered_id(1), CandidateHealth::Degraded, true, true),
                context(true, 100),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(2), CandidateHealth::Healthy, true, true),
                context(true, 7),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(3), CandidateHealth::Healthy, true, true),
                context(true, 7),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(4), CandidateHealth::Healthy, true, false),
                context(true, 100),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(5), CandidateHealth::Healthy, true, true),
                context(false, 100),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(6), CandidateHealth::Unavailable, true, true),
                context(true, 100),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(7), CandidateHealth::Healthy, true, true),
                context(true, 6),
            )
            .unwrap();
        registry
            .register(
                adapter(registered_id(8), CandidateHealth::Healthy, true, true),
                AuthenticatedTransportContext {
                    peer_support: None,
                    ..context(true, 100)
                },
            )
            .unwrap();

        let ranked = TransportSelector::rank(
            TransferRequirements::default(),
            &registry
                .candidates()
                .into_iter()
                .map(|candidate| candidate.candidate)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            ranked
                .iter()
                .map(|candidate| candidate.id)
                .collect::<Vec<_>>(),
            [
                registered_id(2),
                registered_id(3),
                registered_id(7),
                registered_id(1),
            ]
        );

        let selected = registry
            .select(TransferRequirements::default())
            .expect("one independently usable adapter is eligible");
        assert_eq!(selected.id(), registered_id(2));

        let attempt = selected
            .open_attempt(AttemptOpenRequest {
                deadline: Instant::now() + Duration::from_secs(1),
                max_data_bytes: 16,
                max_control_bytes: 16,
            })
            .await
            .expect("selected adapter creates its own attempt");
        attempt.send_data(b"not-iroh").await.unwrap();
    }

    #[test]
    fn registry_keeps_reliable_and_full_duplex_capabilities_independent() {
        let reliable_id = StreamTransportId::new(9).unwrap();
        let full_duplex_id = StreamTransportId::new(10).unwrap();
        let context = AuthenticatedTransportContext {
            locally_enabled: true,
            policy_allowed: true,
            peer_support: Some(AuthenticatedPeerSupport::new(
                AuthenticatedSupportSource::ProvisionedPeer,
                true,
            )),
            configured_priority: 0,
        };
        let mut registry = StreamTransportRegistry::new();
        registry
            .register(
                Arc::new(SelectionAdapter {
                    id: reliable_id,
                    health: CandidateHealth::Healthy,
                    reliable_ordered: true,
                    full_duplex: false,
                }),
                context,
            )
            .unwrap();
        registry
            .register(
                Arc::new(SelectionAdapter {
                    id: full_duplex_id,
                    health: CandidateHealth::Healthy,
                    reliable_ordered: false,
                    full_duplex: true,
                }),
                context,
            )
            .unwrap();

        let reliable_only = TransferRequirements {
            reliable_ordered: true,
            full_duplex: false,
        };
        let reliable_candidates = registry.candidates();
        let reliable = reliable_candidates
            .iter()
            .find(|candidate| candidate.candidate.id == reliable_id)
            .unwrap();
        assert!(reliable.candidate.reliable_ordered);
        assert!(!reliable.candidate.full_duplex);
        assert_eq!(registry.select(reliable_only).unwrap().id(), reliable_id);

        let full_duplex_only = TransferRequirements {
            reliable_ordered: false,
            full_duplex: true,
        };
        let full_duplex_candidates = registry.candidates();
        let full_duplex = full_duplex_candidates
            .iter()
            .find(|candidate| candidate.candidate.id == full_duplex_id)
            .unwrap();
        assert!(!full_duplex.candidate.reliable_ordered);
        assert!(full_duplex.candidate.full_duplex);
        assert_eq!(
            registry.select(full_duplex_only).unwrap().id(),
            full_duplex_id
        );
    }

    fn authority(seed: u8, age: u64, offset: u64, generation: u64) -> AttemptAuthority {
        AttemptAuthority {
            peer_authenticated: true,
            mission_authenticated: true,
            semantic_version: 9,
            profile_id: 5,
            transcript: [seed; 32],
            attempt_nonce: [seed.wrapping_add(1); 32],
            custody_age_ms: Some(age),
            durable_offset: offset,
            checkpoint_generation: generation,
        }
    }

    #[test]
    fn stream_transport_coordinator_retries_only_from_authenticated_durable_progress() {
        let mut coordinator = AttemptCoordinator::new(CoordinatorConfig {
            retry_budget: 2,
            positive_credit_stall: Duration::from_secs(3),
            control_liveness: Duration::from_secs(1),
        });
        coordinator.begin(authority(1, 50, 0, 0)).unwrap();
        coordinator.checkpoint(8, 1).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(TransportFailure::Closed)),
            CoordinatorAction::Retry {
                durable_offset: 8,
                checkpoint_generation: 1
            }
        );
        assert!(matches!(
            coordinator.begin(authority(1, 50, 8, 1)),
            Err(CoordinatorError::Replay)
        ));
        assert!(matches!(
            coordinator.begin(authority(2, 49, 8, 1)),
            Err(CoordinatorError::YoungerCustody)
        ));
        coordinator.begin(authority(3, 50, 8, 1)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::ZeroCreditDataDeadline),
            CoordinatorAction::ContinueBackpressure
        );
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(
                TransportFailure::ControlLivenessExpired
            )),
            CoordinatorAction::Retry {
                durable_offset: 8,
                checkpoint_generation: 1
            }
        );
        coordinator.begin(authority(5, 51, 8, 1)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(
                TransportFailure::PositiveCreditStall
            )),
            CoordinatorAction::Exhausted
        );
    }

    #[test]
    fn stream_transport_terminal_cancel_and_checkpoint_rules_are_typed() {
        let mut coordinator = AttemptCoordinator::new(CoordinatorConfig {
            retry_budget: 3,
            positive_credit_stall: Duration::from_secs(3),
            control_liveness: Duration::from_secs(1),
        });
        coordinator.begin(authority(7, 10, 0, 0)).unwrap();
        assert!(coordinator.checkpoint(4, 0).is_err());
        assert_eq!(
            coordinator.signal(AttemptSignal::Terminal(TerminalOutcome::Integrity)),
            CoordinatorAction::Terminal(TerminalOutcome::Integrity)
        );
        coordinator.begin(authority(9, 10, 0, 0)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(TransportFailure::Cancelled)),
            CoordinatorAction::Cancelled
        );
    }

    #[test]
    fn stream_iroh_adapter_reports_one_production_transport() {
        assert_eq!(StreamTransportId::IROH_QUIC_V1.get(), 1);
    }

    #[tokio::test]
    async fn stream_iroh_adapter_reopens_a_fresh_concurrent_pair() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().unwrap());
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.unwrap();
                for expected in [
                    b"first".as_slice(),
                    b"headerbody".as_slice(),
                    b"resume".as_slice(),
                ] {
                    let mut pair = connection
                        .accept_stream_pair(Instant::now() + Duration::from_secs(2), 64, 64)
                        .await
                        .unwrap();
                    assert_eq!(
                        pair.data.read_frame().await.unwrap().as_deref(),
                        Some(expected)
                    );
                    pair.control.write_frame(b"checkpoint").await.unwrap();
                    pair.control.finish().await.unwrap();
                    assert_eq!(pair.data.read_frame().await.unwrap(), None);
                }
            }
        });
        let address = server
            .bound_sockets()
            .into_iter()
            .find(|address| address.is_ipv4())
            .unwrap();
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .unwrap();
        let production_registry =
            crate::runtime::blob_stream::production_stream_transport_registry(connection.clone())
                .expect("production transport registration");
        let production = crate::runtime::blob_stream::select_stream_transport(&production_registry)
            .expect("Iroh remains the shipped production adapter");
        assert_eq!(production.id(), StreamTransportId::IROH_QUIC_V1);
        let adapter = IrohQuicV1Adapter::new(connection.clone());
        assert_eq!(adapter.id(), StreamTransportId::IROH_QUIC_V1);
        for (prefix, body) in [
            (b"first".as_slice(), b"".as_slice()),
            (b"header".as_slice(), b"body".as_slice()),
            (b"resume".as_slice(), b"".as_slice()),
        ] {
            let attempt = adapter
                .open_attempt(AttemptOpenRequest {
                    deadline: Instant::now() + Duration::from_secs(2),
                    max_data_bytes: 64,
                    max_control_bytes: 64,
                })
                .await
                .unwrap();
            attempt.send_data_parts(prefix, body).await.unwrap();
            assert_eq!(
                attempt.receive_control().await.unwrap().as_deref(),
                Some(b"checkpoint".as_slice())
            );
            assert_eq!(attempt.receive_control().await.unwrap(), None);
            attempt.finish_data().await.unwrap();
        }
        server_task.await.unwrap();
        connection.close();
        client.close().await;
        server.close().await;
    }
}
