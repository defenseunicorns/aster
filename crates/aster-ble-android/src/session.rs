use crate::{
    ValidationReceipt, ValidatorConfig, ValidatorError, ValidatorErrorCategory,
    validate_ring1_receipt,
};
use aster_ble_l2cap::BleL2capContact;
use aster_contact::{ContactErrorKind, OrderedContact, TransientLocator};
use aster_node::{
    ContactOutcome, ContactReason, MissionPeerExpectation, MutableSourceInterests, NodeApplication,
    NodeError, OrderedEventContactRole, RunningNode, TransportNeutralNodeConfig,
    application::{
        ApplicationError, ApplicationErrorKind, EventClientContext, EventItem, EventPublishResult,
        EventQuery, EventSubscriptionRequest, Priority, Scope, SelectedEventHandle, Topic,
    },
    mission::UnprotectedReferenceMission,
    publication_journal as numbered, start_transport_neutral_node,
};
use serde::Serialize;
use std::{
    future::Future,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::Notify;

const MAXIMUM_FRAME_BYTES: usize = 2 * 1024 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RING1_EVENT_JOURNAL_CLIENT_ID: &[u8] = b"android-btle-ring1-text/v1";
const RING1_EVENT_JOURNAL_FILE: &str = "android-btle-ring1-text-publication.redb";
const RING1_EVENT_SUBSCRIPTION_KEY: &[u8] = b"aster.android-btle-ring1.consume.v1";
const RING1_EVENT_TOPIC: &str = "mesh.messages";
const RING1_EVENT_SCOPE: &str = "demo/playground";
const RING1_TEXT_LOGICAL_KEY: &[u8] = b"android-btle-ring1/text/v1";

/// Opaque identifier for one process-local validator attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunId(u64);

impl RunId {
    pub(crate) const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn into_raw(self) -> u64 {
        self.0
    }
}

/// Sanitized foreground validator progress phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorPhase {
    /// Android has established the LE CoC and local bridge.
    CarrierConnected,
    /// The protected mission-authenticated session is running.
    Authenticating,
    /// Authentication and reconciliation completed; receipt validation is running.
    Reconciling,
}

impl ValidatorPhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CarrierConnected => "carrier_connected",
            Self::Authenticating => "authenticating",
            Self::Reconciling => "reconciling",
        }
    }
}

/// Exactly one phase update or terminal outcome.
#[derive(Clone, Debug)]
pub enum SessionEvent {
    /// Non-terminal progress update.
    Phase(ValidatorPhase),
    /// Sole terminal result for the run.
    Terminal(RunOutcome),
}

/// Terminal validator result.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    /// Exact v9 Event validation completed.
    Complete(ValidationReceipt),
    /// The run failed or was cancelled with a sanitized error.
    Failed(ValidatorError),
}

/// Receives bounded progress and one terminal result from a validator attempt.
pub trait PhaseSink: Send + Sync + 'static {
    /// Emits one immutable event. Implementations must return promptly.
    fn emit(&self, event: SessionEvent);
}

trait SessionExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        config: ValidatorConfig,
        stream: UnixStream,
        control: Arc<RunControl>,
        sink: Arc<dyn PhaseSink>,
    ) -> RunOutcome;
}

struct RealSessionExecutor;

impl SessionExecutor for RealSessionExecutor {
    fn execute(
        &self,
        config: ValidatorConfig,
        stream: UnixStream,
        control: Arc<RunControl>,
        sink: Arc<dyn PhaseSink>,
    ) -> RunOutcome {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("aster-btle-android")
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                return RunOutcome::Failed(ValidatorError::new(
                    ValidatorErrorCategory::Internal,
                    "validator runtime failed to start",
                ));
            }
        };
        match runtime.block_on(run_session(config, stream, control, sink)) {
            Ok(receipt) => RunOutcome::Complete(receipt),
            Err(error) => RunOutcome::Failed(error),
        }
    }
}

struct RunControl {
    cancelled: AtomicBool,
    cancellation: Notify,
    contact: Mutex<Option<Arc<dyn OrderedContact>>>,
    cancellation_stream: Mutex<Option<UnixStream>>,
}

impl RunControl {
    fn new(cancellation_stream: UnixStream) -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            contact: Mutex::new(None),
            cancellation_stream: Mutex::new(Some(cancellation_stream)),
        }
    }

    fn install_contact(&self, contact: Arc<dyn OrderedContact>) {
        if let Ok(mut slot) = self.contact.lock() {
            *slot = Some(contact.clone());
        }
        if self.cancelled.load(Ordering::Acquire) {
            contact.close();
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Ok(slot) = self.contact.lock()
            && let Some(contact) = slot.as_ref()
        {
            contact.close();
        }
        if let Ok(mut slot) = self.cancellation_stream.lock()
            && let Some(stream) = slot.take()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.cancellation.notify_waiters();
    }

    async fn cancelled(&self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let notified = self.cancellation.notified();
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

struct ActiveRun {
    id: RunId,
    control: Arc<RunControl>,
}

struct RegistryInner {
    active: Mutex<Option<ActiveRun>>,
    next_id: AtomicU64,
    executor: Arc<dyn SessionExecutor>,
}

/// Process-local one-at-a-time Android validator authority.
#[derive(Clone)]
pub struct RunRegistry {
    inner: Arc<RegistryInner>,
}

impl RunRegistry {
    fn new(executor: Arc<dyn SessionExecutor>) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                active: Mutex::new(None),
                next_id: AtomicU64::new(1),
                executor,
            }),
        }
    }

    /// Returns the sole process-wide production registry.
    #[must_use]
    pub fn global() -> &'static Self {
        static REGISTRY: OnceLock<RunRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| Self::new(Arc::new(RealSessionExecutor)))
    }

    /// Parses configuration before adopting and starting one descriptor-backed run.
    pub fn start_json(
        &self,
        config_json: &str,
        descriptor: OwnedFd,
        sink: Arc<dyn PhaseSink>,
    ) -> Result<RunId, ValidatorError> {
        let config = ValidatorConfig::from_json(config_json)?;
        self.start(config, descriptor, sink)
    }

    /// Starts one already-validated descriptor-backed run.
    pub fn start(
        &self,
        config: ValidatorConfig,
        descriptor: OwnedFd,
        sink: Arc<dyn PhaseSink>,
    ) -> Result<RunId, ValidatorError> {
        let stream = UnixStream::from(descriptor);
        let cancellation_stream = stream.try_clone().map_err(|_| {
            ValidatorError::new(
                ValidatorErrorCategory::Unavailable,
                "validator contact descriptor is unavailable",
            )
        })?;
        let control = Arc::new(RunControl::new(cancellation_stream));
        let id = RunId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        {
            let mut active = self.inner.active.lock().map_err(|_| {
                ValidatorError::new(
                    ValidatorErrorCategory::Internal,
                    "validator run registry is unavailable",
                )
            })?;
            if active.is_some() {
                return Err(ValidatorError::new(
                    ValidatorErrorCategory::Unavailable,
                    "validator already has an active run",
                ));
            }
            *active = Some(ActiveRun {
                id,
                control: control.clone(),
            });
        }
        let inner = self.inner.clone();
        let worker_sink = sink.clone();
        let worker_control = control.clone();
        let spawn = thread::Builder::new()
            .name("aster-btle-android-run".to_owned())
            .spawn(move || {
                let outcome = inner.executor.execute(
                    config,
                    stream,
                    worker_control.clone(),
                    worker_sink.clone(),
                );
                if let Ok(mut active) = inner.active.lock()
                    && active.as_ref().is_some_and(|active| active.id == id)
                {
                    active.take();
                }
                worker_sink.emit(SessionEvent::Terminal(outcome));
                worker_control.cancel();
            });
        if spawn.is_err() {
            control.cancel();
            if let Ok(mut active) = self.inner.active.lock()
                && active.as_ref().is_some_and(|active| active.id == id)
            {
                active.take();
            }
            return Err(ValidatorError::new(
                ValidatorErrorCategory::Internal,
                "validator worker failed to start",
            ));
        }
        Ok(id)
    }

    /// Idempotently cancels one active run.
    pub fn cancel(&self, id: RunId) -> Result<(), ValidatorError> {
        let control = self
            .inner
            .active
            .lock()
            .map_err(|_| {
                ValidatorError::new(
                    ValidatorErrorCategory::Internal,
                    "validator run registry is unavailable",
                )
            })?
            .as_ref()
            .filter(|active| active.id == id)
            .map(|active| active.control.clone());
        if let Some(control) = control {
            control.cancel();
        }
        Ok(())
    }
}

async fn run_session(
    config: ValidatorConfig,
    stream: UnixStream,
    control: Arc<RunControl>,
    sink: Arc<dyn PhaseSink>,
) -> Result<ValidationReceipt, ValidatorError> {
    sink.emit(SessionEvent::Phase(ValidatorPhase::CarrierConnected));
    stream.set_nonblocking(true).map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Unavailable,
            "validator contact descriptor is unavailable",
        )
    })?;
    let io = tokio::net::UnixStream::from_std(stream).map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Unavailable,
            "validator contact descriptor is unavailable",
        )
    })?;
    let mission = load_mission(&config)?;
    let locator = TransientLocator::new(
        format!(
            "android:{}/psm:{}",
            config.bluetooth_address(),
            config.psm()
        )
        .into_bytes(),
    )
    .map_err(map_contact_error)?;
    let contact: Arc<dyn OrderedContact> = Arc::new(
        BleL2capContact::new(io, locator, MAXIMUM_FRAME_BYTES, OPERATION_TIMEOUT)
            .map_err(map_contact_error)?,
    );
    let node = start_transport_neutral_node(node_config(&config, mission))
        .await
        .map_err(map_node_error)?;
    let publication = match await_subscription_or_cancellation(
        prepared_contact_state(&node, config.event_text()),
        control.as_ref(),
    )
    .await
    {
        Ok(publication) => publication,
        Err(error) => {
            let _ = node.shutdown().await;
            return Err(error);
        }
    };
    control.install_contact(contact.clone());
    let expectation = MissionPeerExpectation::new(contact.peer_evidence(), config.mission_peer());
    sink.emit(SessionEvent::Phase(ValidatorPhase::Authenticating));
    let contacts = node.ordered_event_contacts();
    let session = contacts.run(
        OrderedEventContactRole::Initiator,
        contact.clone(),
        expectation,
    );
    tokio::pin!(session);
    let result = tokio::select! {
        result = &mut session => result.map_err(map_ordered_contact_error),
        () = control.cancelled() => {
            contact.close();
            Err(ValidatorError::new(
                ValidatorErrorCategory::Unavailable,
                "validator contact was cancelled",
            ))
        }
    };
    let validated = match result {
        Ok(receipt) => {
            sink.emit(SessionEvent::Phase(ValidatorPhase::Reconciling));
            validate_ring1_receipt(&config, &receipt, &publication)
        }
        Err(error) => Err(error),
    };
    let shutdown = node.shutdown().await.map_err(map_node_error);
    match (validated, shutdown) {
        (Ok(receipt), Ok(_)) => Ok(receipt),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

pub(crate) struct PreparationControl {
    cancelled: AtomicBool,
    cancellation: Notify,
}

impl PreparationControl {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancellation.notify_waiters();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.cancellation.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

pub(crate) async fn prepare_local_event_cancellable(
    config: &ValidatorConfig,
    control: Option<&PreparationControl>,
) -> Result<EventPublishResult, ValidatorError> {
    tokio::time::timeout(
        OPERATION_TIMEOUT,
        prepare_local_event_inner(config, control),
    )
    .await
    .map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Timeout,
            "validator local Event preparation timed out",
        )
    })?
}

async fn prepare_local_event_inner(
    config: &ValidatorConfig,
    control: Option<&PreparationControl>,
) -> Result<EventPublishResult, ValidatorError> {
    let mission = load_mission(config)?;
    let start = start_transport_neutral_node(node_config(config, mission));
    tokio::pin!(start);
    let node = match control {
        Some(control) => tokio::select! {
            biased;
            () = control.cancelled() => return Err(preparation_cancelled()),
            result = &mut start => result,
        },
        None => start.await,
    }
    .map_err(|error| local_node_error(error, "validator local Event node could not start"))?;
    let prepared = {
        let preparation = prepare_text_event(&node, config);
        tokio::pin!(preparation);
        match control {
            Some(control) => tokio::select! {
                biased;
                () = control.cancelled() => Err(preparation_cancelled()),
                result = &mut preparation => result,
            },
            None => preparation.await,
        }
    };
    let shutdown = node
        .shutdown()
        .await
        .map_err(|error| local_node_error(error, "validator local Event node could not shut down"));
    match (prepared, shutdown) {
        (Ok(publication), Ok(_)) => Ok(publication),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn preparation_cancelled() -> ValidatorError {
    ValidatorError::new(
        ValidatorErrorCategory::Unavailable,
        "validator local Event preparation was cancelled",
    )
}

async fn prepare_text_event(
    node: &RunningNode,
    config: &ValidatorConfig,
) -> Result<EventPublishResult, ValidatorError> {
    let mut journal = node
        .open_or_initialize_publication_journal(
            Path::new(RING1_EVENT_JOURNAL_FILE),
            RING1_EVENT_JOURNAL_CLIENT_ID,
        )
        .map_err(|_| journal_error())?;
    let events = node.selected_events();
    journal
        .recover(&mut numbered::Backend::Live(&events))
        .await
        .map_err(|_| journal_error())?;
    ensure_ring1_event_subscription(
        &events,
        journal.client_context().map_err(|_| journal_error())?,
    )
    .await?;

    let intent = text_event_intent(config.event_text());
    if let Some((_, pending)) = journal.pending() {
        let retained = pending.clone();
        let retained_publication = commit_intent(&mut journal, &events, retained.clone()).await?;
        if retained == intent {
            return Ok(retained_publication);
        }
    }
    if let Some(existing) = latest_text_event(&events).await?
        && existing.payload == config.event_text().as_bytes()
    {
        return Ok(publication_from_item(existing, false));
    }
    commit_intent(&mut journal, &events, intent).await
}

fn load_mission(config: &ValidatorConfig) -> Result<UnprotectedReferenceMission, ValidatorError> {
    UnprotectedReferenceMission::load(config.mission_bundle_path()).map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Authentication,
            "validator mission bundle could not be loaded",
        )
    })
}

fn node_config(
    config: &ValidatorConfig,
    mission: UnprotectedReferenceMission,
) -> TransportNeutralNodeConfig {
    TransportNeutralNodeConfig {
        state: config.state_path().to_path_buf(),
        mission,
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_secs(60),
        run_for: None,
        application: NodeApplication::Relay,
    }
}

async fn commit_intent(
    journal: &mut numbered::Journal,
    events: &SelectedEventHandle,
    intent: numbered::Intent,
) -> Result<EventPublishResult, ValidatorError> {
    let publication = journal
        .publish_metadata(&mut numbered::Backend::Live(events), intent)
        .await
        .map_err(|_| journal_error())?;
    journal
        .acknowledge(&mut numbered::Backend::Live(events))
        .await
        .map_err(|_| journal_error())?;
    Ok(publication)
}

fn text_event_intent(text: &str) -> numbered::Intent {
    numbered::Intent {
        predecessor: None,
        topic: RING1_EVENT_TOPIC.to_owned(),
        scope: RING1_EVENT_SCOPE.to_owned(),
        priority: Priority::Priority as u8,
        logical_key: RING1_TEXT_LOGICAL_KEY.to_vec(),
        payload: text.as_bytes().to_vec(),
        tombstone: false,
        ttl_ms: None,
    }
}

async fn prepared_text_event(
    node: &RunningNode,
    text: &str,
) -> Result<EventPublishResult, ValidatorError> {
    latest_text_event(&node.selected_events())
        .await?
        .filter(|event| event.payload == text.as_bytes())
        .map(|event| publication_from_item(event, false))
        .ok_or_else(|| {
            ValidatorError::new(
                ValidatorErrorCategory::Storage,
                "validator local Event preparation is incomplete",
            )
        })
}

async fn prepared_contact_state(
    node: &RunningNode,
    text: &str,
) -> Result<EventPublishResult, ValidatorError> {
    let publication = prepared_text_event(node, text).await?;
    let subscriptions = node
        .selected_events()
        .list_subscriptions()
        .await
        .map_err(map_subscription_error)?;
    let prepared = subscriptions.iter().any(|subscription| {
        subscription.operation_key == RING1_EVENT_SUBSCRIPTION_KEY
            && subscription.topic.as_str() == RING1_EVENT_TOPIC
            && subscription.scope.as_str() == RING1_EVENT_SCOPE
            && !subscription.include_descendant_scopes
    });
    if !prepared {
        return Err(ValidatorError::new(
            ValidatorErrorCategory::Storage,
            "validator local Event preparation is incomplete",
        ));
    }
    Ok(publication)
}

async fn latest_text_event(
    events: &SelectedEventHandle,
) -> Result<Option<EventItem>, ValidatorError> {
    let mut query = EventQuery {
        publisher: Some(events.identity()),
        topic: Some(Topic::new(RING1_EVENT_TOPIC).map_err(|_| internal_subscription_error())?),
        scope: Some(Scope::new(RING1_EVENT_SCOPE).map_err(|_| internal_subscription_error())?),
        logical_key: Some(RING1_TEXT_LOGICAL_KEY.to_vec()),
        limit: 128,
        ..EventQuery::default()
    };
    let mut latest: Option<EventItem> = None;
    let mut previous_marker = query.after_acceptance_marker;
    loop {
        let page = events
            .query(query.clone())
            .await
            .map_err(map_subscription_error)?;
        for event in page.items {
            if latest
                .as_ref()
                .is_none_or(|current| event.event_sequence > current.event_sequence)
            {
                latest = Some(event);
            }
        }
        if !page.has_more {
            return Ok(latest);
        }
        if page.scanned_through <= previous_marker {
            return Err(ValidatorError::new(
                ValidatorErrorCategory::Storage,
                "validator Event query did not advance",
            ));
        }
        previous_marker = page.scanned_through;
        query.after_acceptance_marker = page.scanned_through;
    }
}

fn publication_from_item(event: EventItem, inserted: bool) -> EventPublishResult {
    EventPublishResult {
        id: event.id,
        publisher: event.publisher,
        publisher_counter: event.publisher_counter,
        event_sequence: event.event_sequence,
        priority: event.priority,
        ttl_ms: event.ttl_ms,
        acceptance_marker: event.acceptance_marker,
        inserted,
    }
}

async fn await_subscription_or_cancellation<F, T>(
    preparation: F,
    control: &RunControl,
) -> Result<T, ValidatorError>
where
    F: Future<Output = Result<T, ValidatorError>>,
{
    tokio::pin!(preparation);
    tokio::select! {
        biased;
        () = control.cancelled() => Err(ValidatorError::new(
            ValidatorErrorCategory::Unavailable,
            "validator contact was cancelled",
        )),
        result = &mut preparation => result,
    }
}

async fn ensure_ring1_event_subscription(
    events: &SelectedEventHandle,
    context: EventClientContext,
) -> Result<(), ValidatorError> {
    events
        .subscribe(EventSubscriptionRequest {
            client: context,
            operation_key: RING1_EVENT_SUBSCRIPTION_KEY.to_vec(),
            topic: Topic::new(RING1_EVENT_TOPIC).map_err(|_| internal_subscription_error())?,
            scope: Scope::new(RING1_EVENT_SCOPE).map_err(|_| internal_subscription_error())?,
            include_descendant_scopes: false,
        })
        .await
        .map_err(map_subscription_error)?;
    Ok(())
}

fn journal_error() -> ValidatorError {
    ValidatorError::new(
        ValidatorErrorCategory::Storage,
        "validator local Event publication could not be prepared",
    )
}

fn local_node_error(error: NodeError, message: &'static str) -> ValidatorError {
    ValidatorError::new(map_node_error(error).category(), message)
}

fn map_subscription_error(error: ApplicationError) -> ValidatorError {
    let category = match error.kind() {
        ApplicationErrorKind::RequestRejected
        | ApplicationErrorKind::UnauthorizedOrRevoked
        | ApplicationErrorKind::PolicyUnsettled => ValidatorErrorCategory::Authentication,
        ApplicationErrorKind::ResourceLimit
        | ApplicationErrorKind::OperationCapacity
        | ApplicationErrorKind::StateUnavailable
        | ApplicationErrorKind::Integrity
        | ApplicationErrorKind::Provisioning => ValidatorErrorCategory::Storage,
        _ => ValidatorErrorCategory::Internal,
    };
    ValidatorError::new(
        category,
        "validator Event subscription could not be prepared",
    )
}

fn internal_subscription_error() -> ValidatorError {
    ValidatorError::new(
        ValidatorErrorCategory::Internal,
        "validator Event subscription configuration is invalid",
    )
}

fn map_contact_error(error: aster_contact::ContactError) -> ValidatorError {
    let category = match error.kind() {
        ContactErrorKind::Configuration => ValidatorErrorCategory::Configuration,
        ContactErrorKind::Bounds => ValidatorErrorCategory::Bounds,
        ContactErrorKind::Unavailable | ContactErrorKind::Transport => {
            ValidatorErrorCategory::Unavailable
        }
        ContactErrorKind::Timeout => ValidatorErrorCategory::Timeout,
        ContactErrorKind::Unauthorized => ValidatorErrorCategory::Authentication,
        ContactErrorKind::Protocol | ContactErrorKind::Unsupported => {
            ValidatorErrorCategory::Protocol
        }
    };
    ValidatorError::new(category, "validator contact failed")
}

fn map_node_error(error: NodeError) -> ValidatorError {
    let category = match error {
        NodeError::Configuration(_) => ValidatorErrorCategory::Configuration,
        NodeError::Mission(_) | NodeError::Revoked(_) | NodeError::SourceEnvelope(_) => {
            ValidatorErrorCategory::Authentication
        }
        NodeError::Store(_)
        | NodeError::Io(_)
        | NodeError::MissionProvisioning(_)
        | NodeError::SoftwareErasure(_)
        | NodeError::FatalBlobCoherence(_) => ValidatorErrorCategory::Storage,
        NodeError::Carrier(_) => ValidatorErrorCategory::Unavailable,
        NodeError::Reconciliation(_)
        | NodeError::Protocol(_)
        | NodeError::EmissionPolicyChanged
        | NodeError::CustodySendSkipped => ValidatorErrorCategory::Protocol,
        NodeError::Identity(_) | NodeError::Demo(_) => ValidatorErrorCategory::Internal,
    };
    ValidatorError::new(category, "validator protected Event session failed")
}

fn map_ordered_contact_error(outcome: ContactOutcome) -> ValidatorError {
    let category = match outcome.reason() {
        ContactReason::AdmissionClosed
        | ContactReason::AdmissionBusy
        | ContactReason::ActorUnavailable
        | ContactReason::ActorStopped
        | ContactReason::CallerCancelled
        | ContactReason::CarrierUnavailable
        | ContactReason::TransportInterrupted
        | ContactReason::TransportTimeout => ValidatorErrorCategory::Unavailable,
        ContactReason::IdentityMismatch | ContactReason::AuthenticationFailed => {
            ValidatorErrorCategory::Authentication
        }
        ContactReason::PolicyRejected | ContactReason::ProtocolViolation => {
            ValidatorErrorCategory::Protocol
        }
        ContactReason::LocalInvariant => ValidatorErrorCategory::Internal,
    };
    ValidatorError::new(category, "validator ordered Event contact failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ValidatorConfig, ValidatorError, ValidatorErrorCategory};
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner, Scope, Topic};
    use aster_node::{application::EventQuery, mission::UnprotectedReferenceMission};
    use std::{
        io::Read,
        os::fd::OwnedFd,
        os::unix::net::UnixStream,
        path::PathBuf,
        sync::{Arc, Condvar, Mutex, atomic::AtomicUsize},
        time::Duration,
    };
    use tokio::io::AsyncReadExt as _;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(1);

    struct RecordingSink {
        events: Mutex<Vec<SessionEvent>>,
        changed: Condvar,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                changed: Condvar::new(),
            })
        }

        fn wait_for_terminal(&self) -> RunOutcome {
            let events = self.events.lock().expect("event lock");
            let (events, timeout) = self
                .changed
                .wait_timeout_while(events, Duration::from_secs(2), |events| {
                    !events
                        .iter()
                        .any(|event| matches!(event, SessionEvent::Terminal(_)))
                })
                .expect("terminal wait");
            assert!(!timeout.timed_out(), "terminal event timed out");
            events
                .iter()
                .find_map(|event| match event {
                    SessionEvent::Terminal(outcome) => Some(outcome.clone()),
                    SessionEvent::Phase(_) => None,
                })
                .expect("terminal event")
        }

        fn terminal_count(&self) -> usize {
            self.events
                .lock()
                .expect("event lock")
                .iter()
                .filter(|event| matches!(event, SessionEvent::Terminal(_)))
                .count()
        }
    }

    impl PhaseSink for RecordingSink {
        fn emit(&self, event: SessionEvent) {
            self.events.lock().expect("event lock").push(event);
            self.changed.notify_all();
        }
    }

    struct TerminalOrderingSink {
        peer: Mutex<UnixStream>,
        stream_open_at_terminal: Mutex<Option<bool>>,
        changed: Condvar,
    }

    impl TerminalOrderingSink {
        fn new(peer: UnixStream) -> Arc<Self> {
            peer.set_nonblocking(true).expect("nonblocking peer");
            Arc::new(Self {
                peer: Mutex::new(peer),
                stream_open_at_terminal: Mutex::new(None),
                changed: Condvar::new(),
            })
        }

        fn wait_for_result(&self) -> bool {
            let result = self.stream_open_at_terminal.lock().expect("result lock");
            let (result, timeout) = self
                .changed
                .wait_timeout_while(result, Duration::from_secs(2), |result| result.is_none())
                .expect("terminal ordering wait");
            assert!(!timeout.timed_out(), "terminal ordering timed out");
            result.expect("terminal ordering result")
        }
    }

    impl PhaseSink for TerminalOrderingSink {
        fn emit(&self, event: SessionEvent) {
            if !matches!(event, SessionEvent::Terminal(_)) {
                return;
            }
            let mut byte = [0u8; 1];
            let open = self
                .peer
                .lock()
                .expect("peer lock")
                .read(&mut byte)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock);
            *self.stream_open_at_terminal.lock().expect("result lock") = Some(open);
            self.changed.notify_all();
        }
    }

    struct ReadUntilEndExecutor;

    impl SessionExecutor for ReadUntilEndExecutor {
        fn execute(
            &self,
            _config: ValidatorConfig,
            stream: UnixStream,
            control: Arc<RunControl>,
            sink: Arc<dyn PhaseSink>,
        ) -> RunOutcome {
            sink.emit(SessionEvent::Phase(ValidatorPhase::CarrierConnected));
            stream
                .set_nonblocking(true)
                .expect("nonblocking test stream");
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(async move {
                    let mut stream =
                        tokio::net::UnixStream::from_std(stream).expect("Tokio test stream");
                    let mut byte = [0u8; 1];
                    tokio::select! {
                        result = stream.read(&mut byte) => match result {
                            Ok(0) | Err(_) => RunOutcome::Failed(ValidatorError::new(
                                ValidatorErrorCategory::Unavailable,
                                "validator contact stream ended",
                            )),
                            Ok(_) => RunOutcome::Failed(ValidatorError::new(
                                ValidatorErrorCategory::Protocol,
                                "validator fake session rejected input",
                            )),
                        },
                        () = control.cancelled() => RunOutcome::Failed(ValidatorError::new(
                            ValidatorErrorCategory::Unavailable,
                            "validator contact was cancelled",
                        )),
                    }
                })
        }
    }

    struct ImmediateTimeoutExecutor {
        calls: AtomicUsize,
    }

    impl SessionExecutor for ImmediateTimeoutExecutor {
        fn execute(
            &self,
            _config: ValidatorConfig,
            _stream: UnixStream,
            _control: Arc<RunControl>,
            _sink: Arc<dyn PhaseSink>,
        ) -> RunOutcome {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            RunOutcome::Failed(ValidatorError::new(
                ValidatorErrorCategory::Timeout,
                "validator contact timed out",
            ))
        }
    }

    struct TestConfig {
        root: PathBuf,
        state: PathBuf,
        mission: PathBuf,
        json: String,
    }

    impl TestConfig {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary directory")
                .join(format!(
                    "aster-ble-android-session-{}-{}",
                    std::process::id(),
                    NEXT_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ));
            std::fs::create_dir(&root).expect("create root");
            let mission = root.join("mission.bundle");
            let state = root.join("state");
            std::fs::write(&mission, b"mission").expect("write mission");
            let json = format!(
                concat!(
                    "{{",
                    "\"state_path\":\"{}\",",
                    "\"mission_bundle_path\":\"{}\",",
                    "\"mission_peer\":\"{}\",",
                    "\"bluetooth_address\":\"7C:FA:80:72:3B:7A\",",
                    "\"psm\":128,",
                    "\"event_text\":\"hello from Android\",",
                    "\"send_packet_bytes\":512,",
                    "\"receive_packet_bytes\":256,",
                    "\"require_event_larger_than_mtu\":true",
                    "}}"
                ),
                state.display(),
                mission.display(),
                "11".repeat(32),
            );
            Self {
                root,
                state,
                mission,
                json,
            }
        }

        fn config(&self) -> ValidatorConfig {
            ValidatorConfig::from_json(&self.json).expect("valid config")
        }

        fn config_with_text(&self, text: &str) -> ValidatorConfig {
            let json = self.json.replace(
                "\"event_text\":\"hello from Android\"",
                &format!(
                    "\"event_text\":{}",
                    serde_json::to_string(text).expect("encode test Event text")
                ),
            );
            ValidatorConfig::from_json(&json).expect("valid config with Event text")
        }
    }

    impl Drop for TestConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn pair() -> (OwnedFd, UnixStream) {
        let (native, peer) = UnixStream::pair().expect("socket pair");
        (native.into(), peer)
    }

    fn validator_mission_bundle(seed: u8, topic: &str) -> Vec<u8> {
        let topic = Topic::new(topic).expect("validator mission topic");
        let scope = Scope::new(RING1_EVENT_SCOPE).expect("validator mission scope");
        let access = ProvisioningAccess::member(scope, vec![1], vec![topic])
            .expect("validator mission access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([seed; 32]).expect("validator mission provisioner");
        provisioner
            .issue_node(1, &[access])
            .expect("validator mission bundle")
            .to_bytes()
            .expect("encode validator mission bundle")
    }

    async fn start_validator_test_node(
        state: PathBuf,
        mission: UnprotectedReferenceMission,
    ) -> RunningNode {
        start_transport_neutral_node(TransportNeutralNodeConfig {
            state,
            mission,
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_secs(60),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start validator node")
    }

    #[tokio::test]
    async fn local_text_publication_is_durable_without_a_carrier_and_retry_safe() {
        let test = TestConfig::new();
        #[cfg(unix)]
        std::fs::set_permissions(
            &test.root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("owner-only publication test root");
        std::fs::remove_file(&test.mission).expect("replace mission fixture");
        UnprotectedReferenceMission::persist(
            &test.mission,
            validator_mission_bundle(0x79, RING1_EVENT_TOPIC),
        )
        .expect("persist validator mission");
        let config = test.config();

        let first = prepare_local_event_cancellable(&config, None)
            .await
            .expect("publish without a carrier");
        let retry = prepare_local_event_cancellable(&config, None)
            .await
            .expect("retry local publication");

        assert_eq!(retry.id, first.id);
        assert_eq!(retry.event_sequence, first.event_sequence);
        let reopened = start_validator_test_node(
            test.state.clone(),
            UnprotectedReferenceMission::load(&test.mission).expect("reload validator mission"),
        )
        .await;
        let page = reopened
            .selected_events()
            .query(EventQuery {
                publisher: Some(reopened.selected_events().identity()),
                topic: Some(Topic::new(RING1_EVENT_TOPIC).expect("validator topic")),
                scope: Some(Scope::new(RING1_EVENT_SCOPE).expect("validator scope")),
                logical_key: Some(RING1_TEXT_LOGICAL_KEY.to_vec()),
                limit: 16,
                ..EventQuery::default()
            })
            .await
            .expect("query durable local publication");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, first.id);
        assert_eq!(page.items[0].payload, config.event_text().as_bytes());
        let subscriptions = reopened
            .selected_events()
            .list_subscriptions()
            .await
            .expect("list durable validator subscriptions");
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].operation_key, RING1_EVENT_SUBSCRIPTION_KEY);
        assert_eq!(subscriptions[0].topic.as_str(), RING1_EVENT_TOPIC);
        assert_eq!(subscriptions[0].scope.as_str(), RING1_EVENT_SCOPE);
        assert!(!subscriptions[0].include_descendant_scopes);
        reopened.shutdown().await.expect("shutdown reopened node");
    }

    #[tokio::test]
    async fn cancelled_local_preparation_starts_no_transport_or_node_state() {
        let test = TestConfig::new();
        #[cfg(unix)]
        std::fs::set_permissions(
            &test.root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("owner-only cancellation test root");
        std::fs::remove_file(&test.mission).expect("replace mission fixture");
        UnprotectedReferenceMission::persist(
            &test.mission,
            validator_mission_bundle(0x77, RING1_EVENT_TOPIC),
        )
        .expect("persist validator mission");
        let control = PreparationControl::new();
        control.cancel();

        let error = prepare_local_event_cancellable(&test.config(), Some(&control))
            .await
            .expect_err("cancelled preparation");

        assert_eq!(error.category(), ValidatorErrorCategory::Unavailable);
        assert!(!test.state.exists());
    }

    #[tokio::test]
    async fn changed_text_advances_the_durable_event_sequence() {
        let test = TestConfig::new();
        #[cfg(unix)]
        std::fs::set_permissions(
            &test.root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("owner-only sequence test root");
        std::fs::remove_file(&test.mission).expect("replace mission fixture");
        UnprotectedReferenceMission::persist(
            &test.mission,
            validator_mission_bundle(0x78, RING1_EVENT_TOPIC),
        )
        .expect("persist validator mission");

        let first = prepare_local_event_cancellable(&test.config_with_text("first"), None)
            .await
            .expect("publish first text");
        let second = prepare_local_event_cancellable(&test.config_with_text("second"), None)
            .await
            .expect("publish changed text");

        assert!(second.event_sequence > first.event_sequence);
        assert_ne!(second.id, first.id);
    }

    #[tokio::test]
    async fn cancellation_interrupts_subscription_preparation() {
        let (cancellation_stream, peer) = UnixStream::pair().expect("cancellation stream pair");
        let control = Arc::new(RunControl::new(cancellation_stream));
        let worker_control = control.clone();
        let waiting = tokio::spawn(async move {
            await_subscription_or_cancellation(
                std::future::pending::<Result<(), ValidatorError>>(),
                worker_control.as_ref(),
            )
            .await
        });
        tokio::task::yield_now().await;
        control.cancel();

        let error = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("subscription cancellation deadline")
            .expect("subscription cancellation task")
            .expect_err("cancelled subscription preparation");
        assert_eq!(error.category(), ValidatorErrorCategory::Unavailable);
        drop(peer);
    }

    #[tokio::test]
    async fn unauthorized_validator_selector_is_authentication_failure() {
        let test = TestConfig::new();
        #[cfg(unix)]
        std::fs::set_permissions(
            &test.root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("owner-only authorization test root");
        std::fs::remove_file(&test.mission).expect("replace mission fixture");
        UnprotectedReferenceMission::persist(
            &test.mission,
            validator_mission_bundle(0x7c, "other.topic"),
        )
        .expect("persist unauthorized validator mission");

        let error = prepare_local_event_cancellable(&test.config(), None)
            .await
            .expect_err("unauthorized validator subscription");
        assert_eq!(error.category(), ValidatorErrorCategory::Authentication);
    }

    #[test]
    fn ordered_contact_error_maps_to_validator_categories() {
        for error in [
            ContactOutcome::admission_closed(),
            ContactOutcome::admission_busy(),
            ContactOutcome::actor_unavailable(),
            ContactOutcome::actor_stopped(),
        ] {
            assert_eq!(
                map_ordered_contact_error(error).category(),
                ValidatorErrorCategory::Unavailable
            );
        }
    }

    #[test]
    fn one_active_run_rejects_overlap() {
        let test = TestConfig::new();
        let registry = RunRegistry::new(Arc::new(ReadUntilEndExecutor));
        let first_sink = RecordingSink::new();
        let (first_fd, _first_peer) = pair();
        let first = registry
            .start(test.config(), first_fd, first_sink.clone())
            .expect("first run");

        let second_sink = RecordingSink::new();
        let (second_fd, mut second_peer) = pair();
        let error = registry
            .start(test.config(), second_fd, second_sink)
            .expect_err("overlap rejected");

        assert_eq!(error.category(), ValidatorErrorCategory::Unavailable);
        let mut byte = [0u8; 1];
        assert_eq!(second_peer.read(&mut byte).expect("peer EOF"), 0);
        registry.cancel(first).expect("cancel first");
        assert!(matches!(
            first_sink.wait_for_terminal(),
            RunOutcome::Failed(_)
        ));
    }

    #[test]
    fn cancel_is_idempotent_and_releases_slot() {
        let test = TestConfig::new();
        let registry = RunRegistry::new(Arc::new(ReadUntilEndExecutor));
        let first_sink = RecordingSink::new();
        let (first_fd, _first_peer) = pair();
        let first = registry
            .start(test.config(), first_fd, first_sink.clone())
            .expect("first run");

        registry.cancel(first).expect("first cancel");
        registry.cancel(first).expect("repeat cancel");
        let _ = first_sink.wait_for_terminal();

        let next_sink = RecordingSink::new();
        let (next_fd, _next_peer) = pair();
        let next = registry
            .start(test.config(), next_fd, next_sink.clone())
            .expect("slot released");
        registry.cancel(next).expect("cancel next");
        let _ = next_sink.wait_for_terminal();
    }

    #[test]
    fn eof_or_half_close_never_reports_success() {
        for cancel in [false, true] {
            let test = TestConfig::new();
            let registry = RunRegistry::new(Arc::new(ReadUntilEndExecutor));
            let sink = RecordingSink::new();
            let (fd, peer) = pair();
            let run = registry
                .start(test.config(), fd, sink.clone())
                .expect("start run");
            if cancel {
                registry.cancel(run).expect("cancel run");
                drop(peer);
            } else {
                drop(peer);
            }

            assert!(matches!(sink.wait_for_terminal(), RunOutcome::Failed(_)));
            assert_eq!(sink.terminal_count(), 1);
        }
    }

    #[test]
    fn timeout_reports_one_terminal_failure() {
        let test = TestConfig::new();
        let registry = RunRegistry::new(Arc::new(ImmediateTimeoutExecutor {
            calls: AtomicUsize::new(0),
        }));
        let sink = RecordingSink::new();
        let (fd, _peer) = pair();

        let _run = registry
            .start(test.config(), fd, sink.clone())
            .expect("start run");
        let outcome = sink.wait_for_terminal();

        let RunOutcome::Failed(error) = outcome else {
            panic!("timeout returned success");
        };
        assert_eq!(error.category(), ValidatorErrorCategory::Timeout);
        assert_eq!(sink.terminal_count(), 1);
    }

    #[test]
    fn terminal_is_delivered_before_bridge_shutdown() {
        let test = TestConfig::new();
        let registry = RunRegistry::new(Arc::new(ImmediateTimeoutExecutor {
            calls: AtomicUsize::new(0),
        }));
        let (fd, peer) = pair();
        let sink = TerminalOrderingSink::new(peer);

        registry
            .start(test.config(), fd, sink.clone())
            .expect("start run");

        assert!(
            sink.wait_for_result(),
            "bridge closed before terminal event"
        );
    }

    #[test]
    fn invalid_configuration_opens_no_descriptor() {
        let registry = RunRegistry::new(Arc::new(ReadUntilEndExecutor));
        let sink = RecordingSink::new();
        let (fd, mut peer) = pair();

        let error = registry
            .start_json("{", fd, sink)
            .expect_err("invalid config");

        assert_eq!(error.category(), ValidatorErrorCategory::Configuration);
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).expect("peer EOF"), 0);
    }
}
