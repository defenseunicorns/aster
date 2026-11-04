use crate::{
    ValidationReceipt, ValidatorConfig, ValidatorError, ValidatorErrorCategory,
    validate_ring1_receipt,
};
use aster_ble_l2cap::BleL2capContact;
use aster_contact::{ContactErrorKind, OrderedContact, TransientLocator};
use aster_node::{
    MissionPeerExpectation, MutableSourceInterests, NodeApplication, NodeError,
    OrderedEventContactRole, TransportNeutralNodeConfig, mission::UnprotectedReferenceMission,
    start_transport_neutral_node,
};
use serde::Serialize;
use std::{
    os::{fd::OwnedFd, unix::net::UnixStream},
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
    let mission =
        UnprotectedReferenceMission::load(config.mission_bundle_path()).map_err(|_| {
            ValidatorError::new(
                ValidatorErrorCategory::Authentication,
                "validator mission bundle could not be loaded",
            )
        })?;
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
    let node = start_transport_neutral_node(TransportNeutralNodeConfig {
        state: config.state_path().to_path_buf(),
        mission,
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_secs(60),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .map_err(map_node_error)?;
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
        result = &mut session => result.map_err(map_node_error),
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
            validate_ring1_receipt(&config, &receipt)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ValidatorConfig, ValidatorError, ValidatorErrorCategory};
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
        json: String,
    }

    impl TestConfig {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "aster-ble-android-session-{}-{}",
                std::process::id(),
                NEXT_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).expect("create root");
            let mission = root.join("mission.bundle");
            std::fs::write(&mission, b"mission").expect("write mission");
            let json = format!(
                concat!(
                    "{{",
                    "\"state_path\":\"{}\",",
                    "\"mission_bundle_path\":\"{}\",",
                    "\"mission_peer\":\"{}\",",
                    "\"bluetooth_address\":\"7C:FA:80:72:3B:7A\",",
                    "\"psm\":128,",
                    "\"send_packet_bytes\":512,",
                    "\"receive_packet_bytes\":256,",
                    "\"require_event_larger_than_mtu\":true",
                    "}}"
                ),
                root.join("state").display(),
                mission.display(),
                "11".repeat(32),
            );
            Self { root, json }
        }

        fn config(&self) -> ValidatorConfig {
            ValidatorConfig::from_json(&self.json).expect("valid config")
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
