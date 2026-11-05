use crate::{
    BluezSocketFactory, BtleAvailability, DriverError, DriverErrorKind, FixedRole,
    OpenCancellation, ValidatedConfig, ValidatedSupervisorConfig,
    controller::{AvailabilityMonitor, BluezAvailabilityMonitor},
    open_contact_with_factory,
    policy::{CappedBackoff, LifecycleCancellation},
};
use aster_contact::OrderedContact;
use aster_node::{
    MissionPeerExpectation, OrderedEventContactError, OrderedEventContactHandle,
    OrderedEventContactRole, PeerReceipt,
};
use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time::sleep};

const INITIAL_PEER_RETRY: Duration = Duration::from_millis(250);
const MAXIMUM_PEER_RETRY: Duration = Duration::from_secs(30);

type ContactOpenFuture =
    Pin<Box<dyn Future<Output = Result<Arc<dyn OrderedContact>, DriverError>> + Send>>;
type ContactAdmissionFuture =
    Pin<Box<dyn Future<Output = Result<PeerReceipt, OrderedEventContactError>> + Send>>;

trait ContactOpener: Send + Sync {
    fn open(&self, config: ValidatedConfig, cancellation: OpenCancellation) -> ContactOpenFuture;
}

trait ContactAdmission: Send + Sync {
    fn run(
        &self,
        role: OrderedEventContactRole,
        contact: Arc<dyn OrderedContact>,
        peer: MissionPeerExpectation,
    ) -> ContactAdmissionFuture;
}

struct ProductionContactOpener;

impl ContactOpener for ProductionContactOpener {
    fn open(&self, config: ValidatedConfig, cancellation: OpenCancellation) -> ContactOpenFuture {
        Box::pin(async move {
            let opened =
                open_contact_with_factory(&config, &BluezSocketFactory, &cancellation).await?;
            Ok(opened.into_contact() as Arc<dyn OrderedContact>)
        })
    }
}

impl ContactAdmission for OrderedEventContactHandle {
    fn run(
        &self,
        role: OrderedEventContactRole,
        contact: Arc<dyn OrderedContact>,
        peer: MissionPeerExpectation,
    ) -> ContactAdmissionFuture {
        let contacts = self.clone();
        Box::pin(async move { contacts.run(role, contact, peer).await })
    }
}

/// Terminal, sanitized failures from the unattended Linux BTLE supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// Validated-impossible local driver configuration reached the contact loop.
    Configuration,
    /// The node stopped admitting ordered Event contacts.
    AdmissionClosed,
    /// The node actor could not accept the contact.
    ActorUnavailable,
    /// The node actor stopped before completing the contact.
    ActorStopped,
    /// The controller monitor stopped with a closed driver category.
    Controller(DriverErrorKind),
    /// An owned supervisor child task stopped unexpectedly.
    TaskStopped,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("Linux BTLE configuration failed"),
            Self::AdmissionClosed => {
                formatter.write_str("Linux BTLE ordered Event admission is closed")
            }
            Self::ActorUnavailable => {
                formatter.write_str("Linux BTLE ordered Event actor is unavailable")
            }
            Self::ActorStopped => formatter.write_str("Linux BTLE ordered Event actor stopped"),
            Self::Controller(kind) => write!(formatter, "Linux BTLE controller failed: {kind:?}"),
            Self::TaskStopped => formatter.write_str("Linux BTLE supervisor task stopped"),
        }
    }
}

impl Error for SupervisorError {}

/// Owned unattended Linux BTLE Event lifecycle.
pub struct LinuxBtleEventSupervisor {
    availability: watch::Receiver<BtleAvailability>,
    cancellation: LifecycleCancellation,
    monitor: JoinHandle<Result<(), DriverError>>,
    contacts: JoinHandle<Result<(), SupervisorError>>,
}

impl LinuxBtleEventSupervisor {
    /// Returns a receiver for coarse controller availability.
    pub fn availability(&self) -> watch::Receiver<BtleAvailability> {
        self.availability.clone()
    }

    /// Requests idempotent cancellation of all owned lifecycle work.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Cancels and joins the controller monitor and contact loop.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.cancel();
        let (contact_result, monitor_result) = tokio::join!(self.contacts, self.monitor);
        let contact_result = contact_result.map_err(|_| SupervisorError::TaskStopped);
        let monitor_result = monitor_result.map_err(|_| SupervisorError::TaskStopped);
        eprintln!("BTLE_EVENT status=stopped");
        contact_result??;
        monitor_result?.map_err(|error| SupervisorError::Controller(error.kind()))
    }
}

/// Starts one unattended Linux BTLE Event supervisor for the provisioned peer.
pub fn spawn_linux_btle_event_supervisor(
    config: ValidatedSupervisorConfig,
    contacts: OrderedEventContactHandle,
) -> LinuxBtleEventSupervisor {
    spawn_linux_btle_event_supervisor_with(
        config,
        Arc::new(contacts),
        Arc::new(BluezAvailabilityMonitor::new()),
        Arc::new(ProductionContactOpener),
    )
}

fn spawn_linux_btle_event_supervisor_with(
    config: ValidatedSupervisorConfig,
    admission: Arc<dyn ContactAdmission>,
    monitor: Arc<dyn AvailabilityMonitor>,
    opener: Arc<dyn ContactOpener>,
) -> LinuxBtleEventSupervisor {
    let cancellation = LifecycleCancellation::new();
    let initial = BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    let (updates, availability) = watch::channel(initial);

    let monitor_cancellation = cancellation.clone();
    let monitor_exit = cancellation.clone();
    let monitor_link = config.link().clone();
    let monitor_task = tokio::spawn(async move {
        let result = monitor
            .run(&monitor_link, updates, monitor_cancellation)
            .await;
        monitor_exit.cancel();
        result
    });

    let contact_cancellation = cancellation.clone();
    let contact_exit = cancellation.clone();
    let contact_availability = availability.clone();
    let contact_task = tokio::spawn(async move {
        let result = run_contact_loop(
            config,
            contact_availability,
            contact_cancellation,
            opener,
            admission,
        )
        .await;
        contact_exit.cancel();
        result
    });

    LinuxBtleEventSupervisor {
        availability,
        cancellation,
        monitor: monitor_task,
        contacts: contact_task,
    }
}

async fn run_contact_loop(
    config: ValidatedSupervisorConfig,
    mut availability: watch::Receiver<BtleAvailability>,
    cancellation: LifecycleCancellation,
    opener: Arc<dyn ContactOpener>,
    admission: Arc<dyn ContactAdmission>,
) -> Result<(), SupervisorError> {
    loop {
        match wait_until_available(&mut availability, &cancellation).await {
            WaitOutcome::Ready => {}
            WaitOutcome::Changed => continue,
            WaitOutcome::Stopped => return Ok(()),
        }

        let mut backoff = CappedBackoff::new(INITIAL_PEER_RETRY, MAXIMUM_PEER_RETRY);
        loop {
            match run_attempt(
                &config,
                &mut availability,
                &cancellation,
                opener.as_ref(),
                admission.as_ref(),
            )
            .await?
            {
                AttemptOutcome::Success(receipt) => {
                    backoff.reset();
                    eprintln!(
                        "BTLE_EVENT status=contact-complete offered={} fetched={} inserted={}",
                        receipt.offered, receipt.fetched, receipt.inserted
                    );
                    if config.role() == FixedRole::Listener {
                        continue;
                    }
                    match wait_for_delay(config.contact_cadence(), &mut availability, &cancellation)
                        .await
                    {
                        WaitOutcome::Ready => continue,
                        WaitOutcome::Changed => break,
                        WaitOutcome::Stopped => return Ok(()),
                    }
                }
                AttemptOutcome::Retry(category) => {
                    let delay = backoff.next_delay();
                    eprintln!(
                        "BTLE_EVENT status=contact-failed category={category:?} retry_ms={}",
                        delay.as_millis()
                    );
                    match wait_for_delay(delay, &mut availability, &cancellation).await {
                        WaitOutcome::Ready => continue,
                        WaitOutcome::Changed => break,
                        WaitOutcome::Stopped => return Ok(()),
                    }
                }
                AttemptOutcome::Changed => break,
                AttemptOutcome::Stopped => return Ok(()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RetryCategory {
    Unavailable,
    Timeout,
    Cancelled,
    Transport,
    PeerRejected,
    AdmissionBusy,
    Contact,
}

struct ContactCompletion {
    offered: usize,
    fetched: usize,
    inserted: usize,
}

impl From<PeerReceipt> for ContactCompletion {
    fn from(receipt: PeerReceipt) -> Self {
        Self {
            offered: receipt.offered,
            fetched: receipt.fetched,
            inserted: receipt.inserted,
        }
    }
}

enum AttemptOutcome {
    Success(ContactCompletion),
    Retry(RetryCategory),
    Changed,
    Stopped,
}

async fn run_attempt(
    config: &ValidatedSupervisorConfig,
    availability: &mut watch::Receiver<BtleAvailability>,
    cancellation: &LifecycleCancellation,
    opener: &dyn ContactOpener,
    admission: &dyn ContactAdmission,
) -> Result<AttemptOutcome, SupervisorError> {
    let driver_config = config.link().for_role(config.role());
    let open_cancellation = OpenCancellation::new();
    let open = opener.open(driver_config, open_cancellation.clone());
    tokio::pin!(open);
    eprintln!(
        "BTLE_EVENT status={} role={:?}",
        match config.role() {
            FixedRole::Initiator => "opening",
            FixedRole::Listener => "listening",
        },
        config.role()
    );

    let contact = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            open_cancellation.cancel();
            let _ = open.await;
            return Ok(AttemptOutcome::Stopped);
        }
        changed = availability.changed() => {
            open_cancellation.cancel();
            let _ = open.await;
            return Ok(if changed.is_ok() {
                AttemptOutcome::Changed
            } else {
                AttemptOutcome::Stopped
            });
        }
        result = &mut open => match result {
            Ok(contact) => contact,
            Err(error) if error.kind() == DriverErrorKind::Configuration => {
                return Err(SupervisorError::Configuration);
            }
            Err(error) => return Ok(AttemptOutcome::Retry(driver_retry(error.kind()))),
        }
    };

    let role = match config.role() {
        FixedRole::Initiator => OrderedEventContactRole::Initiator,
        FixedRole::Listener => OrderedEventContactRole::Responder,
    };
    let peer = MissionPeerExpectation::new(contact.peer_evidence(), config.peer_mission_id());
    let contact_result = admission.run(role, contact.clone(), peer);
    tokio::pin!(contact_result);
    let result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            contact.close();
            return Ok(AttemptOutcome::Stopped);
        }
        changed = availability.changed() => {
            contact.close();
            return Ok(if changed.is_ok() {
                AttemptOutcome::Changed
            } else {
                AttemptOutcome::Stopped
            });
        }
        result = &mut contact_result => result,
    };
    contact.close();
    match result {
        Ok(receipt) => Ok(AttemptOutcome::Success(receipt.into())),
        Err(OrderedEventContactError::AdmissionBusy) => {
            Ok(AttemptOutcome::Retry(RetryCategory::AdmissionBusy))
        }
        Err(OrderedEventContactError::Contact(_)) => {
            Ok(AttemptOutcome::Retry(RetryCategory::Contact))
        }
        Err(OrderedEventContactError::AdmissionClosed) => Err(SupervisorError::AdmissionClosed),
        Err(OrderedEventContactError::ActorUnavailable) => Err(SupervisorError::ActorUnavailable),
        Err(OrderedEventContactError::ActorStopped) => Err(SupervisorError::ActorStopped),
    }
}

const fn driver_retry(kind: DriverErrorKind) -> RetryCategory {
    match kind {
        DriverErrorKind::Configuration => unreachable!(),
        DriverErrorKind::Unavailable => RetryCategory::Unavailable,
        DriverErrorKind::Timeout => RetryCategory::Timeout,
        DriverErrorKind::Cancelled => RetryCategory::Cancelled,
        DriverErrorKind::Transport => RetryCategory::Transport,
        DriverErrorKind::PeerRejected => RetryCategory::PeerRejected,
    }
}

#[derive(Clone, Copy)]
enum WaitOutcome {
    Ready,
    Changed,
    Stopped,
}

async fn wait_until_available(
    availability: &mut watch::Receiver<BtleAvailability>,
    cancellation: &LifecycleCancellation,
) -> WaitOutcome {
    loop {
        if *availability.borrow_and_update() == BtleAvailability::Available {
            return WaitOutcome::Ready;
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return WaitOutcome::Stopped,
            changed = availability.changed() => {
                if changed.is_err() {
                    return WaitOutcome::Stopped;
                }
            }
        }
    }
}

async fn wait_for_delay(
    delay: Duration,
    availability: &mut watch::Receiver<BtleAvailability>,
    cancellation: &LifecycleCancellation,
) -> WaitOutcome {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => WaitOutcome::Stopped,
        changed = availability.changed() => if changed.is_ok() {
            WaitOutcome::Changed
        } else {
            WaitOutcome::Stopped
        },
        () = sleep(delay) => WaitOutcome::Ready,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AvailabilityReason, BtleAvailability, DriverError, DriverErrorKind, FixedRole, LinkConfig,
        OpenCancellation, RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, ValidatedConfig,
        ValidatedLinkConfig, ValidatedSupervisorConfig,
        controller::{AvailabilityMonitor, MonitorFuture},
        policy::LifecycleCancellation,
    };
    use aster_contact::{
        CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler,
        OrderedContact, TransientLocator,
    };
    use aster_node::{
        MissionPeerExpectation, NodeError, OrderedEventContactError, OrderedEventContactRole,
        PeerReceipt,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::VecDeque,
        future::pending,
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{Notify, mpsc, watch};

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("test Bluetooth address")
    }

    fn config(local: u8, peer: u8, cadence: Duration) -> ValidatedSupervisorConfig {
        crate::SupervisorConfig {
            link: LinkConfig {
                adapter_name: "hci7".to_owned(),
                local_address: address("02:00:00:00:00:01"),
                local_address_type: AddressType::LeRandom,
                peer_address: address("02:00:00:00:00:02"),
                peer_address_type: AddressType::LePublic,
                psm: 0x0081,
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
            local_mission_id: [local; 32],
            peer_mission_id: [peer; 32],
            contact_cadence: cadence,
        }
        .validate()
        .expect("test supervisor configuration")
    }

    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[derive(Default)]
    struct Activity {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    impl Activity {
        fn enter(self: &Arc<Self>) -> ActivityGuard {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            ActivityGuard(self.clone())
        }
    }

    struct ActivityGuard(Arc<Activity>);

    impl Drop for ActivityGuard {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct FakeMonitor {
        events: Mutex<Option<mpsc::UnboundedReceiver<BtleAvailability>>>,
    }

    impl AvailabilityMonitor for FakeMonitor {
        fn run<'a>(
            &'a self,
            _link: &'a ValidatedLinkConfig,
            updates: watch::Sender<BtleAvailability>,
            cancellation: LifecycleCancellation,
        ) -> MonitorFuture<'a> {
            let mut events = self.events.lock().unwrap().take().unwrap();
            Box::pin(async move {
                loop {
                    tokio::select! {
                        () = cancellation.cancelled() => return Ok(()),
                        event = events.recv() => match event {
                            Some(availability) => {
                                updates.send_if_modified(|current| {
                                    if *current == availability {
                                        false
                                    } else {
                                        *current = availability;
                                        true
                                    }
                                });
                            }
                            None => return Ok(()),
                        }
                    }
                }
            })
        }
    }

    fn fake_monitor() -> (
        Arc<dyn AvailabilityMonitor>,
        mpsc::UnboundedSender<BtleAvailability>,
    ) {
        let (events, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(FakeMonitor {
                events: Mutex::new(Some(receiver)),
            }),
            events,
        )
    }

    struct TestContact {
        closed: AtomicUsize,
        close_notify: Notify,
    }

    impl TestContact {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                closed: AtomicUsize::new(0),
                close_notify: Notify::new(),
            })
        }
    }

    impl OrderedContact for TestContact {
        fn peer_evidence(&self) -> CarrierPeerEvidence {
            CarrierPeerEvidence::UnauthenticatedLocator {
                transient_locator: TransientLocator::new(b"test-peer".to_vec()).unwrap(),
            }
        }

        fn max_frame_bytes(&self) -> usize {
            4096
        }

        fn request_with_total_limit<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(pending())
        }

        fn request_with_total_limit_checked<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
            _before_write: ContactPreflight<'a>,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(pending())
        }

        fn respond_once_with_total_limit<'a>(
            &'a self,
            _total_limit: usize,
            _handler: ContactRequestHandler<'a>,
        ) -> ContactFuture<'a, bool> {
            Box::pin(pending())
        }

        fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
            Box::pin(pending())
        }

        fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
            Box::pin(pending())
        }

        fn close(&self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
            self.close_notify.notify_waiters();
        }
    }

    enum OpenAction {
        Fail(DriverErrorKind),
        Succeed(Arc<TestContact>),
        Pending,
    }

    struct FakeOpener {
        actions: Mutex<VecDeque<OpenAction>>,
        calls: AtomicUsize,
        roles: Mutex<Vec<FixedRole>>,
        times: Mutex<Vec<tokio::time::Instant>>,
        activity: Arc<Activity>,
    }

    impl FakeOpener {
        fn new(
            actions: impl IntoIterator<Item = OpenAction>,
            activity: Arc<Activity>,
        ) -> Arc<Self> {
            Arc::new(Self {
                actions: Mutex::new(actions.into_iter().collect()),
                calls: AtomicUsize::new(0),
                roles: Mutex::new(Vec::new()),
                times: Mutex::new(Vec::new()),
                activity,
            })
        }
    }

    impl ContactOpener for FakeOpener {
        fn open(
            &self,
            config: ValidatedConfig,
            cancellation: OpenCancellation,
        ) -> ContactOpenFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.roles.lock().unwrap().push(config.role());
            self.times.lock().unwrap().push(tokio::time::Instant::now());
            let action = self
                .actions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(OpenAction::Pending);
            let guard = self.activity.enter();
            Box::pin(async move {
                let _guard = guard;
                match action {
                    OpenAction::Fail(kind) => Err(DriverError::new(kind, "test open failure")),
                    OpenAction::Succeed(contact) => Ok(contact as Arc<dyn OrderedContact>),
                    OpenAction::Pending => {
                        cancellation.cancelled().await;
                        Err(DriverError::new(
                            DriverErrorKind::Cancelled,
                            "test open cancellation",
                        ))
                    }
                }
            })
        }
    }

    #[derive(Clone, Copy)]
    enum AdmissionFailure {
        Closed,
        Busy,
        Unavailable,
        Stopped,
        Contact,
    }

    enum AdmissionAction {
        Fail(AdmissionFailure),
        Succeed,
        Pending,
    }

    struct FakeAdmission {
        actions: Mutex<VecDeque<AdmissionAction>>,
        calls: AtomicUsize,
        roles: Mutex<Vec<OrderedEventContactRole>>,
        peers: Mutex<Vec<[u8; 32]>>,
        activity: Arc<Activity>,
    }

    impl FakeAdmission {
        fn new(
            actions: impl IntoIterator<Item = AdmissionAction>,
            activity: Arc<Activity>,
        ) -> Arc<Self> {
            Arc::new(Self {
                actions: Mutex::new(actions.into_iter().collect()),
                calls: AtomicUsize::new(0),
                roles: Mutex::new(Vec::new()),
                peers: Mutex::new(Vec::new()),
                activity,
            })
        }
    }

    impl ContactAdmission for FakeAdmission {
        fn run(
            &self,
            role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            peer: MissionPeerExpectation,
        ) -> ContactAdmissionFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.roles.lock().unwrap().push(role);
            self.peers.lock().unwrap().push(peer.mission_id());
            let action = self
                .actions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(AdmissionAction::Pending);
            let guard = self.activity.enter();
            Box::pin(async move {
                let _guard = guard;
                match action {
                    AdmissionAction::Succeed => Ok(PeerReceipt::default()),
                    AdmissionAction::Pending => pending().await,
                    AdmissionAction::Fail(failure) => Err(match failure {
                        AdmissionFailure::Closed => OrderedEventContactError::AdmissionClosed,
                        AdmissionFailure::Busy => OrderedEventContactError::AdmissionBusy,
                        AdmissionFailure::Unavailable => OrderedEventContactError::ActorUnavailable,
                        AdmissionFailure::Stopped => OrderedEventContactError::ActorStopped,
                        AdmissionFailure::Contact => OrderedEventContactError::Contact(
                            NodeError::Protocol("test contact failure".to_owned()),
                        ),
                    }),
                }
            })
        }
    }

    fn spawn_test(
        config: ValidatedSupervisorConfig,
        monitor: Arc<dyn AvailabilityMonitor>,
        opener: Arc<dyn ContactOpener>,
        admission: Arc<dyn ContactAdmission>,
    ) -> LinuxBtleEventSupervisor {
        spawn_linux_btle_event_supervisor_with(config, admission, monitor, opener)
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_starts_no_contact() {
        let activity = Arc::new(Activity::default());
        let (monitor, _events) = fake_monitor();
        let opener = FakeOpener::new([], activity.clone());
        let admission = FakeAdmission::new([], activity);
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );

        settle().await;

        assert_eq!(opener.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            *supervisor.availability().borrow(),
            BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable)
        );
        supervisor.cancel();
        supervisor.cancel();
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn available_starts_exactly_one_derived_role() {
        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new([OpenAction::Pending], activity.clone());
        let admission = FakeAdmission::new([], activity.clone());
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );

        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;

        assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*opener.roles.lock().unwrap(), [FixedRole::Initiator]);
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn controller_loss_cancels_open_and_active_contact() {
        let activity = Arc::new(Activity::default());
        let contact = TestContact::new();
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [OpenAction::Pending, OpenAction::Succeed(contact.clone())],
            activity.clone(),
        );
        let admission = FakeAdmission::new([AdmissionAction::Pending], activity.clone());
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );

        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        assert_eq!(activity.active.load(Ordering::SeqCst), 1);
        events
            .send(BtleAvailability::Unavailable(
                AvailabilityReason::ControllerUnpowered,
            ))
            .unwrap();
        settle().await;
        assert_eq!(activity.active.load(Ordering::SeqCst), 0);

        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        assert_eq!(activity.active.load(Ordering::SeqCst), 1);
        events
            .send(BtleAvailability::Unavailable(
                AvailabilityReason::ControllerAbsent,
            ))
            .unwrap();
        settle().await;

        assert_eq!(contact.closed.load(Ordering::SeqCst), 1);
        assert_eq!(activity.active.load(Ordering::SeqCst), 0);
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn retryable_failures_back_off_without_overlap() {
        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [
                OpenAction::Fail(DriverErrorKind::Unavailable),
                OpenAction::Fail(DriverErrorKind::Timeout),
                OpenAction::Fail(DriverErrorKind::Transport),
                OpenAction::Fail(DriverErrorKind::PeerRejected),
                OpenAction::Succeed(TestContact::new()),
                OpenAction::Succeed(TestContact::new()),
                OpenAction::Fail(DriverErrorKind::Transport),
                OpenAction::Fail(DriverErrorKind::Transport),
                OpenAction::Fail(DriverErrorKind::Transport),
                OpenAction::Pending,
            ],
            activity.clone(),
        );
        let admission = FakeAdmission::new(
            [
                AdmissionAction::Fail(AdmissionFailure::Busy),
                AdmissionAction::Fail(AdmissionFailure::Contact),
            ],
            activity.clone(),
        );
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );

        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        let delays = [250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];
        for (index, delay) in delays.into_iter().enumerate() {
            assert_eq!(opener.calls.load(Ordering::SeqCst), index + 1);
            tokio::time::advance(Duration::from_millis(delay - 1)).await;
            settle().await;
            assert_eq!(opener.calls.load(Ordering::SeqCst), index + 1);
            tokio::time::advance(Duration::from_millis(1)).await;
            settle().await;
        }

        assert_eq!(opener.calls.load(Ordering::SeqCst), 10);
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn availability_epoch_and_success_reset_peer_backoff() {
        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [
                OpenAction::Fail(DriverErrorKind::Unavailable),
                OpenAction::Fail(DriverErrorKind::Unavailable),
                OpenAction::Succeed(TestContact::new()),
                OpenAction::Fail(DriverErrorKind::Unavailable),
                OpenAction::Pending,
            ],
            activity.clone(),
        );
        let admission = FakeAdmission::new([AdmissionAction::Succeed], activity);
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );

        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        events
            .send(BtleAvailability::Unavailable(
                AvailabilityReason::ControllerUnpowered,
            ))
            .unwrap();
        settle().await;
        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_millis(249)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 3);

        tokio::time::advance(Duration::from_secs(10)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 4);
        tokio::time::advance(Duration::from_millis(249)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 4);
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 5);
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_obeys_cadence_and_listener_relistens() {
        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [OpenAction::Succeed(TestContact::new()), OpenAction::Pending],
            activity.clone(),
        );
        let admission = FakeAdmission::new([AdmissionAction::Succeed], activity);
        let initiator = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission,
        );
        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(9_999)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(opener.calls.load(Ordering::SeqCst), 2);
        initiator.shutdown().await.unwrap();

        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [OpenAction::Succeed(TestContact::new()), OpenAction::Pending],
            activity.clone(),
        );
        let admission = FakeAdmission::new([AdmissionAction::Succeed], activity);
        let listener = spawn_test(
            config(2, 1, Duration::from_secs(10)),
            monitor,
            opener.clone(),
            admission.clone(),
        );
        events.send(BtleAvailability::Available).unwrap();
        settle().await;

        assert_eq!(opener.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *opener.roles.lock().unwrap(),
            [FixedRole::Listener, FixedRole::Listener]
        );
        assert_eq!(
            *admission.roles.lock().unwrap(),
            [OrderedEventContactRole::Responder]
        );
        assert_eq!(*admission.peers.lock().unwrap(), [[1; 32]]);
        listener.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_admission_errors_stop_the_supervisor() {
        let cases = [
            (AdmissionFailure::Closed, SupervisorError::AdmissionClosed),
            (
                AdmissionFailure::Unavailable,
                SupervisorError::ActorUnavailable,
            ),
            (AdmissionFailure::Stopped, SupervisorError::ActorStopped),
        ];
        for (failure, expected) in cases {
            let activity = Arc::new(Activity::default());
            let (monitor, events) = fake_monitor();
            let opener =
                FakeOpener::new([OpenAction::Succeed(TestContact::new())], activity.clone());
            let admission = FakeAdmission::new([AdmissionAction::Fail(failure)], activity.clone());
            let supervisor = spawn_test(
                config(1, 2, Duration::from_secs(10)),
                monitor,
                opener.clone(),
                admission,
            );
            events.send(BtleAvailability::Available).unwrap();
            settle().await;

            assert_eq!(supervisor.shutdown().await.unwrap_err(), expected);
            assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
            assert_eq!(activity.active.load(Ordering::SeqCst), 0);
        }

        let activity = Arc::new(Activity::default());
        let (monitor, events) = fake_monitor();
        let opener = FakeOpener::new(
            [OpenAction::Fail(DriverErrorKind::Configuration)],
            activity.clone(),
        );
        let admission = FakeAdmission::new([], activity);
        let supervisor = spawn_test(
            config(1, 2, Duration::from_secs(10)),
            monitor,
            opener,
            admission,
        );
        events.send(BtleAvailability::Available).unwrap();
        settle().await;
        assert_eq!(
            supervisor.shutdown().await.unwrap_err(),
            SupervisorError::Configuration
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_drains_every_lifecycle_state() {
        async fn run_case(
            availability: bool,
            open_actions: Vec<OpenAction>,
            admission_actions: Vec<AdmissionAction>,
        ) -> (Arc<Activity>, Vec<Arc<TestContact>>) {
            let contacts = open_actions
                .iter()
                .filter_map(|action| match action {
                    OpenAction::Succeed(contact) => Some(contact.clone()),
                    OpenAction::Fail(_) | OpenAction::Pending => None,
                })
                .collect::<Vec<_>>();
            let activity = Arc::new(Activity::default());
            let (monitor, events) = fake_monitor();
            let opener = FakeOpener::new(open_actions, activity.clone());
            let admission = FakeAdmission::new(admission_actions, activity.clone());
            let supervisor = spawn_test(
                config(1, 2, Duration::from_secs(10)),
                monitor,
                opener,
                admission,
            );
            if availability {
                events.send(BtleAvailability::Available).unwrap();
            }
            settle().await;
            supervisor.shutdown().await.unwrap();
            (activity, contacts)
        }

        let cases = [
            run_case(false, vec![], vec![]).await,
            run_case(true, vec![OpenAction::Pending], vec![]).await,
            run_case(
                true,
                vec![OpenAction::Succeed(TestContact::new())],
                vec![AdmissionAction::Pending],
            )
            .await,
            run_case(
                true,
                vec![OpenAction::Fail(DriverErrorKind::Unavailable)],
                vec![],
            )
            .await,
            run_case(
                true,
                vec![OpenAction::Succeed(TestContact::new())],
                vec![AdmissionAction::Succeed],
            )
            .await,
        ];

        for (activity, contacts) in cases {
            assert_eq!(activity.active.load(Ordering::SeqCst), 0);
            for contact in contacts {
                assert!(contact.closed.load(Ordering::SeqCst) > 0);
            }
        }

        let monitor_stopped = Arc::new(AtomicBool::new(false));
        let cancellation = LifecycleCancellation::new();
        let monitor_cancellation = cancellation.clone();
        let monitor_observation = monitor_stopped.clone();
        let monitor = tokio::spawn(async move {
            monitor_cancellation.cancelled().await;
            monitor_observation.store(true, Ordering::SeqCst);
            Ok::<(), DriverError>(())
        });
        let contacts = tokio::spawn(async {
            pending::<()>().await;
            Ok::<(), SupervisorError>(())
        });
        contacts.abort();
        let (_updates, availability) = watch::channel(BtleAvailability::Available);
        let supervisor = LinuxBtleEventSupervisor {
            availability,
            cancellation,
            monitor,
            contacts,
        };
        settle().await;
        assert_eq!(
            supervisor.shutdown().await.unwrap_err(),
            SupervisorError::TaskStopped
        );
        assert!(monitor_stopped.load(Ordering::SeqCst));
    }
}
