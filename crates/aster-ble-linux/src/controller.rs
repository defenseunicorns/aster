use crate::{
    DriverError, FixedRole, OpenRequest, ValidatedLinkConfig,
    policy::{CappedBackoff, LifecycleCancellation},
};
use bluer::{AdapterEvent, AdapterProperty, Address, AddressType, SessionEvent};
use futures::{Stream, StreamExt, stream};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::watch;

const INITIAL_SESSION_RETRY: Duration = Duration::from_millis(250);
const MAXIMUM_SESSION_RETRY: Duration = Duration::from_secs(30);

/// Coarse observation of the configured Linux BTLE controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtleAvailability {
    /// BlueZ or the provisioned controller cannot currently support a contact.
    Unavailable(AvailabilityReason),
    /// The provisioned controller exists, is powered, and has the expected identity.
    Available,
}

/// Sanitized reason why the configured Linux BTLE controller is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityReason {
    /// The BlueZ service or its D-Bus session cannot be observed.
    BluezUnavailable,
    /// The configured controller name is not present.
    ControllerAbsent,
    /// The configured controller is present but powered off.
    ControllerUnpowered,
    /// BlueZ denied observation of the configured controller.
    ControllerUnauthorized,
    /// The named controller does not have the provisioned address and address type.
    ControllerIdentityMismatch,
}

pub(crate) type MonitorFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), DriverError>> + Send + 'a>>;
type BluezFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BluezFailure>> + Send + 'a>>;
type SessionStream = Pin<Box<dyn Stream<Item = SessionSignal> + Send>>;
type AdapterStream = Pin<Box<dyn Stream<Item = AdapterSignal> + Send>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BluezFailure {
    BluezUnavailable,
    ControllerAbsent,
    ControllerUnauthorized,
}

impl BluezFailure {
    const fn availability(self) -> BtleAvailability {
        let reason = match self {
            Self::BluezUnavailable => AvailabilityReason::BluezUnavailable,
            Self::ControllerAbsent => AvailabilityReason::ControllerAbsent,
            Self::ControllerUnauthorized => AvailabilityReason::ControllerUnauthorized,
        };
        BtleAvailability::Unavailable(reason)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionSignal {
    AdapterAdded(String),
    AdapterRemoved(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterSignal {
    PropertiesChanged,
    Unrelated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdapterSnapshot {
    powered: bool,
    address: Address,
    address_type: AddressType,
}

trait BluezBackend: Send + Sync {
    fn open_session(&self) -> BluezFuture<'_, Box<dyn BluezSession>>;
}

trait BluezSession: Send + Sync {
    fn subscribe(&self) -> BluezFuture<'_, SessionStream>;
    fn adapter_names(&self) -> BluezFuture<'_, Vec<String>>;
    fn adapter<'a>(&'a self, name: &'a str) -> BluezFuture<'a, Box<dyn BluezAdapter>>;
}

trait BluezAdapter: Send + Sync {
    fn subscribe(&self) -> BluezFuture<'_, AdapterStream>;
    fn snapshot(&self) -> BluezFuture<'_, AdapterSnapshot>;
}

pub(crate) trait AvailabilityMonitor: Send + Sync {
    fn run<'a>(
        &'a self,
        link: &'a ValidatedLinkConfig,
        updates: watch::Sender<BtleAvailability>,
        cancellation: LifecycleCancellation,
    ) -> MonitorFuture<'a>;
}

pub(crate) struct BluezAvailabilityMonitor {
    backend: Arc<dyn BluezBackend>,
}

impl BluezAvailabilityMonitor {
    pub(crate) fn new() -> Self {
        Self {
            backend: Arc::new(ProductionBluez),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: Arc<dyn BluezBackend>) -> Self {
        Self { backend }
    }

    async fn run_monitor(
        &self,
        link: &ValidatedLinkConfig,
        updates: watch::Sender<BtleAvailability>,
        cancellation: LifecycleCancellation,
    ) -> Result<(), DriverError> {
        let configured = ConfiguredController::from_link(link);
        let mut backoff = CappedBackoff::new(INITIAL_SESSION_RETRY, MAXIMUM_SESSION_RETRY);

        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }

            let session = match wait_for(&cancellation, self.backend.open_session()).await {
                WaitResult::Value(Ok(session)) => session,
                WaitResult::Value(Err(failure)) => {
                    if retry_session(&updates, &cancellation, &mut backoff, failure).await {
                        return Ok(());
                    }
                    continue;
                }
                WaitResult::Cancelled => return Ok(()),
            };
            let session_events = match wait_for(&cancellation, session.subscribe()).await {
                WaitResult::Value(Ok(events)) => events,
                WaitResult::Value(Err(failure)) => {
                    if retry_session(&updates, &cancellation, &mut backoff, failure).await {
                        return Ok(());
                    }
                    continue;
                }
                WaitResult::Cancelled => return Ok(()),
            };
            let adapter_names = match wait_for(&cancellation, session.adapter_names()).await {
                WaitResult::Value(Ok(names)) => names,
                WaitResult::Value(Err(failure)) => {
                    if retry_session(&updates, &cancellation, &mut backoff, failure).await {
                        return Ok(());
                    }
                    continue;
                }
                WaitResult::Cancelled => return Ok(()),
            };

            backoff.reset();
            let present = adapter_names.iter().any(|name| name == &configured.name);
            match monitor_session(
                session.as_ref(),
                session_events,
                &configured,
                present,
                &updates,
                &cancellation,
            )
            .await
            {
                SessionOutcome::Cancelled => return Ok(()),
                SessionOutcome::Lost(failure) => {
                    if retry_session(&updates, &cancellation, &mut backoff, failure).await {
                        return Ok(());
                    }
                }
            }
        }
    }
}

impl Default for BluezAvailabilityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl AvailabilityMonitor for BluezAvailabilityMonitor {
    fn run<'a>(
        &'a self,
        link: &'a ValidatedLinkConfig,
        updates: watch::Sender<BtleAvailability>,
        cancellation: LifecycleCancellation,
    ) -> MonitorFuture<'a> {
        Box::pin(self.run_monitor(link, updates, cancellation))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfiguredController {
    name: String,
    address: Address,
    address_type: AddressType,
}

impl ConfiguredController {
    fn from_link(link: &ValidatedLinkConfig) -> Self {
        match link.for_role(FixedRole::Initiator).open_request() {
            OpenRequest::Initiator {
                adapter_name,
                local,
                ..
            } => Self {
                name: adapter_name,
                address: local.addr,
                address_type: local.addr_type,
            },
            OpenRequest::Listener { .. } => unreachable!("initiator role requested"),
        }
    }

    fn classify(&self, snapshot: AdapterSnapshot) -> BtleAvailability {
        if !snapshot.powered {
            BtleAvailability::Unavailable(AvailabilityReason::ControllerUnpowered)
        } else if snapshot.address != self.address || snapshot.address_type != self.address_type {
            BtleAvailability::Unavailable(AvailabilityReason::ControllerIdentityMismatch)
        } else {
            BtleAvailability::Available
        }
    }
}

enum SessionOutcome {
    Cancelled,
    Lost(BluezFailure),
}

async fn monitor_session(
    session: &dyn BluezSession,
    mut session_events: SessionStream,
    configured: &ConfiguredController,
    mut present: bool,
    updates: &watch::Sender<BtleAvailability>,
    cancellation: &LifecycleCancellation,
) -> SessionOutcome {
    loop {
        if !present {
            publish(
                updates,
                BtleAvailability::Unavailable(AvailabilityReason::ControllerAbsent),
            );
            present = match next_configured_session_event(
                &mut session_events,
                &configured.name,
                cancellation,
            )
            .await
            {
                SessionEventOutcome::Added => true,
                SessionEventOutcome::Removed => false,
                SessionEventOutcome::Ended => {
                    return SessionOutcome::Lost(BluezFailure::BluezUnavailable);
                }
                SessionEventOutcome::Cancelled => return SessionOutcome::Cancelled,
            };
            if !present {
                continue;
            }
        }

        let adapter = match wait_for(cancellation, session.adapter(&configured.name)).await {
            WaitResult::Value(Ok(adapter)) => adapter,
            WaitResult::Value(Err(BluezFailure::ControllerAbsent)) => {
                present = false;
                continue;
            }
            WaitResult::Value(Err(failure)) => return SessionOutcome::Lost(failure),
            WaitResult::Cancelled => return SessionOutcome::Cancelled,
        };
        let adapter_events = match wait_for(cancellation, adapter.subscribe()).await {
            WaitResult::Value(Ok(events)) => events,
            WaitResult::Value(Err(BluezFailure::ControllerAbsent)) => {
                present = false;
                continue;
            }
            WaitResult::Value(Err(failure)) => return SessionOutcome::Lost(failure),
            WaitResult::Cancelled => return SessionOutcome::Cancelled,
        };
        let initial = match wait_for(cancellation, adapter.snapshot()).await {
            WaitResult::Value(Ok(snapshot)) => snapshot,
            WaitResult::Value(Err(BluezFailure::ControllerAbsent)) => {
                present = false;
                continue;
            }
            WaitResult::Value(Err(failure)) => return SessionOutcome::Lost(failure),
            WaitResult::Cancelled => return SessionOutcome::Cancelled,
        };
        publish(updates, configured.classify(initial));

        let session_observations = session_events
            .by_ref()
            .map(|event| ControllerEvent::Session(Some(event)))
            .chain(stream::iter([ControllerEvent::Session(None)]));
        let adapter_observations = adapter_events
            .map(|event| ControllerEvent::Adapter(Some(event)))
            .chain(stream::iter([ControllerEvent::Adapter(None)]));
        // Round-robin source selection prevents starvation; only cancellation is prioritized.
        let mut events = stream::select(session_observations, adapter_observations);
        loop {
            let event = tokio::select! {
                biased;
                () = cancellation.cancelled() => return SessionOutcome::Cancelled,
                event = events.next() => event,
            };
            match event {
                Some(ControllerEvent::Session(session_event)) => match session_event {
                    Some(SessionSignal::AdapterRemoved(name)) if name == configured.name => {
                        publish(
                            updates,
                            BtleAvailability::Unavailable(AvailabilityReason::ControllerAbsent),
                        );
                        present = false;
                        break;
                    }
                    Some(_) => {}
                    None => return SessionOutcome::Lost(BluezFailure::BluezUnavailable),
                },
                Some(ControllerEvent::Adapter(adapter_event)) => match adapter_event {
                    Some(AdapterSignal::PropertiesChanged) => {
                        match wait_for(cancellation, adapter.snapshot()).await {
                            WaitResult::Value(Ok(snapshot)) => {
                                publish(updates, configured.classify(snapshot));
                            }
                            WaitResult::Value(Err(BluezFailure::ControllerAbsent)) => {
                                publish(
                                    updates,
                                    BtleAvailability::Unavailable(
                                        AvailabilityReason::ControllerAbsent,
                                    ),
                                );
                                present = false;
                                break;
                            }
                            WaitResult::Value(Err(failure)) => {
                                return SessionOutcome::Lost(failure);
                            }
                            WaitResult::Cancelled => return SessionOutcome::Cancelled,
                        }
                    }
                    Some(AdapterSignal::Unrelated) => {}
                    None => return SessionOutcome::Lost(BluezFailure::BluezUnavailable),
                },
                None => return SessionOutcome::Lost(BluezFailure::BluezUnavailable),
            }
        }
    }
}

enum ControllerEvent {
    Session(Option<SessionSignal>),
    Adapter(Option<AdapterSignal>),
}

enum SessionEventOutcome {
    Added,
    Removed,
    Ended,
    Cancelled,
}

async fn next_configured_session_event(
    events: &mut SessionStream,
    configured_name: &str,
    cancellation: &LifecycleCancellation,
) -> SessionEventOutcome {
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return SessionEventOutcome::Cancelled,
            event = events.next() => match event {
                Some(SessionSignal::AdapterAdded(name)) if name == configured_name => {
                    return SessionEventOutcome::Added;
                }
                Some(SessionSignal::AdapterRemoved(name)) if name == configured_name => {
                    return SessionEventOutcome::Removed;
                }
                Some(_) => {}
                None => return SessionEventOutcome::Ended,
            }
        }
    }
}

enum WaitResult<T> {
    Value(T),
    Cancelled,
}

async fn wait_for<T>(
    cancellation: &LifecycleCancellation,
    future: impl Future<Output = T>,
) -> WaitResult<T> {
    tokio::select! {
        value = future => WaitResult::Value(value),
        () = cancellation.cancelled() => WaitResult::Cancelled,
    }
}

async fn wait_delay(cancellation: &LifecycleCancellation, delay: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        () = cancellation.cancelled() => true,
    }
}

async fn retry_session(
    updates: &watch::Sender<BtleAvailability>,
    cancellation: &LifecycleCancellation,
    backoff: &mut CappedBackoff,
    failure: BluezFailure,
) -> bool {
    publish(updates, failure.availability());
    wait_delay(cancellation, backoff.next_delay()).await
}

fn publish(updates: &watch::Sender<BtleAvailability>, availability: BtleAvailability) {
    let changed = updates.send_if_modified(|current| {
        if *current == availability {
            false
        } else {
            *current = availability;
            true
        }
    });
    if changed {
        match availability {
            BtleAvailability::Available => eprintln!("BTLE_EVENT status=available"),
            BtleAvailability::Unavailable(reason) => {
                eprintln!("BTLE_EVENT status=unavailable reason={reason:?}");
            }
        }
    }
}

struct ProductionBluez;

impl BluezBackend for ProductionBluez {
    fn open_session(&self) -> BluezFuture<'_, Box<dyn BluezSession>> {
        Box::pin(async {
            bluer::Session::new()
                .await
                .map(|session| Box::new(ProductionSession(session)) as Box<dyn BluezSession>)
                .map_err(session_failure)
        })
    }
}

struct ProductionSession(bluer::Session);

impl BluezSession for ProductionSession {
    fn subscribe(&self) -> BluezFuture<'_, SessionStream> {
        Box::pin(async move {
            let events = self.0.events().await.map_err(session_failure)?;
            Ok(events
                .map(|event| match event {
                    SessionEvent::AdapterAdded(name) => SessionSignal::AdapterAdded(name),
                    SessionEvent::AdapterRemoved(name) => SessionSignal::AdapterRemoved(name),
                })
                .boxed())
        })
    }

    fn adapter_names(&self) -> BluezFuture<'_, Vec<String>> {
        Box::pin(async move { self.0.adapter_names().await.map_err(session_failure) })
    }

    fn adapter<'a>(&'a self, name: &'a str) -> BluezFuture<'a, Box<dyn BluezAdapter>> {
        Box::pin(async move {
            self.0
                .adapter(name)
                .map(|adapter| Box::new(ProductionAdapter(adapter)) as Box<dyn BluezAdapter>)
                .map_err(adapter_failure)
        })
    }
}

struct ProductionAdapter(bluer::Adapter);

impl BluezAdapter for ProductionAdapter {
    fn subscribe(&self) -> BluezFuture<'_, AdapterStream> {
        Box::pin(async move {
            let events = self.0.events().await.map_err(adapter_failure)?;
            Ok(events
                .map(|event| match event {
                    AdapterEvent::PropertyChanged(
                        AdapterProperty::Address(_)
                        | AdapterProperty::AddressType(_)
                        | AdapterProperty::Powered(_),
                    ) => AdapterSignal::PropertiesChanged,
                    AdapterEvent::DeviceAdded(_)
                    | AdapterEvent::DeviceRemoved(_)
                    | AdapterEvent::PropertyChanged(_) => AdapterSignal::Unrelated,
                })
                .boxed())
        })
    }

    fn snapshot(&self) -> BluezFuture<'_, AdapterSnapshot> {
        Box::pin(async move {
            let powered = self.0.is_powered().await.map_err(adapter_failure)?;
            let address = self.0.address().await.map_err(adapter_failure)?;
            let address_type = self.0.address_type().await.map_err(adapter_failure)?;
            Ok(AdapterSnapshot {
                powered,
                address,
                address_type,
            })
        })
    }
}

fn session_failure(error: bluer::Error) -> BluezFailure {
    if unauthorized(&error.kind) {
        BluezFailure::ControllerUnauthorized
    } else {
        BluezFailure::BluezUnavailable
    }
}

fn adapter_failure(error: bluer::Error) -> BluezFailure {
    if unauthorized(&error.kind) {
        BluezFailure::ControllerUnauthorized
    } else if matches!(
        error.kind,
        bluer::ErrorKind::DoesNotExist | bluer::ErrorKind::NotFound
    ) {
        BluezFailure::ControllerAbsent
    } else {
        BluezFailure::BluezUnavailable
    }
}

fn unauthorized(kind: &bluer::ErrorKind) -> bool {
    matches!(
        kind,
        bluer::ErrorKind::NotAuthorized | bluer::ErrorKind::NotPermitted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinkConfig, RING1_MAXIMUM_EXCHANGE_BYTES, policy::LifecycleCancellation};
    use bluer::{Address, AddressType};
    use std::{
        collections::VecDeque,
        str::FromStr,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::{Notify, mpsc, watch};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        OpenSession,
        SubscribeSession,
        SnapshotAdapterNames,
        ConstructAdapter,
        SubscribeAdapter,
        SnapshotAdapter,
    }

    struct Script {
        opens: VecDeque<Result<(), BluezFailure>>,
        session_events: VecDeque<mpsc::UnboundedReceiver<SessionSignal>>,
        adapter_names: VecDeque<Result<Vec<String>, BluezFailure>>,
        adapter_events: VecDeque<mpsc::UnboundedReceiver<AdapterSignal>>,
        snapshots: VecDeque<Result<AdapterSnapshot, BluezFailure>>,
        calls: Vec<Call>,
    }

    #[derive(Clone)]
    struct ScriptedBluez {
        script: Arc<Mutex<Script>>,
        changed: Arc<Notify>,
    }

    impl ScriptedBluez {
        fn new(
            opens: impl IntoIterator<Item = Result<(), BluezFailure>>,
            session_events: impl IntoIterator<Item = mpsc::UnboundedReceiver<SessionSignal>>,
            adapter_names: impl IntoIterator<Item = Result<Vec<String>, BluezFailure>>,
            adapter_events: impl IntoIterator<Item = mpsc::UnboundedReceiver<AdapterSignal>>,
            snapshots: impl IntoIterator<Item = Result<AdapterSnapshot, BluezFailure>>,
        ) -> Self {
            Self {
                script: Arc::new(Mutex::new(Script {
                    opens: opens.into_iter().collect(),
                    session_events: session_events.into_iter().collect(),
                    adapter_names: adapter_names.into_iter().collect(),
                    adapter_events: adapter_events.into_iter().collect(),
                    snapshots: snapshots.into_iter().collect(),
                    calls: Vec::new(),
                })),
                changed: Arc::new(Notify::new()),
            }
        }

        fn record(&self, call: Call) {
            self.script.lock().unwrap().calls.push(call);
            self.changed.notify_waiters();
        }

        async fn wait_for_calls(&self, count: usize) {
            loop {
                let notified = self.changed.notified();
                if self.script.lock().unwrap().calls.len() >= count {
                    return;
                }
                notified.await;
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.script.lock().unwrap().calls.clone()
        }
    }

    impl BluezBackend for ScriptedBluez {
        fn open_session(&self) -> BluezFuture<'_, Box<dyn BluezSession>> {
            Box::pin(async move {
                self.record(Call::OpenSession);
                self.script
                    .lock()
                    .unwrap()
                    .opens
                    .pop_front()
                    .expect("scripted session result")?;
                Ok(Box::new(ScriptedSession(self.clone())) as Box<dyn BluezSession>)
            })
        }
    }

    struct ScriptedSession(ScriptedBluez);

    impl BluezSession for ScriptedSession {
        fn subscribe(&self) -> BluezFuture<'_, SessionStream> {
            Box::pin(async move {
                self.0.record(Call::SubscribeSession);
                let events = self
                    .0
                    .script
                    .lock()
                    .unwrap()
                    .session_events
                    .pop_front()
                    .expect("scripted session events");
                Ok(Box::pin(tokio_stream(events)) as SessionStream)
            })
        }

        fn adapter_names(&self) -> BluezFuture<'_, Vec<String>> {
            Box::pin(async move {
                self.0.record(Call::SnapshotAdapterNames);
                self.0
                    .script
                    .lock()
                    .unwrap()
                    .adapter_names
                    .pop_front()
                    .expect("scripted adapter-name snapshot")
            })
        }

        fn adapter(&self, _name: &str) -> BluezFuture<'_, Box<dyn BluezAdapter>> {
            Box::pin(async move {
                self.0.record(Call::ConstructAdapter);
                Ok(Box::new(ScriptedAdapter(self.0.clone())) as Box<dyn BluezAdapter>)
            })
        }
    }

    struct ScriptedAdapter(ScriptedBluez);

    impl BluezAdapter for ScriptedAdapter {
        fn subscribe(&self) -> BluezFuture<'_, AdapterStream> {
            Box::pin(async move {
                self.0.record(Call::SubscribeAdapter);
                let events = self
                    .0
                    .script
                    .lock()
                    .unwrap()
                    .adapter_events
                    .pop_front()
                    .expect("scripted adapter events");
                Ok(Box::pin(tokio_stream(events)) as AdapterStream)
            })
        }

        fn snapshot(&self) -> BluezFuture<'_, AdapterSnapshot> {
            Box::pin(async move {
                self.0.record(Call::SnapshotAdapter);
                self.0
                    .script
                    .lock()
                    .unwrap()
                    .snapshots
                    .pop_front()
                    .expect("scripted adapter snapshot")
            })
        }
    }

    fn tokio_stream<T: Send + 'static>(
        receiver: mpsc::UnboundedReceiver<T>,
    ) -> impl futures::Stream<Item = T> + Send {
        futures::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|item| (item, receiver))
        })
    }

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("test Bluetooth address")
    }

    fn link() -> crate::ValidatedLinkConfig {
        LinkConfig {
            adapter_name: "hci7".to_owned(),
            local_address: address("02:00:00:00:00:01"),
            local_address_type: AddressType::LeRandom,
            peer_address: address("02:00:00:00:00:02"),
            peer_address_type: AddressType::LePublic,
            psm: 0x0081,
            maximum_frame_bytes: 2 * 1024 * 1024,
            maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
            open_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(30),
        }
        .validate()
        .unwrap()
    }

    fn snapshot(powered: bool, address: Address, address_type: AddressType) -> AdapterSnapshot {
        AdapterSnapshot {
            powered,
            address,
            address_type,
        }
    }

    fn expected_snapshot(powered: bool) -> AdapterSnapshot {
        snapshot(powered, address("02:00:00:00:00:01"), AddressType::LeRandom)
    }

    fn spawn_monitor(
        bluez: ScriptedBluez,
    ) -> (
        watch::Receiver<BtleAvailability>,
        LifecycleCancellation,
        tokio::task::JoinHandle<Result<(), crate::DriverError>>,
    ) {
        let monitor = BluezAvailabilityMonitor::with_backend(Arc::new(bluez));
        let (updates, receiver) = watch::channel(BtleAvailability::Unavailable(
            AvailabilityReason::BluezUnavailable,
        ));
        let cancellation = LifecycleCancellation::new();
        let worker_cancellation = cancellation.clone();
        let link = link();
        let task =
            tokio::spawn(async move { monitor.run(&link, updates, worker_cancellation).await });
        (receiver, cancellation, task)
    }

    async fn next_update(receiver: &mut watch::Receiver<BtleAvailability>) -> BtleAvailability {
        receiver.changed().await.expect("monitor still running");
        *receiver.borrow_and_update()
    }

    async fn stop(
        cancellation: LifecycleCancellation,
        task: tokio::task::JoinHandle<Result<(), crate::DriverError>>,
    ) {
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_subscribes_before_snapshot() {
        let (_session_tx, session_rx) = mpsc::unbounded_channel();
        let (_adapter_tx, adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(())],
            [session_rx],
            [Ok(vec!["hci7".to_owned()])],
            [adapter_rx],
            [Ok(expected_snapshot(true))],
        );
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());

        bluez.wait_for_calls(6).await;

        assert_eq!(
            bluez.calls(),
            vec![
                Call::OpenSession,
                Call::SubscribeSession,
                Call::SnapshotAdapterNames,
                Call::ConstructAdapter,
                Call::SubscribeAdapter,
                Call::SnapshotAdapter,
            ]
        );
        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_tracks_add_power_identity_and_removal() {
        let (session_tx, session_rx) = mpsc::unbounded_channel();
        let (adapter_tx, adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(())],
            [session_rx],
            [Ok(vec![])],
            [adapter_rx],
            [
                Ok(expected_snapshot(false)),
                Ok(expected_snapshot(false)),
                Ok(snapshot(
                    true,
                    address("02:00:00:00:00:09"),
                    AddressType::LeRandom,
                )),
                Ok(expected_snapshot(true)),
            ],
        );
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());

        bluez.wait_for_calls(3).await;
        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::ControllerAbsent)
        );

        session_tx
            .send(SessionSignal::AdapterAdded("hci7".to_owned()))
            .unwrap();
        bluez.wait_for_calls(6).await;
        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::ControllerUnpowered)
        );

        adapter_tx.send(AdapterSignal::PropertiesChanged).unwrap();
        bluez.wait_for_calls(7).await;
        assert!(!updates.has_changed().unwrap());

        adapter_tx.send(AdapterSignal::PropertiesChanged).unwrap();
        bluez.wait_for_calls(8).await;
        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::ControllerIdentityMismatch)
        );

        adapter_tx.send(AdapterSignal::PropertiesChanged).unwrap();
        bluez.wait_for_calls(9).await;
        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);

        session_tx
            .send(SessionSignal::AdapterRemoved("hci7".to_owned()))
            .unwrap();
        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::ControllerAbsent)
        );
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_resnapshots_all_properties_after_relevant_change() {
        let (_session_tx, session_rx) = mpsc::unbounded_channel();
        let (adapter_tx, adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(())],
            [session_rx],
            [Ok(vec!["hci7".to_owned()])],
            [adapter_rx],
            [
                Ok(expected_snapshot(true)),
                Ok(snapshot(
                    true,
                    address("02:00:00:00:00:01"),
                    AddressType::LePublic,
                )),
            ],
        );
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());
        bluez.wait_for_calls(6).await;
        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);

        adapter_tx.send(AdapterSignal::PropertiesChanged).unwrap();
        bluez.wait_for_calls(7).await;

        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::ControllerIdentityMismatch)
        );
        assert_eq!(
            bluez
                .calls()
                .iter()
                .filter(|call| **call == Call::SnapshotAdapter)
                .count(),
            2
        );
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_ignores_unrelated_events() {
        let (session_tx, session_rx) = mpsc::unbounded_channel();
        let (adapter_tx, adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(())],
            [session_rx],
            [Ok(vec!["hci7".to_owned()])],
            [adapter_rx],
            [Ok(expected_snapshot(true))],
        );
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());
        bluez.wait_for_calls(6).await;
        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);

        session_tx
            .send(SessionSignal::AdapterAdded("hci0".to_owned()))
            .unwrap();
        session_tx
            .send(SessionSignal::AdapterRemoved("hci1".to_owned()))
            .unwrap();
        adapter_tx.send(AdapterSignal::Unrelated).unwrap();
        tokio::task::yield_now().await;

        assert_eq!(bluez.calls().len(), 6);
        assert!(!updates.has_changed().unwrap());
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_does_not_starve_adapter_events_during_unrelated_session_flood() {
        let (session_tx, session_rx) = mpsc::unbounded_channel();
        let (adapter_tx, adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(())],
            [session_rx],
            [Ok(vec!["hci7".to_owned()])],
            [adapter_rx],
            [Ok(expected_snapshot(false)), Ok(expected_snapshot(true))],
        );
        for _ in 0..4096 {
            session_tx
                .send(SessionSignal::AdapterAdded("hci0".to_owned()))
                .unwrap();
        }
        adapter_tx.send(AdapterSignal::PropertiesChanged).unwrap();
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());
        bluez.wait_for_calls(6).await;

        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            bluez
                .calls()
                .iter()
                .filter(|call| **call == Call::SnapshotAdapter)
                .count(),
            2
        );
        assert_eq!(*updates.borrow_and_update(), BtleAvailability::Available);
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_reconnects_when_adapter_stream_ends_while_controller_remains_present() {
        let (_first_session_tx, first_session_rx) = mpsc::unbounded_channel();
        let (_second_session_tx, second_session_rx) = mpsc::unbounded_channel();
        let (first_adapter_tx, first_adapter_rx) = mpsc::unbounded_channel();
        let (_second_adapter_tx, second_adapter_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [Ok(()), Ok(())],
            [first_session_rx, second_session_rx],
            [Ok(vec!["hci7".to_owned()]), Ok(vec!["hci7".to_owned()])],
            [first_adapter_rx, second_adapter_rx],
            [Ok(expected_snapshot(true)), Ok(expected_snapshot(true))],
        );
        let (mut updates, cancellation, task) = spawn_monitor(bluez.clone());
        bluez.wait_for_calls(6).await;
        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);

        drop(first_adapter_tx);
        assert_eq!(
            next_update(&mut updates).await,
            BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable)
        );
        tokio::time::advance(Duration::from_millis(250)).await;
        bluez.wait_for_calls(12).await;

        assert_eq!(next_update(&mut updates).await, BtleAvailability::Available);
        assert_eq!(
            bluez
                .calls()
                .iter()
                .filter(|call| **call == Call::OpenSession)
                .count(),
            2
        );
        stop(cancellation, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_reconnects_session_with_independent_capped_backoff() {
        let (session_tx, session_rx) = mpsc::unbounded_channel();
        let (_final_tx, final_rx) = mpsc::unbounded_channel();
        let bluez = ScriptedBluez::new(
            [
                Err(BluezFailure::BluezUnavailable),
                Err(BluezFailure::BluezUnavailable),
                Ok(()),
                Ok(()),
            ],
            [session_rx, final_rx],
            [Ok(vec![]), Ok(vec![])],
            [],
            [],
        );
        let (_updates, cancellation, task) = spawn_monitor(bluez.clone());

        bluez.wait_for_calls(1).await;
        tokio::time::advance(Duration::from_millis(249)).await;
        assert_eq!(bluez.calls().len(), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        bluez.wait_for_calls(2).await;
        tokio::time::advance(Duration::from_millis(499)).await;
        assert_eq!(bluez.calls().len(), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        bluez.wait_for_calls(5).await;

        drop(session_tx);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(249)).await;
        assert_eq!(
            bluez
                .calls()
                .iter()
                .filter(|call| **call == Call::OpenSession)
                .count(),
            3
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        bluez.wait_for_calls(8).await;
        assert_eq!(
            bluez
                .calls()
                .iter()
                .filter(|call| **call == Call::OpenSession)
                .count(),
            4
        );
        stop(cancellation, task).await;
    }
}
