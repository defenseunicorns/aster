use super::map_bluer_error;
use crate::{
    ASTER_ROSTER_BEACON_V1_BYTES, ASTER_ROSTER_SERVICE_UUID, CanonicalLocator,
    CanonicalLocatorError, DriverError, DriverErrorKind, ValidatedControllerConfig,
    config::ControllerOperationBinding,
};
use bluer::{Address, AddressType, Uuid, adv};
use futures::{Stream, StreamExt, stream, stream::SelectAll};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    future::Future,
    pin::Pin,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};

pub(crate) const DISCOVERY_OBSERVATION_QUEUE_CAPACITY: usize = 64;
const DISCOVERY_DEVICE_WATCHER_CAPACITY: usize = 64;
const DISCOVERY_INITIAL_DEVICE_INSPECTION_CAPACITY: usize = 256;
const BACKEND_DRAIN_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) type PlatformFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DriverError>> + Send + 'a>>;
pub(crate) type TerminationFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub(crate) type ScanTerminationFuture<'a> =
    Pin<Box<dyn Future<Output = ScanTermination> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScanTermination {
    Requested,
    CapacityExceeded,
    Unexpected,
}

#[derive(Clone, Copy)]
enum BoundedRecord {
    Exact([u8; ASTER_ROSTER_BEACON_V1_BYTES]),
    WrongLength,
}

/// One bounded live Service Data observation from the owned scan.
#[derive(Clone, Copy)]
pub(crate) struct DiscoveryObservation {
    locator: CanonicalLocator,
    record: BoundedRecord,
}

impl DiscoveryObservation {
    pub(crate) fn new(
        address: Address,
        address_type: AddressType,
        record: &[u8],
    ) -> Result<Self, DiscoveryObservationError> {
        let locator = CanonicalLocator::new(address, address_type).map_err(
            |CanonicalLocatorError::NonLeAddress| DiscoveryObservationError::NonLeLocator,
        )?;
        let record = record
            .try_into()
            .map(BoundedRecord::Exact)
            .unwrap_or(BoundedRecord::WrongLength);
        Ok(Self { locator, record })
    }

    pub(crate) const fn locator(&self) -> CanonicalLocator {
        self.locator
    }

    pub(crate) fn record(&self) -> &[u8] {
        match &self.record {
            BoundedRecord::Exact(record) => record,
            BoundedRecord::WrongLength => &[],
        }
    }
}

impl fmt::Debug for DiscoveryObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscoveryObservation([REDACTED])")
    }
}

/// Closed translation failure before an observation enters the bounded queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiscoveryObservationError {
    NonLeLocator,
}

/// Exact private service UUID and authenticated record advertised together.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RosterAdvertisement {
    record: [u8; ASTER_ROSTER_BEACON_V1_BYTES],
}

impl fmt::Debug for RosterAdvertisement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterAdvertisement([REDACTED])")
    }
}

impl RosterAdvertisement {
    pub(crate) const fn new(record: [u8; ASTER_ROSTER_BEACON_V1_BYTES]) -> Self {
        Self { record }
    }

    pub(crate) const fn service_uuid(&self) -> [u8; 16] {
        ASTER_ROSTER_SERVICE_UUID
    }

    pub(crate) const fn record(&self) -> &[u8; ASTER_ROSTER_BEACON_V1_BYTES] {
        &self.record
    }
}

fn bluez_advertisement(roster: RosterAdvertisement) -> adv::Advertisement {
    let service_uuid = Uuid::from_bytes(roster.service_uuid());
    let service_uuids = [service_uuid].into_iter().collect();
    let service_data = [(service_uuid, roster.record().to_vec())]
        .into_iter()
        .collect();
    adv::Advertisement {
        advertisement_type: adv::Type::Peripheral,
        service_uuids,
        service_data,
        discoverable: Some(false),
        secondary_channel: Some(adv::SecondaryChannel::OneM),
        min_interval: Some(std::time::Duration::from_millis(250)),
        max_interval: Some(std::time::Duration::from_millis(250)),
        timeout: Some(std::time::Duration::from_secs(30)),
        ..adv::Advertisement::default()
    }
}

fn map_advertisement_registration_error(error: bluer::Error) -> DriverError {
    if matches!(
        &error.kind,
        bluer::ErrorKind::InvalidArguments | bluer::ErrorKind::InvalidLength
    ) {
        DriverError::new(
            DriverErrorKind::Unavailable,
            "BlueZ advertisement registration rejected",
        )
    } else {
        map_bluer_error(error)
    }
}

fn bluez_discovery_filter() -> bluer::DiscoveryFilter {
    let mut filter = bluer::DiscoveryFilter::default();
    filter
        .uuids
        .insert(Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID));
    filter.transport = bluer::DiscoveryTransport::Le;
    filter.duplicate_data = true;
    filter
}

fn observation_from_service_data(
    locator: CanonicalLocator,
    service_data: &HashMap<Uuid, Vec<u8>>,
) -> Option<DiscoveryObservation> {
    let record = service_data.get(&Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID))?;
    DiscoveryObservation::new(locator.address(), locator.address_type(), record).ok()
}

pub(crate) trait OwnedAdvertisement: Send {
    fn release(&mut self) -> PlatformFuture<'_, ()>;
    fn terminated(&self) -> TerminationFuture<'static>;
}

pub(crate) trait OwnedScan: Send {
    fn stop(&mut self) -> PlatformFuture<'_, ()>;
    fn termination(&self) -> ScanTerminationFuture<'static>;
}

trait AdvertisementBackend: Send + 'static {
    fn release(&mut self) -> PlatformFuture<'_, ()>;
    fn terminated(&self) -> TerminationFuture<'static>;
}

struct BluezAdvertisementBackend {
    handle: Option<adv::AdvertisementHandle>,
    owner_loss: watch::Receiver<bool>,
}

impl BluezAdvertisementBackend {
    const fn new(handle: adv::AdvertisementHandle, owner_loss: watch::Receiver<bool>) -> Self {
        Self {
            handle: Some(handle),
            owner_loss,
        }
    }
}

impl AdvertisementBackend for BluezAdvertisementBackend {
    fn release(&mut self) -> PlatformFuture<'_, ()> {
        self.handle.take();
        Box::pin(async { Ok(()) })
    }

    fn terminated(&self) -> TerminationFuture<'static> {
        wait_for_owner_loss(self.owner_loss.clone())
    }
}

enum AdvertisementCommand {
    Release(oneshot::Sender<Result<(), DriverError>>),
}

struct AdvertisementOwner {
    commands: mpsc::Sender<AdvertisementCommand>,
    ceased: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AdvertisementOwner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OwnedAdvertisement for AdvertisementOwner {
    fn release(&mut self) -> PlatformFuture<'_, ()> {
        let commands = self.commands.clone();
        let ceased = self.ceased.clone();
        Box::pin(async move {
            if *ceased.borrow() {
                return Ok(());
            }
            let (reply, result) = oneshot::channel();
            if commands
                .send(AdvertisementCommand::Release(reply))
                .await
                .is_err()
            {
                return if *ceased.borrow() {
                    Ok(())
                } else {
                    Err(owner_lost())
                };
            }
            match result.await {
                Ok(result) => result,
                Err(_) if *ceased.borrow() => Ok(()),
                Err(_) => Err(owner_lost()),
            }
        })
    }

    fn terminated(&self) -> TerminationFuture<'static> {
        let mut ceased = self.ceased.clone();
        Box::pin(async move {
            loop {
                if *ceased.borrow_and_update() || ceased.changed().await.is_err() {
                    return;
                }
            }
        })
    }
}

fn spawn_advertisement_owner<B>(backend: B) -> AdvertisementOwner
where
    B: AdvertisementBackend,
{
    let (commands, receiver) = mpsc::channel(1);
    let (ceased, ceased_receiver) = watch::channel(false);
    let task = tokio::spawn(run_advertisement_owner(backend, receiver, ceased));
    AdvertisementOwner {
        commands,
        ceased: ceased_receiver,
        task,
    }
}

async fn run_advertisement_owner<B>(
    mut backend: B,
    mut commands: mpsc::Receiver<AdvertisementCommand>,
    ceased: watch::Sender<bool>,
) where
    B: AdvertisementBackend,
{
    let mut terminated = backend.terminated();
    loop {
        enum OwnerEvent {
            Command(Option<AdvertisementCommand>),
            Terminated,
        }
        let event = tokio::select! {
            command = commands.recv() => OwnerEvent::Command(command),
            () = terminated.as_mut() => OwnerEvent::Terminated,
        };
        match event {
            OwnerEvent::Command(Some(AdvertisementCommand::Release(reply))) => {
                let mut release = backend.release();
                tokio::select! {
                    result = release.as_mut() => match result {
                        Ok(()) => {
                            let _ = reply.send(Ok(()));
                            break;
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    },
                    () = terminated.as_mut() => {
                        let _ = reply.send(Ok(()));
                        break;
                    }
                }
            }
            OwnerEvent::Command(None) => {
                let mut release = backend.release();
                tokio::select! {
                    _ = release.as_mut() => {},
                    () = terminated.as_mut() => {},
                }
                break;
            }
            OwnerEvent::Terminated => break,
        }
    }
    ceased.send_replace(true);
}

fn owner_lost() -> DriverError {
    DriverError::new(
        DriverErrorKind::Transport,
        "owned BlueZ advertisement task ended unexpectedly",
    )
}

enum ScanBackendEvent {
    Observation(DiscoveryObservation),
    CapacityExceeded,
    NeedsDrain,
    Terminated,
}

type ScanEventFuture<'a> = Pin<Box<dyn Future<Output = ScanBackendEvent> + Send + 'a>>;

trait ScanBackend: Send + 'static {
    fn stop(&mut self) -> PlatformFuture<'_, ()>;
    fn terminated(&self) -> TerminationFuture<'static>;
    fn next_event(&mut self) -> ScanEventFuture<'_>;
    fn force_owner_loss(&self) {}
}

enum ScanCommand {
    Stop(oneshot::Sender<Result<(), DriverError>>),
}

struct ScanOwner {
    commands: mpsc::Sender<ScanCommand>,
    termination: watch::Receiver<Option<ScanTermination>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ScanOwner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OwnedScan for ScanOwner {
    fn stop(&mut self) -> PlatformFuture<'_, ()> {
        let commands = self.commands.clone();
        let termination = self.termination.clone();
        Box::pin(async move {
            if termination.borrow().is_some() {
                return Ok(());
            }
            let (reply, result) = oneshot::channel();
            if commands.send(ScanCommand::Stop(reply)).await.is_err() {
                return if termination.borrow().is_some() {
                    Ok(())
                } else {
                    Err(scan_owner_lost())
                };
            }
            match result.await {
                Ok(result) => result,
                Err(_) if termination.borrow().is_some() => Ok(()),
                Err(_) => Err(scan_owner_lost()),
            }
        })
    }

    fn termination(&self) -> ScanTerminationFuture<'static> {
        let mut termination = self.termination.clone();
        Box::pin(async move {
            loop {
                if let Some(reason) = *termination.borrow_and_update() {
                    return reason;
                }
                if termination.changed().await.is_err() {
                    return ScanTermination::Unexpected;
                }
            }
        })
    }
}

fn spawn_scan_owner<B>(backend: B) -> StartedScan
where
    B: ScanBackend,
{
    let (commands, receiver) = mpsc::channel(1);
    let (observations, observation_receiver) = mpsc::channel(DISCOVERY_OBSERVATION_QUEUE_CAPACITY);
    let (termination, termination_receiver) = watch::channel(None);
    let task = tokio::spawn(run_scan_owner(backend, receiver, observations, termination));
    StartedScan::new(
        Box::new(ScanOwner {
            commands,
            termination: termination_receiver,
            task,
        }),
        observation_receiver,
    )
}

async fn run_scan_owner<B>(
    mut backend: B,
    mut commands: mpsc::Receiver<ScanCommand>,
    observations: mpsc::Sender<DiscoveryObservation>,
    termination: watch::Sender<Option<ScanTermination>>,
) where
    B: ScanBackend,
{
    let mut terminated = backend.terminated();
    let reason = loop {
        enum OwnerEvent {
            Command(Option<ScanCommand>),
            Backend(ScanBackendEvent),
            Terminated,
        }
        let event = tokio::select! {
            command = commands.recv() => OwnerEvent::Command(command),
            event = backend.next_event() => OwnerEvent::Backend(event),
            () = terminated.as_mut() => OwnerEvent::Terminated,
        };
        match event {
            OwnerEvent::Command(Some(ScanCommand::Stop(reply))) => {
                let mut stop = backend.stop();
                tokio::select! {
                    result = stop.as_mut() => match result {
                        Ok(()) => {
                            let _ = reply.send(Ok(()));
                            break ScanTermination::Requested;
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    },
                    () = terminated.as_mut() => {
                        let _ = reply.send(Ok(()));
                        break ScanTermination::Requested;
                    }
                }
            }
            OwnerEvent::Command(None) => {
                drain_scan_backend(&mut backend).await;
                break ScanTermination::Requested;
            }
            OwnerEvent::Backend(ScanBackendEvent::Observation(observation)) => {
                match observations.try_send(observation) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        drain_scan_backend(&mut backend).await;
                        break ScanTermination::CapacityExceeded;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        drain_scan_backend(&mut backend).await;
                        break ScanTermination::Requested;
                    }
                }
            }
            OwnerEvent::Backend(ScanBackendEvent::CapacityExceeded) => {
                drain_scan_backend(&mut backend).await;
                break ScanTermination::CapacityExceeded;
            }
            OwnerEvent::Backend(ScanBackendEvent::NeedsDrain) => {
                drain_scan_backend(&mut backend).await;
                break ScanTermination::Unexpected;
            }
            OwnerEvent::Backend(ScanBackendEvent::Terminated) => {
                break ScanTermination::Unexpected;
            }
            OwnerEvent::Terminated => break ScanTermination::Unexpected,
        }
    };
    termination.send_replace(Some(reason));
}

async fn drain_scan_backend(backend: &mut dyn ScanBackend) {
    let timed_out = {
        let mut terminated = backend.terminated();
        let mut stop = backend.stop();
        tokio::time::timeout(BACKEND_DRAIN_DEADLINE, async {
            tokio::select! {
                _ = stop.as_mut() => {},
                () = terminated.as_mut() => {},
            }
        })
        .await
        .is_err()
    };
    if timed_out {
        backend.force_owner_loss();
    }
}

fn scan_owner_lost() -> DriverError {
    DriverError::new(
        DriverErrorKind::Transport,
        "owned BlueZ scan task ended unexpectedly",
    )
}

type AdapterEventStream = Pin<Box<dyn Stream<Item = bluer::AdapterEvent> + Send>>;
type DeviceEventStream = Pin<Box<dyn Stream<Item = WatchedDeviceEvent> + Send>>;

async fn final_discovery_io<Adapter, T, Verify, VerifyFuture, Operation, OperationFuture>(
    controller: &ControllerOperationBinding,
    verify: Verify,
    operation: Operation,
) -> Result<T, DriverError>
where
    Verify: FnOnce() -> VerifyFuture,
    VerifyFuture: Future<Output = Result<Adapter, DriverError>>,
    Operation: FnOnce(Adapter) -> OperationFuture,
    OperationFuture: Future<Output = Result<T, DriverError>>,
{
    controller.ensure_current()?;
    let adapter = verify().await?;
    controller.ensure_current()?;
    operation(adapter).await
}

enum WatchedDeviceEvent {
    Property(u64, CanonicalLocator, bluer::DeviceEvent),
    Ended(u64, Address),
}

#[derive(Clone, Copy)]
struct WatchedDevice {
    generation: u64,
    locator: CanonicalLocator,
}

enum AddDeviceError {
    Capacity,
    Platform,
}

enum DeviceSnapshotError {
    Disappeared,
    Driver,
}

type DeviceSnapshotFuture =
    Pin<Box<dyn Future<Output = Result<Option<DiscoveryObservation>, DeviceSnapshotError>> + Send>>;

fn take_watch_generation(next: &mut u64) -> Option<u64> {
    let generation = *next;
    *next = next.checked_add(1)?;
    Some(generation)
}

trait DeviceWatchBackend: Clone + Send + 'static {
    fn subscribe(
        &self,
        address: Address,
        generation: u64,
    ) -> PlatformFuture<'_, Option<(CanonicalLocator, DeviceEventStream)>>;
    fn snapshot(&self, locator: CanonicalLocator) -> DeviceSnapshotFuture;
}

#[derive(Clone)]
struct BluezDeviceWatchBackend {
    guard: BluezControllerGuard,
}

impl DeviceWatchBackend for BluezDeviceWatchBackend {
    fn subscribe(
        &self,
        address: Address,
        generation: u64,
    ) -> PlatformFuture<'_, Option<(CanonicalLocator, DeviceEventStream)>> {
        Box::pin(subscribe_device(&self.guard, address, generation))
    }

    fn snapshot(&self, locator: CanonicalLocator) -> DeviceSnapshotFuture {
        let guard = self.guard.clone();
        Box::pin(async move { read_device_snapshot(&guard, locator).await })
    }
}

struct BluezScanBackend<D = BluezDeviceWatchBackend> {
    devices: D,
    raw_adapter_events: Option<AdapterEventStream>,
    discovery_owner_events: Option<AdapterEventStream>,
    device_events: SelectAll<DeviceEventStream>,
    watched: BTreeMap<Address, WatchedDevice>,
    retained_watch_generations: BTreeSet<u64>,
    next_watch_generation: u64,
    initial_capacity_exceeded: bool,
    owner_loss: watch::Receiver<bool>,
}

impl BluezScanBackend<BluezDeviceWatchBackend> {
    async fn start(
        guard: BluezControllerGuard,
        owner_loss: watch::Receiver<bool>,
    ) -> Result<Self, DriverError> {
        final_discovery_io(
            &guard.controller,
            || guard.adapter(),
            |adapter| async move {
                adapter
                    .set_discovery_filter(bluez_discovery_filter())
                    .await
                    .map_err(map_bluer_error)
            },
        )
        .await?;
        let raw_adapter_events = Box::pin(
            final_discovery_io(
                &guard.controller,
                || guard.adapter(),
                |adapter| async move { adapter.events().await.map_err(map_bluer_error) },
            )
            .await?,
        );
        let mut addresses = final_discovery_io(
            &guard.controller,
            || guard.adapter(),
            |adapter| async move { adapter.device_addresses().await.map_err(map_bluer_error) },
        )
        .await?;
        addresses.sort_unstable();
        let mut initial_capacity_exceeded =
            addresses.len() > DISCOVERY_INITIAL_DEVICE_INSPECTION_CAPACITY;
        addresses.truncate(DISCOVERY_INITIAL_DEVICE_INSPECTION_CAPACITY);
        let mut device_events = SelectAll::new();
        let mut watched = BTreeMap::new();
        let mut retained_watch_generations = BTreeSet::new();
        let mut next_watch_generation = 1_u64;
        for address in addresses {
            let generation =
                take_watch_generation(&mut next_watch_generation).ok_or_else(|| {
                    DriverError::new(DriverErrorKind::Transport, "BlueZ device watcher exhausted")
                })?;
            if let Some((locator, events)) = subscribe_device(&guard, address, generation).await? {
                if retained_watch_generations.len() >= DISCOVERY_DEVICE_WATCHER_CAPACITY {
                    initial_capacity_exceeded = true;
                    break;
                }
                watched.insert(
                    address,
                    WatchedDevice {
                        generation,
                        locator,
                    },
                );
                retained_watch_generations.insert(generation);
                device_events.push(events);
            }
        }
        let discovery_owner_events = Box::pin(
            final_discovery_io(
                &guard.controller,
                || guard.adapter(),
                |adapter| async move { adapter.discover_devices().await.map_err(map_bluer_error) },
            )
            .await?,
        );
        Ok(Self {
            devices: BluezDeviceWatchBackend { guard },
            raw_adapter_events: Some(raw_adapter_events),
            discovery_owner_events: Some(discovery_owner_events),
            device_events,
            watched,
            retained_watch_generations,
            next_watch_generation,
            initial_capacity_exceeded,
            owner_loss,
        })
    }
}

impl<D> BluezScanBackend<D>
where
    D: DeviceWatchBackend,
{
    async fn add_live_device(
        &mut self,
        address: Address,
    ) -> Result<Option<DiscoveryObservation>, AddDeviceError> {
        let watched = if let Some(watched) = self.watched.get(&address).copied() {
            watched
        } else {
            let generation = take_watch_generation(&mut self.next_watch_generation)
                .ok_or(AddDeviceError::Platform)?;
            let Some((locator, events)) = self
                .devices
                .subscribe(address, generation)
                .await
                .map_err(|_| AddDeviceError::Platform)?
            else {
                return Ok(None);
            };
            if self.retained_watch_generations.len() >= DISCOVERY_DEVICE_WATCHER_CAPACITY {
                return Err(AddDeviceError::Capacity);
            }
            let watched = WatchedDevice {
                generation,
                locator,
            };
            self.watched.insert(address, watched);
            self.retained_watch_generations.insert(generation);
            self.device_events.push(events);
            watched
        };

        match self.devices.snapshot(watched.locator).await {
            Ok(Some(observation)) if observation.locator() == watched.locator => {
                Ok(Some(observation))
            }
            Ok(Some(_)) => Err(AddDeviceError::Platform),
            Err(DeviceSnapshotError::Driver) => Err(AddDeviceError::Platform),
            Ok(None) | Err(DeviceSnapshotError::Disappeared) => Ok(None),
        }
    }

    fn remove_live_device(&mut self, address: Address) {
        self.watched.remove(&address);
    }

    fn watch_is_current(&self, generation: u64, locator: CanonicalLocator) -> bool {
        self.watched
            .get(&locator.address())
            .is_some_and(|watched| watched.generation == generation && watched.locator == locator)
    }

    async fn next_bluez_event(&mut self) -> ScanBackendEvent {
        if std::mem::take(&mut self.initial_capacity_exceeded) {
            return ScanBackendEvent::CapacityExceeded;
        }
        loop {
            enum SourceEvent {
                LiveAdapter(Option<bluer::AdapterEvent>),
                DiscoveryOwner(Option<bluer::AdapterEvent>),
                Device(Option<WatchedDeviceEvent>),
            }
            let Some(raw_adapter_events) = self.raw_adapter_events.as_mut() else {
                return ScanBackendEvent::Terminated;
            };
            let Some(discovery_owner_events) = self.discovery_owner_events.as_mut() else {
                return ScanBackendEvent::Terminated;
            };
            let event = {
                tokio::select! {
                    event = raw_adapter_events.next() => SourceEvent::LiveAdapter(event),
                    event = self.device_events.next(), if !self.device_events.is_empty() => {
                        SourceEvent::Device(event)
                    }
                    event = discovery_owner_events.next() => SourceEvent::DiscoveryOwner(event),
                }
            };
            match event {
                SourceEvent::LiveAdapter(None) | SourceEvent::DiscoveryOwner(None) => {
                    return ScanBackendEvent::Terminated;
                }
                SourceEvent::LiveAdapter(Some(bluer::AdapterEvent::DeviceAdded(address))) => {
                    match self.add_live_device(address).await {
                        Ok(Some(observation)) => {
                            return ScanBackendEvent::Observation(observation);
                        }
                        Ok(None) => {}
                        Err(AddDeviceError::Capacity) => {
                            return ScanBackendEvent::CapacityExceeded;
                        }
                        Err(AddDeviceError::Platform) => return ScanBackendEvent::NeedsDrain,
                    }
                }
                SourceEvent::LiveAdapter(Some(bluer::AdapterEvent::DeviceRemoved(address))) => {
                    self.remove_live_device(address);
                }
                SourceEvent::LiveAdapter(Some(bluer::AdapterEvent::PropertyChanged(_))) => {}
                SourceEvent::DiscoveryOwner(Some(_)) => {}
                SourceEvent::Device(Some(WatchedDeviceEvent::Ended(generation, address))) => {
                    self.retained_watch_generations.remove(&generation);
                    if self
                        .watched
                        .get(&address)
                        .is_some_and(|watched| watched.generation == generation)
                    {
                        self.watched.remove(&address);
                    }
                }
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(
                    generation,
                    locator,
                    bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::ServiceData(data)),
                ))) => {
                    if self.watch_is_current(generation, locator)
                        && let Some(observation) = observation_from_service_data(locator, &data)
                    {
                        return ScanBackendEvent::Observation(observation);
                    }
                }
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(
                    generation,
                    locator,
                    bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::AddressType(kind)),
                ))) if self.watch_is_current(generation, locator)
                    && kind != locator.address_type() =>
                {
                    return ScanBackendEvent::NeedsDrain;
                }
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(_, _, _))) => {}
                SourceEvent::Device(None) => return ScanBackendEvent::NeedsDrain,
            }
        }
    }
}

impl<D> ScanBackend for BluezScanBackend<D>
where
    D: DeviceWatchBackend,
{
    fn stop(&mut self) -> PlatformFuture<'_, ()> {
        self.raw_adapter_events.take();
        self.discovery_owner_events.take();
        Box::pin(async { Ok(()) })
    }

    fn terminated(&self) -> TerminationFuture<'static> {
        wait_for_owner_loss(self.owner_loss.clone())
    }

    fn next_event(&mut self) -> ScanEventFuture<'_> {
        Box::pin(self.next_bluez_event())
    }
}

async fn subscribe_device(
    guard: &BluezControllerGuard,
    address: Address,
    generation: u64,
) -> Result<Option<(CanonicalLocator, DeviceEventStream)>, DriverError> {
    let events = final_discovery_io(
        &guard.controller,
        || guard.adapter(),
        |adapter| async move {
            adapter
                .device(address)
                .map_err(map_bluer_error)?
                .events()
                .await
                .map_err(map_bluer_error)
        },
    )
    .await?;
    let address_type = final_discovery_io(
        &guard.controller,
        || guard.adapter(),
        |adapter| async move {
            adapter
                .device(address)
                .map_err(map_bluer_error)?
                .address_type()
                .await
                .map_err(map_bluer_error)
        },
    )
    .await?;
    let Ok(locator) = CanonicalLocator::new(address, address_type) else {
        return Ok(None);
    };
    let events = events
        .map(move |event| WatchedDeviceEvent::Property(generation, locator, event))
        .chain(stream::once(async move {
            WatchedDeviceEvent::Ended(generation, address)
        }));
    Ok(Some((locator, Box::pin(events))))
}

async fn read_device_snapshot(
    guard: &BluezControllerGuard,
    expected: CanonicalLocator,
) -> Result<Option<DiscoveryObservation>, DeviceSnapshotError> {
    let adapter = guard
        .adapter()
        .await
        .map_err(|_| DeviceSnapshotError::Driver)?;
    guard
        .controller
        .ensure_current()
        .map_err(|_| DeviceSnapshotError::Driver)?;
    let Some(service_data) = adapter
        .device(expected.address())
        .map_err(map_device_snapshot_error)?
        .service_data()
        .await
        .map_err(map_device_snapshot_error)?
    else {
        return Ok(None);
    };
    guard
        .controller
        .ensure_current()
        .map_err(|_| DeviceSnapshotError::Driver)?;
    let Some(record) = service_data.get(&Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID)) else {
        return Ok(None);
    };
    let record = record
        .as_slice()
        .try_into()
        .map(BoundedRecord::Exact)
        .unwrap_or(BoundedRecord::WrongLength);
    drop(service_data);
    let adapter = guard
        .adapter()
        .await
        .map_err(|_| DeviceSnapshotError::Driver)?;
    guard
        .controller
        .ensure_current()
        .map_err(|_| DeviceSnapshotError::Driver)?;
    let address_type = adapter
        .device(expected.address())
        .map_err(map_device_snapshot_error)?
        .address_type()
        .await
        .map_err(map_device_snapshot_error)?;
    guard
        .controller
        .ensure_current()
        .map_err(|_| DeviceSnapshotError::Driver)?;
    let Ok(locator) = CanonicalLocator::new(expected.address(), address_type) else {
        return Ok(None);
    };
    Ok(Some(DiscoveryObservation { locator, record }))
}

fn map_device_snapshot_error(error: bluer::Error) -> DeviceSnapshotError {
    match error.kind {
        bluer::ErrorKind::DoesNotExist | bluer::ErrorKind::NotFound => {
            DeviceSnapshotError::Disappeared
        }
        _ => DeviceSnapshotError::Driver,
    }
}

pub(crate) struct BluezDiscoveryPlatform {
    session: bluer::Session,
    owner_loss: BluezOwnerLoss,
}

#[derive(Clone)]
struct BluezControllerGuard {
    session: bluer::Session,
    controller: ControllerOperationBinding,
}

impl BluezControllerGuard {
    async fn adapter(&self) -> Result<bluer::Adapter, DriverError> {
        self.controller.ensure_current()?;
        let names = self
            .session
            .adapter_names()
            .await
            .map_err(map_bluer_error)?;
        if !names
            .iter()
            .any(|name| name == self.controller.adapter_name())
        {
            return Err(controller_unavailable());
        }
        self.controller.ensure_current()?;
        let adapter = self
            .session
            .adapter(self.controller.adapter_name())
            .map_err(map_bluer_error)?;
        self.controller.ensure_current()?;
        let powered = adapter.is_powered().await.map_err(map_bluer_error)?;
        self.controller.ensure_current()?;
        let address = adapter.address().await.map_err(map_bluer_error)?;
        self.controller.ensure_current()?;
        let address_type = adapter.address_type().await.map_err(map_bluer_error)?;
        self.controller.ensure_current()?;
        if !powered
            || address != self.controller.local_address()
            || address_type != self.controller.local_address_type()
        {
            return Err(controller_unavailable());
        }
        Ok(adapter)
    }
}

#[derive(Clone)]
pub(crate) struct BluezOwnerLoss(watch::Sender<bool>);

impl BluezOwnerLoss {
    fn channel() -> (Self, watch::Receiver<bool>) {
        let (sender, receiver) = watch::channel(false);
        (Self(sender), receiver)
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.subscribe()
    }

    pub(crate) fn force(&self) {
        self.0.send_replace(true);
    }
}

fn wait_for_owner_loss(mut owner_loss: watch::Receiver<bool>) -> TerminationFuture<'static> {
    Box::pin(async move {
        loop {
            if *owner_loss.borrow_and_update() || owner_loss.changed().await.is_err() {
                return;
            }
        }
    })
}

impl BluezDiscoveryPlatform {
    pub(crate) async fn open() -> Result<Self, DriverError> {
        let session = bluer::Session::new().await.map_err(map_bluer_error)?;
        let (owner_loss, _) = BluezOwnerLoss::channel();
        Ok(Self {
            session,
            owner_loss,
        })
    }

    pub(crate) fn owner_loss(&self) -> BluezOwnerLoss {
        self.owner_loss.clone()
    }

    fn guard(&self, controller: &ValidatedControllerConfig) -> BluezControllerGuard {
        BluezControllerGuard {
            session: self.session.clone(),
            controller: controller.operation_binding(),
        }
    }
}

impl DiscoveryPlatform for BluezDiscoveryPlatform {
    fn start_advertisement<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
        advertisement: RosterAdvertisement,
    ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
        Box::pin(async move {
            let guard = self.guard(controller);
            // Passive controller compatibility is established by controller_probe.
            // Exact registration is the operational advertisement capability
            // and permission check for this policy-authorized radio epoch.
            let handle = final_discovery_io(
                &guard.controller,
                || guard.adapter(),
                |adapter| async move {
                    adapter
                        .advertise(bluez_advertisement(advertisement))
                        .await
                        .map_err(map_advertisement_registration_error)
                },
            )
            .await?;
            Ok(
                Box::new(spawn_advertisement_owner(BluezAdvertisementBackend::new(
                    handle,
                    self.owner_loss.subscribe(),
                ))) as Box<dyn OwnedAdvertisement>,
            )
        })
    }

    fn start_scan<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
    ) -> PlatformFuture<'a, StartedScan> {
        Box::pin(async move {
            BluezScanBackend::start(self.guard(controller), self.owner_loss.subscribe())
                .await
                .map(spawn_scan_owner)
        })
    }

    fn force_owner_loss(&self) {
        self.owner_loss.force();
    }
}

fn controller_unavailable() -> DriverError {
    DriverError::new(
        DriverErrorKind::Unavailable,
        "configured Bluetooth controller is unavailable",
    )
}

pub(crate) struct StartedScan {
    owner: Box<dyn OwnedScan>,
    observations: mpsc::Receiver<DiscoveryObservation>,
}

impl StartedScan {
    pub(crate) const fn new(
        owner: Box<dyn OwnedScan>,
        observations: mpsc::Receiver<DiscoveryObservation>,
    ) -> Self {
        Self {
            owner,
            observations,
        }
    }

    pub(crate) fn into_parts(self) -> (Box<dyn OwnedScan>, mpsc::Receiver<DiscoveryObservation>) {
        (self.owner, self.observations)
    }
}

pub(crate) trait DiscoveryPlatform: Send + Sync {
    fn start_advertisement<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
        advertisement: RosterAdvertisement,
    ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>>;

    fn start_scan<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
    ) -> PlatformFuture<'a, StartedScan>;

    fn force_owner_loss(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContactLimits, ControllerConfig, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
        LeasedDiscoveryCredentialSet, RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES,
        RosteredAdapterConfig, RosteredDiscoveryConfig, RosteredSupervisorConfig,
        ValidatedRosteredSupervisorConfig,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::sync::{Notify, mpsc};

    fn config() -> ValidatedRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        RosteredAdapterConfig::Enabled(Box::new(RosteredSupervisorConfig {
            controller: ControllerConfig {
                adapter_name: "hci7".to_owned(),
                local_address: Address::new([2, 0, 0, 0, 0, 1]),
                local_address_type: AddressType::LeRandom,
            },
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
        }))
        .validate()
        .unwrap()
        .unwrap()
    }

    fn automatic_controller(
        cancellation: &crate::LifecycleCancellation,
    ) -> ValidatedControllerConfig {
        ValidatedControllerConfig::for_epoch(
            "hci7".to_owned(),
            Address::new([2, 0, 0, 0, 0, 1]),
            AddressType::LeRandom,
            1,
            cancellation.observer(),
        )
        .unwrap()
    }

    struct FakeOwner {
        stopped: Arc<AtomicBool>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for FakeOwner {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.stopped.store(true, Ordering::Release);
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move { terminated.notified().await })
        }
    }

    impl OwnedScan for FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.stopped.store(true, Ordering::Release);
                Ok(())
            })
        }

        fn termination(&self) -> ScanTerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move {
                terminated.notified().await;
                ScanTermination::Unexpected
            })
        }
    }

    struct FakePlatform {
        advertisement: Mutex<Option<RosterAdvertisement>>,
        sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
        advertisement_released: Arc<AtomicBool>,
        advertisement_terminated: Arc<Notify>,
        scan_stopped: Arc<AtomicBool>,
        scan_terminated: Arc<Notify>,
    }

    impl DiscoveryPlatform for FakePlatform {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            *self.advertisement.lock().unwrap() = Some(advertisement);
            let owner = FakeOwner {
                stopped: self.advertisement_released.clone(),
                terminated: self.advertisement_terminated.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            let (sender, receiver) = mpsc::channel(DISCOVERY_OBSERVATION_QUEUE_CAPACITY);
            *self.sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stopped: self.scan_stopped.clone(),
                terminated: self.scan_terminated.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    receiver,
                ))
            })
        }
    }

    #[test]
    fn observation_translation_is_canonical_and_bounds_service_data() {
        let public = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 1]),
            AddressType::LePublic,
            &[0x55; 40],
        )
        .unwrap();
        let random = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 2]),
            AddressType::LeRandom,
            &[0x66; 40],
        )
        .unwrap();
        assert_eq!(public.locator().address_type(), AddressType::LePublic);
        assert_eq!(random.locator().address_type(), AddressType::LeRandom);
        assert_eq!(public.record(), &[0x55; 40]);
        assert_eq!(
            DiscoveryObservation::new(Address::new([1; 6]), AddressType::BrEdr, &[0; 40])
                .unwrap_err(),
            DiscoveryObservationError::NonLeLocator
        );

        let oversized = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 3]),
            AddressType::LeRandom,
            &[0x77; 41],
        )
        .unwrap();
        assert!(oversized.record().is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_exact_verification_blocks_final_rf_call() {
        let cancellation = crate::LifecycleCancellation::new();
        let binding = automatic_controller(&cancellation).operation_binding();
        let calls = AtomicUsize::new(0);

        let result = final_discovery_io(
            &binding,
            || async {
                cancellation.cancel();
                Ok(())
            },
            |_| async {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
        .await;

        assert_eq!(result.unwrap_err().kind(), DriverErrorKind::Cancelled);
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn exact_identity_change_blocks_final_rf_call() {
        let cancellation = crate::LifecycleCancellation::new();
        let binding = automatic_controller(&cancellation).operation_binding();
        let calls = AtomicUsize::new(0);

        let result = final_discovery_io(
            &binding,
            || async {
                Err::<(), _>(DriverError::new(
                    DriverErrorKind::Unavailable,
                    "test controller identity changed",
                ))
            },
            |_| async {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
        .await;

        assert_eq!(result.unwrap_err().kind(), DriverErrorKind::Unavailable);
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn production_advertisement_uses_the_frozen_extended_tuple() {
        let record = [0x55; ASTER_ROSTER_BEACON_V1_BYTES];
        let advertisement = bluez_advertisement(RosterAdvertisement::new(record));
        let service_uuid = bluer::Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID);

        assert_eq!(
            advertisement.advertisement_type,
            bluer::adv::Type::Peripheral
        );
        assert_eq!(
            advertisement.service_uuids.into_iter().collect::<Vec<_>>(),
            [service_uuid]
        );
        assert_eq!(advertisement.service_data.len(), 1);
        assert_eq!(
            advertisement.service_data.get(&service_uuid),
            Some(&record.to_vec())
        );
        assert_eq!(advertisement.discoverable, Some(false));
        assert_eq!(
            advertisement.secondary_channel,
            Some(bluer::adv::SecondaryChannel::OneM)
        );
        assert_eq!(advertisement.min_interval, Some(Duration::from_millis(250)));
        assert_eq!(advertisement.max_interval, Some(Duration::from_millis(250)));
        assert_eq!(advertisement.timeout, Some(Duration::from_secs(30)));
        assert!(advertisement.manufacturer_data.is_empty());
        assert!(advertisement.solicit_uuids.is_empty());
        assert!(advertisement.system_includes.is_empty());
        assert!(advertisement.local_name.is_none());
        assert!(advertisement.appearance.is_none());
        assert!(advertisement.duration.is_none());
        assert!(advertisement.tx_power.is_none());
    }

    #[test]
    fn advertisement_registration_errors_preserve_operational_categories() {
        for kind in [
            bluer::ErrorKind::InvalidArguments,
            bluer::ErrorKind::InvalidLength,
        ] {
            let error = map_advertisement_registration_error(bluer::Error {
                kind,
                message: "sensitive BlueZ detail".to_owned(),
            });

            assert_eq!(
                error,
                DriverError::new(
                    DriverErrorKind::Unavailable,
                    "BlueZ advertisement registration rejected",
                )
            );
        }

        let timeout = map_advertisement_registration_error(bluer::Error {
            kind: bluer::ErrorKind::AuthenticationTimeout,
            message: "sensitive BlueZ detail".to_owned(),
        });
        assert_eq!(
            timeout,
            DriverError::new(DriverErrorKind::Timeout, "BlueZ operation failed")
        );
    }

    #[test]
    fn production_scan_filter_is_exact_le_uuid_with_duplicate_data() {
        let filter = bluez_discovery_filter();
        assert_eq!(filter.uuids.len(), 1);
        assert!(
            filter
                .uuids
                .contains(&bluer::Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID))
        );
        assert_eq!(filter.transport, bluer::DiscoveryTransport::Le);
        assert!(filter.duplicate_data);
        assert!(filter.rssi.is_none());
        assert!(filter.pathloss.is_none());
        assert!(!filter.discoverable);
        assert!(filter.pattern.is_none());
    }

    #[test]
    fn service_data_translation_accepts_only_the_aster_uuid() {
        let locator =
            CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom).unwrap();
        let mut service_data = std::collections::HashMap::new();
        service_data.insert(bluer::Uuid::from_u128(1), vec![0x11; 40]);
        assert!(observation_from_service_data(locator, &service_data).is_none());

        service_data.insert(
            bluer::Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID),
            vec![0x55; 40],
        );
        let observation = observation_from_service_data(locator, &service_data).unwrap();
        assert_eq!(observation.locator(), locator);
        assert_eq!(observation.record(), &[0x55; 40]);
    }

    #[derive(Clone)]
    struct ScriptedDeviceWatchBackend {
        locator: CanonicalLocator,
        snapshot_locator: CanonicalLocator,
        record: [u8; ASTER_ROSTER_BEACON_V1_BYTES],
        snapshot_disappeared: bool,
    }

    impl DeviceWatchBackend for ScriptedDeviceWatchBackend {
        fn subscribe(
            &self,
            _address: Address,
            _generation: u64,
        ) -> PlatformFuture<'_, Option<(CanonicalLocator, DeviceEventStream)>> {
            let locator = self.locator;
            Box::pin(async move {
                Ok(Some((
                    locator,
                    Box::pin(stream::pending::<WatchedDeviceEvent>()) as DeviceEventStream,
                )))
            })
        }

        fn snapshot(&self, locator: CanonicalLocator) -> DeviceSnapshotFuture {
            if self.snapshot_disappeared {
                return Box::pin(async { Err(DeviceSnapshotError::Disappeared) });
            }
            let snapshot = (locator == self.locator)
                .then(|| {
                    DiscoveryObservation::new(
                        self.snapshot_locator.address(),
                        self.snapshot_locator.address_type(),
                        &self.record,
                    )
                })
                .transpose()
                .expect("scripted locator is LE");
            Box::pin(async move { Ok(snapshot) })
        }
    }

    fn test_scan<D>(devices: D, raw_adapter_events: AdapterEventStream) -> BluezScanBackend<D>
    where
        D: DeviceWatchBackend,
    {
        let (_owner_loss, owner_loss) = watch::channel(false);
        BluezScanBackend {
            devices,
            raw_adapter_events: Some(raw_adapter_events),
            discovery_owner_events: Some(Box::pin(stream::pending())),
            device_events: SelectAll::new(),
            watched: BTreeMap::new(),
            retained_watch_generations: BTreeSet::new(),
            next_watch_generation: 1,
            initial_capacity_exceeded: false,
            owner_loss,
        }
    }

    #[tokio::test]
    async fn device_added_after_prearming_is_snapshot_admitted() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let locator = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let record = [0x55; ASTER_ROSTER_BEACON_V1_BYTES];
        let raw_adapter_events =
            stream::once(async move { bluer::AdapterEvent::DeviceAdded(address) });
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator,
                snapshot_locator: locator,
                record,
                snapshot_disappeared: false,
            },
            Box::pin(raw_adapter_events),
        );

        let ScanBackendEvent::Observation(observation) = backend.next_bluez_event().await else {
            panic!("live new-device snapshot must produce one observation");
        };
        assert_eq!(observation.locator(), locator);
        assert_eq!(observation.record(), &record);
    }

    #[tokio::test]
    async fn raw_add_snapshots_an_already_prearmed_device() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let locator = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let record = [0x55; ASTER_ROSTER_BEACON_V1_BYTES];
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator,
                snapshot_locator: locator,
                record,
                snapshot_disappeared: false,
            },
            Box::pin(stream::pending()),
        );
        backend.watched.insert(
            address,
            WatchedDevice {
                generation: 1,
                locator,
            },
        );
        backend.retained_watch_generations.insert(1);

        let Ok(Some(observation)) = backend.add_live_device(address).await else {
            panic!("a raw add must snapshot its prearmed watcher");
        };
        assert_eq!(observation.locator(), locator);
        assert_eq!(observation.record(), &record);
    }

    #[tokio::test]
    async fn address_type_change_during_snapshot_stops_the_scan() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let subscribed = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let changed = CanonicalLocator::new(address, AddressType::LePublic).unwrap();
        let raw_adapter_events =
            stream::once(async move { bluer::AdapterEvent::DeviceAdded(address) });
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator: subscribed,
                snapshot_locator: changed,
                record: [0x55; ASTER_ROSTER_BEACON_V1_BYTES],
                snapshot_disappeared: false,
            },
            Box::pin(raw_adapter_events),
        );

        assert!(matches!(
            backend.next_bluez_event().await,
            ScanBackendEvent::NeedsDrain
        ));
    }

    #[tokio::test]
    async fn old_watcher_end_does_not_remove_replacement() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let locator = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let record = [0x55; ASTER_ROSTER_BEACON_V1_BYTES];
        let service_data: HashMap<_, _> =
            [(Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID), record.to_vec())]
                .into_iter()
                .collect();
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator,
                snapshot_locator: locator,
                record,
                snapshot_disappeared: false,
            },
            Box::pin(stream::pending()),
        );
        backend.watched.insert(
            address,
            WatchedDevice {
                generation: 2,
                locator,
            },
        );
        backend.retained_watch_generations.extend([1, 2]);
        backend.device_events.push(Box::pin(stream::iter([
            WatchedDeviceEvent::Ended(1, address),
            WatchedDeviceEvent::Property(
                2,
                locator,
                bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::ServiceData(
                    service_data,
                )),
            ),
        ])));

        let ScanBackendEvent::Observation(observation) = backend.next_bluez_event().await else {
            panic!("replacement watcher must still emit observations");
        };
        assert_eq!(observation.locator(), locator);
        assert_eq!(observation.record(), &record);
        assert_eq!(backend.retained_watch_generations, BTreeSet::from([2]));
    }

    #[tokio::test]
    async fn retired_device_streams_remain_charged_until_end() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let locator = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator,
                snapshot_locator: locator,
                record: [0x55; ASTER_ROSTER_BEACON_V1_BYTES],
                snapshot_disappeared: false,
            },
            Box::pin(stream::pending()),
        );

        for _ in 0..DISCOVERY_DEVICE_WATCHER_CAPACITY {
            assert!(backend.add_live_device(address).await.is_ok());
            backend.remove_live_device(address);
        }

        assert!(matches!(
            backend.add_live_device(address).await,
            Err(AddDeviceError::Capacity)
        ));
    }

    #[derive(Clone)]
    struct IgnoredDeviceWatchBackend;

    impl DeviceWatchBackend for IgnoredDeviceWatchBackend {
        fn subscribe(
            &self,
            _address: Address,
            _generation: u64,
        ) -> PlatformFuture<'_, Option<(CanonicalLocator, DeviceEventStream)>> {
            Box::pin(async { Ok(None) })
        }

        fn snapshot(&self, _locator: CanonicalLocator) -> DeviceSnapshotFuture {
            unreachable!("an ignored device has no snapshot")
        }
    }

    #[tokio::test]
    async fn non_le_device_does_not_exhaust_retained_watcher_capacity() {
        let mut backend = test_scan(IgnoredDeviceWatchBackend, Box::pin(stream::pending()));
        backend
            .retained_watch_generations
            .extend(1..=DISCOVERY_DEVICE_WATCHER_CAPACITY as u64);

        assert!(matches!(
            backend
                .add_live_device(Address::new([2, 0, 0, 0, 0, 9]))
                .await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn device_disappearance_during_snapshot_is_not_a_scan_failure() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let locator = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();
        let mut backend = test_scan(
            ScriptedDeviceWatchBackend {
                locator,
                snapshot_locator: locator,
                record: [0x55; ASTER_ROSTER_BEACON_V1_BYTES],
                snapshot_disappeared: true,
            },
            Box::pin(stream::pending()),
        );

        assert!(matches!(backend.add_live_device(address).await, Ok(None)));
        assert_eq!(backend.retained_watch_generations.len(), 1);
    }

    struct BlockingAdvertisementBackend {
        release_calls: Arc<AtomicUsize>,
        release_completed: Arc<Notify>,
    }

    struct TerminatingAdvertisementBackend {
        release_started: Arc<Notify>,
        terminated: Arc<Notify>,
    }

    impl AdvertisementBackend for TerminatingAdvertisementBackend {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.release_started.notify_one();
                pending().await
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move { terminated.notified().await })
        }
    }

    impl AdvertisementBackend for BlockingAdvertisementBackend {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.release_calls.fetch_add(1, Ordering::AcqRel);
                self.release_completed.notified().await;
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn advertisement_owner_completes_local_release_after_waiter_deadline() {
        let release_calls = Arc::new(AtomicUsize::new(0));
        let release_completed = Arc::new(Notify::new());
        let mut owner = spawn_advertisement_owner(BlockingAdvertisementBackend {
            release_calls: release_calls.clone(),
            release_completed: release_completed.clone(),
        });

        let result = tokio::time::timeout(Duration::from_secs(5), owner.release()).await;
        assert!(result.is_err());
        assert_eq!(release_calls.load(Ordering::Acquire), 1);

        release_completed.notify_one();
        owner.terminated().await;
        assert_eq!(release_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn advertisement_owner_observes_termination_while_release_is_blocked() {
        let release_started = Arc::new(Notify::new());
        let terminated = Arc::new(Notify::new());
        let mut owner = spawn_advertisement_owner(TerminatingAdvertisementBackend {
            release_started: release_started.clone(),
            terminated: terminated.clone(),
        });
        let release = tokio::spawn(async move {
            release_started.notified().await;
            terminated.notify_one();
        });

        owner.release().await.unwrap();
        release.await.unwrap();
        owner.terminated().await;
    }

    #[tokio::test]
    async fn bluez_owner_loss_ends_local_waiters() {
        let (owner_loss, receiver) = BluezOwnerLoss::channel();
        let waiter = tokio::spawn(wait_for_owner_loss(receiver));

        owner_loss.force();

        waiter.await.unwrap();
    }

    struct QueuedScanBackend {
        events: VecDeque<ScanBackendEvent>,
        stop_calls: Arc<AtomicUsize>,
    }

    struct TerminatingScanBackend {
        stop_started: Arc<Notify>,
        terminated: Arc<Notify>,
    }

    struct BlockingDrainScanBackend {
        event: Option<ScanBackendEvent>,
        owner_loss_forced: Arc<AtomicBool>,
    }

    impl ScanBackend for BlockingDrainScanBackend {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(pending())
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }

        fn next_event(&mut self) -> ScanEventFuture<'_> {
            match self.event.take() {
                Some(event) => Box::pin(async move { event }),
                None => Box::pin(pending()),
            }
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(true, Ordering::Release);
        }
    }

    impl ScanBackend for TerminatingScanBackend {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.stop_started.notify_one();
                pending().await
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move { terminated.notified().await })
        }

        fn next_event(&mut self) -> ScanEventFuture<'_> {
            Box::pin(pending())
        }
    }

    impl ScanBackend for QueuedScanBackend {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.stop_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }

        fn next_event(&mut self) -> ScanEventFuture<'_> {
            match self.events.pop_front() {
                Some(event) => Box::pin(async move { event }),
                None => Box::pin(pending()),
            }
        }
    }

    #[tokio::test]
    async fn scan_queue_overflow_stops_the_owned_window_without_dropping_and_continuing() {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let events = (0..=DISCOVERY_OBSERVATION_QUEUE_CAPACITY)
            .map(|index| {
                ScanBackendEvent::Observation(
                    DiscoveryObservation::new(
                        Address::new([2, 0, 0, 0, 0, index as u8]),
                        AddressType::LeRandom,
                        &[index as u8; ASTER_ROSTER_BEACON_V1_BYTES],
                    )
                    .unwrap(),
                )
            })
            .collect();
        let started = spawn_scan_owner(QueuedScanBackend {
            events,
            stop_calls: stop_calls.clone(),
        });
        let (owner, mut observations) = started.into_parts();

        assert_eq!(owner.termination().await, ScanTermination::CapacityExceeded);
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
        let mut count = 0;
        while observations.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, DISCOVERY_OBSERVATION_QUEUE_CAPACITY);
    }

    #[tokio::test]
    async fn device_watcher_capacity_stops_and_reports_bounded_idle_reason() {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let started = spawn_scan_owner(QueuedScanBackend {
            events: [ScanBackendEvent::CapacityExceeded].into_iter().collect(),
            stop_calls: stop_calls.clone(),
        });
        let (owner, _observations) = started.into_parts();

        assert_eq!(owner.termination().await, ScanTermination::CapacityExceeded);
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_scan_drain_forces_owner_loss_at_the_platform_deadline() {
        let owner_loss_forced = Arc::new(AtomicBool::new(false));
        let started = spawn_scan_owner(BlockingDrainScanBackend {
            event: Some(ScanBackendEvent::CapacityExceeded),
            owner_loss_forced: owner_loss_forced.clone(),
        });
        let (owner, _observations) = started.into_parts();
        let termination = tokio::spawn(async move { owner.termination().await });

        tokio::time::advance(BACKEND_DRAIN_DEADLINE).await;

        assert_eq!(
            termination.await.unwrap(),
            ScanTermination::CapacityExceeded
        );
        assert!(owner_loss_forced.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn scan_owner_observes_termination_while_stop_is_blocked() {
        let stop_started = Arc::new(Notify::new());
        let terminated = Arc::new(Notify::new());
        let started = spawn_scan_owner(TerminatingScanBackend {
            stop_started: stop_started.clone(),
            terminated: terminated.clone(),
        });
        let (mut owner, _observations) = started.into_parts();
        let release = tokio::spawn(async move {
            stop_started.notified().await;
            terminated.notify_one();
        });

        owner.stop().await.unwrap();
        release.await.unwrap();
        assert_eq!(owner.termination().await, ScanTermination::Requested);
    }

    #[tokio::test]
    async fn fake_platform_preserves_exact_advertisement_queue_and_owned_release() {
        let platform = FakePlatform {
            advertisement: Mutex::new(None),
            sender: Mutex::new(None),
            advertisement_released: Arc::new(AtomicBool::new(false)),
            advertisement_terminated: Arc::new(Notify::new()),
            scan_stopped: Arc::new(AtomicBool::new(false)),
            scan_terminated: Arc::new(Notify::new()),
        };
        let record = [0x55; 40];
        let advertisement = RosterAdvertisement::new(record);
        let mut owned_advertisement = platform
            .start_advertisement(config().controller(), advertisement)
            .await
            .unwrap();
        assert_eq!(
            platform
                .advertisement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .service_uuid(),
            ASTER_ROSTER_SERVICE_UUID
        );
        assert_eq!(
            platform
                .advertisement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .record(),
            &record
        );
        let debug = format!("{advertisement:?}");
        assert_eq!(debug, "RosterAdvertisement([REDACTED])");
        assert!(!debug.contains("55"));
        platform.advertisement_terminated.notify_one();
        owned_advertisement.terminated().await;
        owned_advertisement.release().await.unwrap();
        assert!(platform.advertisement_released.load(Ordering::Acquire));

        let started_scan = platform.start_scan(config().controller()).await.unwrap();
        let (mut owned_scan, _receiver) = started_scan.into_parts();
        let sender = platform.sender.lock().unwrap().take().unwrap();
        for index in 0..DISCOVERY_OBSERVATION_QUEUE_CAPACITY {
            sender
                .try_send(
                    DiscoveryObservation::new(
                        Address::new([2, 0, 0, 0, 0, index as u8]),
                        AddressType::LeRandom,
                        &[index as u8; 40],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        assert!(matches!(
            sender.try_send(
                DiscoveryObservation::new(
                    Address::new([2, 0, 0, 0, 0, 99]),
                    AddressType::LeRandom,
                    &[0x99; 40],
                )
                .unwrap()
            ),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        platform.scan_terminated.notify_one();
        assert_eq!(owned_scan.termination().await, ScanTermination::Unexpected);
        owned_scan.stop().await.unwrap();
        assert!(platform.scan_stopped.load(Ordering::Acquire));
    }
}
