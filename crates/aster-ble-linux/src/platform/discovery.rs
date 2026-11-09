use super::map_bluer_error;
use crate::{
    ASTER_ROSTER_BEACON_V1_BYTES, ASTER_ROSTER_SERVICE_UUID, CanonicalLocator,
    CanonicalLocatorError, DriverError, DriverErrorKind, ValidatedControllerConfig,
};
use bluer::{Address, AddressType, Uuid, adv};
use futures::{Stream, StreamExt, stream, stream::SelectAll};
use std::{
    collections::{BTreeSet, HashMap},
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

fn validate_advertising_support(
    supported_instances: u8,
    active_instances: u8,
    secondary_channels: &BTreeSet<adv::SecondaryChannel>,
    capabilities: &adv::Capabilities,
) -> Result<(), DriverError> {
    if supported_instances <= active_instances
        || !secondary_channels.contains(&adv::SecondaryChannel::OneM)
        || capabilities.max_advertisement_length < 79
    {
        return Err(advertising_unsupported());
    }
    Ok(())
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
    fn stop(&mut self) -> PlatformFuture<'_, ()>;
    fn terminated(&self) -> TerminationFuture<'static>;
}

pub(crate) trait OwnedScan: Send {
    fn stop(&mut self) -> PlatformFuture<'_, ()>;
    fn termination(&self) -> ScanTerminationFuture<'static>;
}

trait AdvertisementBackend: Send + 'static {
    fn stop(&mut self) -> PlatformFuture<'_, ()>;
    fn terminated(&self) -> TerminationFuture<'static>;
}

impl AdvertisementBackend for adv::AdvertisementHandle {
    fn stop(&mut self) -> PlatformFuture<'_, ()> {
        Box::pin(async {
            adv::AdvertisementHandle::stop(self)
                .await
                .map_err(map_bluer_error)
        })
    }

    fn terminated(&self) -> TerminationFuture<'static> {
        let terminated = self.termination();
        Box::pin(async move {
            let _ = terminated.await;
        })
    }
}

enum AdvertisementCommand {
    Stop(oneshot::Sender<Result<(), DriverError>>),
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
    fn stop(&mut self) -> PlatformFuture<'_, ()> {
        let commands = self.commands.clone();
        let ceased = self.ceased.clone();
        Box::pin(async move {
            if *ceased.borrow() {
                return Ok(());
            }
            let (reply, result) = oneshot::channel();
            if commands
                .send(AdvertisementCommand::Stop(reply))
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
            OwnerEvent::Command(Some(AdvertisementCommand::Stop(reply))) => {
                let mut stop = backend.stop();
                tokio::select! {
                    result = stop.as_mut() => match result {
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
                let mut stop = backend.stop();
                tokio::select! {
                    _ = stop.as_mut() => {},
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

enum WatchedDeviceEvent {
    Property(CanonicalLocator, bluer::DeviceEvent),
    Ended(Address),
}

enum AddDeviceError {
    Capacity,
    Platform,
}

struct BluezScanBackend {
    adapter: bluer::Adapter,
    session: bluer::DiscoverySession,
    adapter_events: AdapterEventStream,
    device_events: SelectAll<DeviceEventStream>,
    watched: BTreeSet<Address>,
    initial_capacity_exceeded: bool,
    owner_loss: BluezOwnerLoss,
}

impl BluezScanBackend {
    async fn start(
        adapter: bluer::Adapter,
        owner_loss: BluezOwnerLoss,
    ) -> Result<Self, DriverError> {
        adapter
            .set_discovery_filter(bluez_discovery_filter())
            .await
            .map_err(map_bluer_error)?;
        let adapter_events = Box::pin(adapter.events().await.map_err(map_bluer_error)?);
        let mut addresses = adapter.device_addresses().await.map_err(map_bluer_error)?;
        addresses.sort_unstable();
        let mut initial_capacity_exceeded =
            addresses.len() > DISCOVERY_INITIAL_DEVICE_INSPECTION_CAPACITY;
        addresses.truncate(DISCOVERY_INITIAL_DEVICE_INSPECTION_CAPACITY);
        let mut device_events = SelectAll::new();
        let mut watched = BTreeSet::new();
        for address in addresses {
            let device = adapter.device(address).map_err(map_bluer_error)?;
            let service_data = device.service_data().await.map_err(map_bluer_error)?;
            if !service_data.is_some_and(|data| {
                data.contains_key(&bluer::Uuid::from_bytes(ASTER_ROSTER_SERVICE_UUID))
            }) {
                continue;
            }
            if watched.len() >= DISCOVERY_DEVICE_WATCHER_CAPACITY {
                initial_capacity_exceeded = true;
                break;
            }
            if let Some(events) = subscribe_device(&adapter, address).await? {
                watched.insert(address);
                device_events.push(events);
            }
        }
        let session = adapter
            .start_discovery_session()
            .await
            .map_err(map_bluer_error)?;
        Ok(Self {
            adapter,
            session,
            adapter_events,
            device_events,
            watched,
            initial_capacity_exceeded,
            owner_loss,
        })
    }

    async fn add_device(&mut self, address: Address) -> Result<(), AddDeviceError> {
        if self.watched.contains(&address) {
            return Ok(());
        }
        if self.watched.len() >= DISCOVERY_DEVICE_WATCHER_CAPACITY {
            return Err(AddDeviceError::Capacity);
        }
        if let Some(events) = subscribe_device(&self.adapter, address)
            .await
            .map_err(|_| AddDeviceError::Platform)?
        {
            self.watched.insert(address);
            self.device_events.push(events);
        }
        Ok(())
    }

    async fn next_bluez_event(&mut self) -> ScanBackendEvent {
        if std::mem::take(&mut self.initial_capacity_exceeded) {
            return ScanBackendEvent::CapacityExceeded;
        }
        loop {
            enum SourceEvent {
                SessionEnded,
                Adapter(Option<bluer::AdapterEvent>),
                Device(Option<WatchedDeviceEvent>),
            }
            let event = {
                let terminated = self.session.terminated();
                tokio::pin!(terminated);
                tokio::select! {
                    _ = terminated.as_mut() => SourceEvent::SessionEnded,
                    event = self.adapter_events.next() => SourceEvent::Adapter(event),
                    event = self.device_events.next(), if !self.device_events.is_empty() => {
                        SourceEvent::Device(event)
                    }
                }
            };
            match event {
                SourceEvent::SessionEnded | SourceEvent::Adapter(None) => {
                    return ScanBackendEvent::Terminated;
                }
                SourceEvent::Adapter(Some(bluer::AdapterEvent::DeviceAdded(address))) => {
                    match self.add_device(address).await {
                        Ok(()) => {}
                        Err(AddDeviceError::Capacity) => {
                            return ScanBackendEvent::CapacityExceeded;
                        }
                        Err(AddDeviceError::Platform) => return ScanBackendEvent::NeedsDrain,
                    }
                }
                SourceEvent::Adapter(Some(bluer::AdapterEvent::DeviceRemoved(_)))
                | SourceEvent::Adapter(Some(bluer::AdapterEvent::PropertyChanged(_))) => {}
                SourceEvent::Device(Some(WatchedDeviceEvent::Ended(address))) => {
                    self.watched.remove(&address);
                }
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(
                    locator,
                    bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::ServiceData(data)),
                ))) => {
                    if let Some(observation) = observation_from_service_data(locator, &data) {
                        return ScanBackendEvent::Observation(observation);
                    }
                }
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(
                    locator,
                    bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::AddressType(kind)),
                ))) if kind != locator.address_type() => return ScanBackendEvent::NeedsDrain,
                SourceEvent::Device(Some(WatchedDeviceEvent::Property(_, _))) => {}
                SourceEvent::Device(None) => return ScanBackendEvent::NeedsDrain,
            }
        }
    }
}

impl ScanBackend for BluezScanBackend {
    fn stop(&mut self) -> PlatformFuture<'_, ()> {
        Box::pin(async { self.session.stop().await.map_err(map_bluer_error) })
    }

    fn terminated(&self) -> TerminationFuture<'static> {
        let terminated = self.session.termination();
        Box::pin(async move {
            let _ = terminated.await;
        })
    }

    fn next_event(&mut self) -> ScanEventFuture<'_> {
        Box::pin(self.next_bluez_event())
    }

    fn force_owner_loss(&self) {
        self.owner_loss.force();
    }
}

async fn subscribe_device(
    adapter: &bluer::Adapter,
    address: Address,
) -> Result<Option<DeviceEventStream>, DriverError> {
    let device = adapter.device(address).map_err(map_bluer_error)?;
    let events = device.events().await.map_err(map_bluer_error)?;
    let address_type = device.address_type().await.map_err(map_bluer_error)?;
    let Ok(locator) = CanonicalLocator::new(address, address_type) else {
        return Ok(None);
    };
    let events = events
        .map(move |event| WatchedDeviceEvent::Property(locator, event))
        .chain(stream::once(
            async move { WatchedDeviceEvent::Ended(address) },
        ));
    Ok(Some(Box::pin(events)))
}

pub(crate) struct BluezDiscoveryPlatform {
    session: bluer::Session,
}

#[derive(Clone)]
pub(crate) struct BluezOwnerLoss {
    session: bluer::Session,
}

impl BluezOwnerLoss {
    pub(crate) fn force(&self) {
        self.session.close();
    }
}

impl BluezDiscoveryPlatform {
    pub(crate) async fn open() -> Result<Self, DriverError> {
        let session = bluer::Session::new().await.map_err(map_bluer_error)?;
        Ok(Self { session })
    }

    pub(crate) fn owner_loss(&self) -> BluezOwnerLoss {
        BluezOwnerLoss {
            session: self.session.clone(),
        }
    }

    async fn adapter(
        &self,
        controller: &ValidatedControllerConfig,
    ) -> Result<bluer::Adapter, DriverError> {
        let names = self
            .session
            .adapter_names()
            .await
            .map_err(map_bluer_error)?;
        if !names.iter().any(|name| name == controller.adapter_name()) {
            return Err(controller_unavailable());
        }
        let adapter = self
            .session
            .adapter(controller.adapter_name())
            .map_err(map_bluer_error)?;
        let powered = adapter.is_powered().await.map_err(map_bluer_error)?;
        let address = adapter.address().await.map_err(map_bluer_error)?;
        let address_type = adapter.address_type().await.map_err(map_bluer_error)?;
        if !powered
            || address != controller.local_address()
            || address_type != controller.local_address_type()
        {
            return Err(controller_unavailable());
        }
        Ok(adapter)
    }
}

impl DiscoveryPlatform for BluezDiscoveryPlatform {
    fn start_advertisement<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
        advertisement: RosterAdvertisement,
    ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
        Box::pin(async move {
            let adapter = self.adapter(controller).await?;
            let supported = adapter
                .supported_advertising_instances()
                .await
                .map_err(map_bluer_error)?;
            let active = adapter
                .active_advertising_instances()
                .await
                .map_err(map_bluer_error)?;
            let channels = adapter
                .supported_advertising_secondary_channels()
                .await
                .map_err(map_bluer_error)?
                .ok_or_else(advertising_unsupported)?;
            let capabilities = adapter
                .supported_advertising_capabilities()
                .await
                .map_err(map_bluer_error)?
                .ok_or_else(advertising_unsupported)?;
            validate_advertising_support(supported, active, &channels, &capabilities)?;
            let handle = adapter
                .advertise(bluez_advertisement(advertisement))
                .await
                .map_err(map_bluer_error)?;
            Ok(Box::new(spawn_advertisement_owner(handle)) as Box<dyn OwnedAdvertisement>)
        })
    }

    fn start_scan<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
    ) -> PlatformFuture<'a, StartedScan> {
        Box::pin(async move {
            let adapter = self.adapter(controller).await?;
            BluezScanBackend::start(adapter, self.owner_loss())
                .await
                .map(spawn_scan_owner)
        })
    }

    fn force_owner_loss(&self) {
        self.session.close();
    }
}

fn controller_unavailable() -> DriverError {
    DriverError::new(
        DriverErrorKind::Unavailable,
        "configured Bluetooth controller is unavailable",
    )
}

fn advertising_unsupported() -> DriverError {
    DriverError::new(
        DriverErrorKind::Unavailable,
        "configured controller lacks rostered advertising support",
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

    struct FakeOwner {
        stopped: Arc<AtomicBool>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
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
        advertisement_stopped: Arc<AtomicBool>,
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
                stopped: self.advertisement_stopped.clone(),
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
    fn advertising_eligibility_requires_capacity_instance_and_one_m_phy() {
        let channels = [bluer::adv::SecondaryChannel::OneM].into_iter().collect();
        let mut capabilities = bluer::adv::Capabilities::default();
        capabilities.max_advertisement_length = 79;

        assert!(validate_advertising_support(2, 1, &channels, &capabilities).is_ok());
        assert!(validate_advertising_support(1, 1, &channels, &capabilities).is_err());

        let mut short = bluer::adv::Capabilities::default();
        short.max_advertisement_length = 78;
        assert!(validate_advertising_support(2, 1, &channels, &short).is_err());
        assert!(validate_advertising_support(2, 1, &Default::default(), &capabilities).is_err());
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

    struct BlockingAdvertisementBackend {
        stop_calls: Arc<AtomicUsize>,
        stop_released: Arc<Notify>,
    }

    struct TerminatingAdvertisementBackend {
        stop_started: Arc<Notify>,
        terminated: Arc<Notify>,
    }

    impl AdvertisementBackend for TerminatingAdvertisementBackend {
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
    }

    impl AdvertisementBackend for BlockingAdvertisementBackend {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.stop_calls.fetch_add(1, Ordering::AcqRel);
                self.stop_released.notified().await;
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn advertisement_owner_completes_unregister_after_waiter_deadline() {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let stop_released = Arc::new(Notify::new());
        let mut owner = spawn_advertisement_owner(BlockingAdvertisementBackend {
            stop_calls: stop_calls.clone(),
            stop_released: stop_released.clone(),
        });

        let result = tokio::time::timeout(Duration::from_secs(5), owner.stop()).await;
        assert!(result.is_err());
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);

        stop_released.notify_one();
        owner.terminated().await;
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn advertisement_owner_observes_termination_while_stop_is_blocked() {
        let stop_started = Arc::new(Notify::new());
        let terminated = Arc::new(Notify::new());
        let mut owner = spawn_advertisement_owner(TerminatingAdvertisementBackend {
            stop_started: stop_started.clone(),
            terminated: terminated.clone(),
        });
        let release = tokio::spawn(async move {
            stop_started.notified().await;
            terminated.notify_one();
        });

        owner.stop().await.unwrap();
        release.await.unwrap();
        owner.terminated().await;
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
    async fn fake_platform_preserves_exact_advertisement_queue_and_owned_stop() {
        let platform = FakePlatform {
            advertisement: Mutex::new(None),
            sender: Mutex::new(None),
            advertisement_stopped: Arc::new(AtomicBool::new(false)),
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
        owned_advertisement.stop().await.unwrap();
        assert!(platform.advertisement_stopped.load(Ordering::Acquire));

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
