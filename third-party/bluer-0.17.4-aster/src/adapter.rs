//! Bluetooth adapter.

use dbus::{
    arg::{PropMap, RefArg, Variant},
    nonblock::{Proxy, SyncConnection},
    Path,
};
use futures::{
    future,
    stream::{self, SelectAll},
    FutureExt, Stream, StreamExt,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::{Debug, Formatter},
    future::Future,
    sync::Arc,
    time::Duration,
};
use strum::{Display, EnumString};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::{
    adv,
    adv::{Advertisement, AdvertisementHandle, Capabilities, Feature, PlatformFeature, SecondaryChannel},
    all_dbus_objects, device,
    device::Device,
    gatt,
    monitor::MonitorManager,
    Address, AddressType, Error, ErrorKind, Event, InternalErrorKind, Modalias, Result, SessionInner,
    SingleSessionToken, SERVICE_NAME, TIMEOUT,
};

pub(crate) const INTERFACE: &str = "org.bluez.Adapter1";
pub(crate) const PATH: &str = "/org/bluez";
pub(crate) const PREFIX: &str = "/org/bluez/";

/// Default adapter name.
pub(crate) const DEFAULT_NAME: &str = "hci0";

/// Interface to a Bluetooth adapter.
#[cfg_attr(docsrs, doc(cfg(feature = "bluetoothd")))]
#[derive(Clone)]
pub struct Adapter {
    inner: Arc<SessionInner>,
    dbus_path: Path<'static>,
    name: Arc<String>,
}

enum DiscoveryCommand {
    Stop(oneshot::Sender<Result<()>>),
}

enum DiscoveryOwnerExit {
    RegistrationFailed(oneshot::Sender<Result<()>>, Error),
    RegistrationTerminated(oneshot::Sender<Result<()>>, DiscoveryTermination),
    Stopped(oneshot::Sender<Result<()>>),
    Terminated(DiscoveryTermination),
    Released,
}

enum DiscoveryOperationOutcome<T> {
    Completed(Result<T>),
    Terminated(DiscoveryTermination),
}

struct DiscoveryStartup<Start, PreBaseline, Discovering, PostBaseline> {
    start: Start,
    pre_state_baseline: PreBaseline,
    discovering: Discovering,
    post_start_baseline: PostBaseline,
}

impl DiscoveryOwnerExit {
    fn finish(self, termination: watch::Sender<Option<DiscoveryTermination>>) {
        match self {
            Self::RegistrationFailed(reply, error) => {
                let _ = reply.send(Err(error));
            }
            Self::RegistrationTerminated(reply, reason) => {
                let error = discovery_registration_error(&reason);
                termination.send_replace(Some(reason));
                let _ = reply.send(Err(error));
            }
            Self::Stopped(reply) => {
                termination.send_replace(Some(DiscoveryTermination::DiscoveringStopped));
                let _ = reply.send(Ok(()));
            }
            Self::Terminated(reason) => {
                termination.send_replace(Some(reason));
            }
            Self::Released => {}
        }
    }
}

async fn run_discovery_owner<
    EventsFuture,
    Events,
    FilterFuture,
    StartFuture,
    PreBaselineFuture,
    DiscoveringFuture,
    PostBaselineFuture,
    Stop,
    StopFuture,
>(
    events: EventsFuture,
    set_filter: FilterFuture,
    startup: DiscoveryStartup<
        StartFuture,
        PreBaselineFuture,
        DiscoveringFuture,
        PostBaselineFuture,
    >,
    mut stop: Stop,
    mut registration_reply: oneshot::Sender<Result<()>>,
    mut commands: mpsc::Receiver<DiscoveryCommand>,
    mut session: watch::Receiver<Option<Error>>,
) -> DiscoveryOwnerExit
where
    EventsFuture: Future<Output = Result<Events>>,
    Events: Stream<Item = AdapterEvent> + Unpin,
    FilterFuture: Future<Output = Result<()>>,
    StartFuture: Future<Output = Result<()>>,
    PreBaselineFuture: Future<Output = Result<()>>,
    DiscoveringFuture: Future<Output = Result<bool>>,
    PostBaselineFuture: Future<Output = Result<()>>,
    Stop: FnMut() -> StopFuture,
    StopFuture: Future<Output = Result<()>>,
{
    let mut events = tokio::select! {
        result = events => match result {
            Ok(events) => events,
            Err(error) => return DiscoveryOwnerExit::RegistrationFailed(registration_reply, error),
        },
        () = registration_reply.closed() => return DiscoveryOwnerExit::Released,
    };

    tokio::select! {
        result = set_filter => if let Err(error) = result {
            return DiscoveryOwnerExit::RegistrationFailed(registration_reply, error);
        },
        () = registration_reply.closed() => return DiscoveryOwnerExit::Released,
    }

    match establish_discovery(startup, &mut events, &mut session).await {
        DiscoveryOperationOutcome::Completed(Ok(())) => {}
        DiscoveryOperationOutcome::Completed(Err(error)) => {
            cleanup_unconfirmed_discovery(&mut events, &mut session, &mut stop).await;
            return DiscoveryOwnerExit::RegistrationFailed(registration_reply, error);
        }
        DiscoveryOperationOutcome::Terminated(reason) => {
            return DiscoveryOwnerExit::RegistrationTerminated(registration_reply, reason);
        }
    }

    let commands_open = registration_reply.send(Ok(())).is_ok();
    if !commands_open {
        cleanup_unconfirmed_discovery(&mut events, &mut session, &mut stop).await;
        return DiscoveryOwnerExit::Released;
    }

    loop {
        tokio::select! {
            biased;
            changed = session.changed() => {
                return DiscoveryOwnerExit::Terminated(session_ended(changed, &mut session));
            },
            command = commands.recv() => match command {
                Some(DiscoveryCommand::Stop(reply)) => {
                    match await_discovery_operation(stop(), &mut events, &mut session, true).await {
                        DiscoveryOperationOutcome::Completed(Ok(())) => {
                            return DiscoveryOwnerExit::Stopped(reply);
                        }
                        DiscoveryOperationOutcome::Completed(Err(error))
                            if confirms_discovery_absent_error(&error) => {
                                return DiscoveryOwnerExit::Stopped(reply);
                            }
                        DiscoveryOperationOutcome::Completed(Err(error)) => {
                            let _ = reply.send(Err(error));
                        }
                        DiscoveryOperationOutcome::Terminated(
                            DiscoveryTermination::DiscoveringStopped,
                        ) => return DiscoveryOwnerExit::Stopped(reply),
                        DiscoveryOperationOutcome::Terminated(reason) => {
                            return DiscoveryOwnerExit::Terminated(reason);
                        }
                    }
                }
                None => {
                    cleanup_unconfirmed_discovery(&mut events, &mut session, &mut stop).await;
                    return DiscoveryOwnerExit::Released;
                }
            },
            event = events.next() => match event {
                Some(AdapterEvent::PropertyChanged(AdapterProperty::Discovering(false))) => {
                    return DiscoveryOwnerExit::Terminated(DiscoveryTermination::DiscoveringStopped);
                }
                Some(_) => {},
                None => {
                    return DiscoveryOwnerExit::Terminated(DiscoveryTermination::AdapterRemoved);
                }
            },
        }
    }
}

fn discovery_registration_error(reason: &DiscoveryTermination) -> Error {
    match reason {
        DiscoveryTermination::DiscoveringStopped => Error::new(ErrorKind::NotReady),
        DiscoveryTermination::AdapterRemoved => Error::new(ErrorKind::NotFound),
        DiscoveryTermination::SessionEnded(error) => error.clone(),
    }
}

async fn establish_discovery<Start, PreBaseline, Discovering, PostBaseline, Events>(
    startup: DiscoveryStartup<Start, PreBaseline, Discovering, PostBaseline>,
    events: &mut Events,
    session: &mut watch::Receiver<Option<Error>>,
) -> DiscoveryOperationOutcome<()>
where
    Start: Future<Output = Result<()>>,
    PreBaseline: Future<Output = Result<()>>,
    Discovering: Future<Output = Result<bool>>,
    PostBaseline: Future<Output = Result<()>>,
    Events: Stream<Item = AdapterEvent> + Unpin,
{
    let DiscoveryStartup {
        start,
        pre_state_baseline,
        discovering,
        post_start_baseline,
    } = startup;

    match await_discovery_operation(start, events, session, false).await {
        DiscoveryOperationOutcome::Completed(Ok(())) => {
            if let Some(reason) = drain_discovery_events(events, false) {
                return DiscoveryOperationOutcome::Terminated(reason);
            }
        }
        outcome => return outcome,
    }

    match await_discovery_operation(pre_state_baseline, events, session, false).await {
        DiscoveryOperationOutcome::Completed(Ok(())) => {
            if let Some(reason) = drain_discovery_events(events, false) {
                return DiscoveryOperationOutcome::Terminated(reason);
            }
        }
        outcome => return outcome,
    }

    // Flush callback backlog, reconcile the property, then fence signals that
    // raced the property response before publishing ownership.
    match await_discovery_operation(discovering, events, session, true).await {
        DiscoveryOperationOutcome::Completed(Ok(true)) => {}
        DiscoveryOperationOutcome::Completed(Ok(false)) => {
            return DiscoveryOperationOutcome::Terminated(
                DiscoveryTermination::DiscoveringStopped,
            );
        }
        DiscoveryOperationOutcome::Completed(Err(error)) => {
            return DiscoveryOperationOutcome::Completed(Err(error));
        }
        DiscoveryOperationOutcome::Terminated(reason) => {
            return DiscoveryOperationOutcome::Terminated(reason);
        }
    }

    match await_discovery_operation(post_start_baseline, events, session, true).await {
        DiscoveryOperationOutcome::Completed(Ok(())) => {
            match drain_discovery_events(events, true) {
                Some(reason) => DiscoveryOperationOutcome::Terminated(reason),
                None => DiscoveryOperationOutcome::Completed(Ok(())),
            }
        }
        outcome => outcome,
    }
}

async fn await_discovery_operation<Operation, Events, Output>(
    operation: Operation,
    events: &mut Events,
    session: &mut watch::Receiver<Option<Error>>,
    stopped_proves_completion: bool,
) -> DiscoveryOperationOutcome<Output>
where
    Operation: Future<Output = Result<Output>>,
    Events: Stream<Item = AdapterEvent> + Unpin,
{
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            result = &mut operation => return DiscoveryOperationOutcome::Completed(result),
            changed = session.changed() => {
                return DiscoveryOperationOutcome::Terminated(session_ended(changed, session));
            },
            event = events.next() => match event {
                Some(AdapterEvent::PropertyChanged(AdapterProperty::Discovering(false)))
                    if stopped_proves_completion => {
                    return DiscoveryOperationOutcome::Terminated(
                        DiscoveryTermination::DiscoveringStopped,
                    );
                }
                Some(_) => {}
                None => {
                    return DiscoveryOperationOutcome::Terminated(
                        DiscoveryTermination::AdapterRemoved,
                    );
                }
            },
        }
    }
}

fn drain_discovery_events<Events>(
    events: &mut Events,
    stopped_proves_completion: bool,
) -> Option<DiscoveryTermination>
where
    Events: Stream<Item = AdapterEvent> + Unpin,
{
    while let Some(event) = events.next().now_or_never() {
        match event {
            Some(AdapterEvent::PropertyChanged(AdapterProperty::Discovering(false)))
                if stopped_proves_completion =>
            {
                return Some(DiscoveryTermination::DiscoveringStopped);
            }
            Some(_) => {}
            None => return Some(DiscoveryTermination::AdapterRemoved),
        }
    }
    None
}

async fn cleanup_unconfirmed_discovery<Events, Stop, StopFuture>(
    events: &mut Events,
    session: &mut watch::Receiver<Option<Error>>,
    stop: &mut Stop,
) where
    Events: Stream<Item = AdapterEvent> + Unpin,
    Stop: FnMut() -> StopFuture,
    StopFuture: Future<Output = Result<()>>,
{
    loop {
        match await_discovery_operation(stop(), events, session, true).await {
            DiscoveryOperationOutcome::Completed(Ok(())) => return,
            DiscoveryOperationOutcome::Completed(Err(error))
                if confirms_discovery_absent_error(&error) => return,
            DiscoveryOperationOutcome::Completed(_) => {}
            DiscoveryOperationOutcome::Terminated(_) => return,
        }
        tokio::select! {
            changed = session.changed() => {
                if changed.is_err() || session.borrow_and_update().is_some() {
                    return;
                }
            },
            event = events.next() => match event {
                Some(AdapterEvent::PropertyChanged(AdapterProperty::Discovering(false))) | None => return,
                Some(_) => {},
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
}

fn session_ended(
    changed: std::result::Result<(), watch::error::RecvError>,
    session: &mut watch::Receiver<Option<Error>>,
) -> DiscoveryTermination {
    let error = if changed.is_err() {
        Error::new(ErrorKind::Internal(InternalErrorKind::DBusConnectionLost))
    } else {
        session.borrow_and_update().clone().unwrap_or_else(|| {
            Error::new(ErrorKind::Internal(InternalErrorKind::DBusConnectionLost))
        })
    };
    DiscoveryTermination::SessionEnded(error)
}

fn confirms_discovery_absent_error(error: &Error) -> bool {
    matches!(
        error.kind,
        ErrorKind::DoesNotExist
            | ErrorKind::NotFound
            | ErrorKind::NotReady
            | ErrorKind::NotRegistered
    )
}

/// Independently proven owned-discovery termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryTermination {
    /// BlueZ acknowledged stop or reported discovery stopped.
    DiscoveringStopped,
    /// The adapter event stream ended or the adapter was removed.
    AdapterRemoved,
    /// The owning D-Bus session ended.
    SessionEnded(Error),
}

/// Exclusive owned discovery session with acknowledged stop.
#[must_use = "DiscoverySession must be held while discovery is active"]
pub struct DiscoverySession {
    commands: mpsc::Sender<DiscoveryCommand>,
    termination: watch::Receiver<Option<DiscoveryTermination>>,
}

impl DiscoverySession {
    /// Requests discovery stop and waits for BlueZ acknowledgement.
    pub async fn stop(&mut self) -> Result<()> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(DiscoveryCommand::Stop(reply))
            .await
            .map_err(|_| Error::new(ErrorKind::NotRegistered))?;
        result
            .await
            .map_err(|_| Error::new(ErrorKind::NotRegistered))?
    }

    /// Waits for acknowledged stop, adapter removal, or session loss.
    pub async fn terminated(&self) -> DiscoveryTermination {
        let mut termination = self.termination.clone();
        loop {
            if let Some(reason) = termination.borrow_and_update().clone() {
                return reason;
            }
            if termination.changed().await.is_err() {
                return DiscoveryTermination::SessionEnded(Error::new(ErrorKind::Internal(
                    InternalErrorKind::DBusConnectionLost,
                )));
            }
        }
    }
}

impl Debug for Adapter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("Adapter").field("name", &self.name()).finish()
    }
}

impl Adapter {
    /// Create Bluetooth adapter interface for adapter with specified name.
    pub(crate) fn new(inner: Arc<SessionInner>, name: &str) -> Result<Self> {
        Ok(Self {
            inner,
            dbus_path: Path::new(PREFIX.to_string() + name)
                .map_err(|_| Error::new(ErrorKind::InvalidName(name.to_string())))?,
            name: Arc::new(name.to_string()),
        })
    }

    fn proxy(&self) -> Proxy<'_, &SyncConnection> {
        Proxy::new(SERVICE_NAME, &self.dbus_path, TIMEOUT, &*self.inner.connection)
    }

    pub(crate) fn dbus_path(adapter_name: &str) -> Result<Path<'static>> {
        Path::new(format!("{PREFIX}{adapter_name}",))
            .map_err(|_| Error::new(ErrorKind::InvalidName((*adapter_name).to_string())))
    }

    pub(crate) fn parse_dbus_path_prefix<'a>(path: &'a Path) -> Option<(&'a str, &'a str)> {
        match path.strip_prefix(PREFIX) {
            Some(p) => {
                let sep = p.find('/').unwrap_or(p.len());
                Some((&p[0..sep], &p[sep..]))
            }
            None => None,
        }
    }

    pub(crate) fn parse_dbus_path<'a>(path: &'a Path) -> Option<&'a str> {
        match Self::parse_dbus_path_prefix(path) {
            Some((v, "")) => Some(v),
            _ => None,
        }
    }

    /// The Bluetooth adapter name.
    ///
    /// For example `hci0`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Bluetooth addresses of discovered Bluetooth devices.
    pub async fn device_addresses(&self) -> Result<Vec<Address>> {
        let mut addrs = Vec::new();
        for (path, interfaces) in all_dbus_objects(&self.inner.connection).await? {
            match Device::parse_dbus_path(&path) {
                Some((adapter, addr)) if adapter == *self.name && interfaces.contains_key(device::INTERFACE) => {
                    addrs.push(addr)
                }
                _ => (),
            }
        }
        Ok(addrs)
    }

    /// Starts monitoring of advertisements.
    ///
    /// Once a monitoring job is activated by BlueZ, the client can expect to get
    /// notified on the targeted advertisements no matter if there is an ongoing
    /// discovery session.
    ///
    /// Use the returned [`MonitorManager`] to target advertisements
    /// and drop it to stop monitoring advertisements.
    pub async fn monitor(&self) -> Result<MonitorManager> {
        MonitorManager::new(self.inner.clone(), self.name()).await
    }

    /// Get interface to Bluetooth device of specified address.
    pub fn device(&self, address: Address) -> Result<Device> {
        Device::new(self.inner.clone(), self.name.clone(), address)
    }

    /// Gets the filter used for device discovery.
    pub async fn discovery_filter(&self) -> DiscoveryFilter {
        self.inner.adapter_discovery_filter.lock().await.get(self.name()).cloned().unwrap_or_default()
    }

    /// Sets the filter used for device discovery.
    ///
    /// Setting a discovery filter does not guarantee that all its filters will be applied.
    /// A discovery session from another program might be active, leading to merging of
    /// the discovery filters by the Bluetooth daemon.
    ///
    /// The discovery filter can only be changed when no device discovery is currently active.
    /// Otherwise a [DiscoveryActive error](ErrorKind::DiscoveryActive) will be returned.
    pub async fn set_discovery_filter(&self, discovery_filter: DiscoveryFilter) -> Result<()> {
        self.inner
            .set_discovery_filter_if_idle(
                &self.dbus_path,
                self.name().to_string(),
                discovery_filter,
            )
            .await
    }

    /// This method starts the device discovery session.
    ///
    /// This includes an inquiry procedure and remote device name resolving.
    ///
    /// This process will start streaming device addresses as new devices are discovered.
    /// A device may be discovered multiple times.
    ///
    /// All already known devices are also included in the device stream.
    /// This may include devices that are currently not in range.
    /// Check the [Device::rssi] property to see if the device is currently present.
    ///
    /// Device properties are queried asynchronously and may not be available
    /// yet when a [DeviceAdded event](AdapterEvent::DeviceAdded) occurs.
    /// Use [discover_devices_with_changes](Self::discover_devices_with_changes)
    /// when you want to be notified when the device properties change.
    ///
    /// The discovery filter can be configured using [set_discovery_filter](Self::set_discovery_filter).
    pub async fn discover_devices(&self) -> Result<impl Stream<Item = AdapterEvent>> {
        let token = self.discovery_session().await?;
        let change_events = self
            .events()
            .await?
            .map(move |evt| {
                let _token = &token;
                evt
            })
            .take_while(|evt| {
                future::ready(!matches!(evt, AdapterEvent::PropertyChanged(AdapterProperty::Discovering(false))))
            });

        let known = self.device_addresses().await?;
        let known_events = stream::iter(known).map(AdapterEvent::DeviceAdded);

        let all_events = known_events.chain(change_events);

        Ok(all_events)
    }

    /// This method starts the device discovery session and notifies of device property changes.
    ///
    /// This includes an inquiry procedure and remote device name resolving.
    ///
    /// This process will start streaming device addresses as new devices are discovered.
    /// Each time device properties change you will receive an additional
    /// [DeviceAdded event](AdapterEvent::DeviceAdded) for that device.
    ///
    /// All already known devices are also included in the device stream.
    /// This may include devices that are currently not in range.
    /// Check the [Device::rssi] property to see if the device is currently present.
    ///
    /// The discovery filter can be configured using [set_discovery_filter](Self::set_discovery_filter).
    pub async fn discover_devices_with_changes(&self) -> Result<impl Stream<Item = AdapterEvent>> {
        let (tx, rx) = mpsc::channel(1);
        let mut discovery = self.discover_devices().await?;
        let adapter = self.clone();

        tokio::spawn(async move {
            let mut changes = SelectAll::new();

            loop {
                tokio::select! {
                    evt = discovery.next() => {
                        match evt {
                            Some(AdapterEvent::DeviceAdded(addr)) => {
                                if let Ok(dev) = adapter.device(addr) {
                                    if let Ok(dev_evts) = dev.events().await {
                                        changes.push(dev_evts.map(move |_| addr));
                                    }
                                }
                                let _ = tx.send(AdapterEvent::DeviceAdded(addr)).await;
                            },
                            Some(AdapterEvent::DeviceRemoved(addr)) => {
                                let _ = tx.send(AdapterEvent::DeviceRemoved(addr)).await;
                            },
                            Some(_) => (),
                            None => break,
                        }
                    },
                    Some(addr) = changes.next(), if !changes.is_empty() => {
                        let _ = tx.send(AdapterEvent::DeviceAdded(addr)).await;
                    },
                    () = tx.closed() => break,
                }
            }
        });

        Ok(ReceiverStream::new(rx))
    }

    async fn discovery_session(&self) -> Result<SingleSessionToken> {
        let dbus_path = self.dbus_path.clone();
        let connection = self.inner.connection.clone();
        let token = self
            .inner
            .single_session(
                &self.dbus_path,
                async move {
                    let () = self
                        .call_method("SetDiscoveryFilter", (self.discovery_filter().await.into_dict(),))
                        .await?;
                    let () = self.call_method("StartDiscovery", ()).await?;
                    Ok(())
                },
                async move {
                    log::trace!("{}: {}.StopDiscovery ()", &dbus_path, SERVICE_NAME);
                    let proxy = Proxy::new(SERVICE_NAME, &dbus_path, TIMEOUT, &*connection);
                    let result: std::result::Result<(), dbus::Error> =
                        proxy.method_call(INTERFACE, "StopDiscovery", ()).await;
                    log::trace!("{}: {}.StopDiscovery () -> {:?}", &dbus_path, SERVICE_NAME, &result);
                },
            )
            .await?;
        Ok(token)
    }

    /// Starts one exclusive discovery session with an acknowledged stop handle.
    pub async fn start_discovery_session(&self) -> Result<DiscoverySession> {
        self.inner
            .reserve_exclusive_session(&self.dbus_path)
            .await?;
        let (commands, command_rx) = mpsc::channel(1);
        let (termination, termination_rx) = watch::channel(None);
        let (registration_tx, registration_rx) = oneshot::channel();
        let adapter = self.clone();
        let events_adapter = adapter.clone();
        let filter_adapter = adapter.clone();
        let start_adapter = adapter.clone();
        let state_adapter = adapter.clone();
        let stop_adapter = adapter.clone();
        let pre_state_baseline = adapter.inner.event_ingress_barrier();
        let post_start_baseline = pre_state_baseline.clone();
        let session = self.inner.terminal.subscribe();

        tokio::spawn(async move {
            let exit = run_discovery_owner(
                async move { events_adapter.events().await },
                async move {
                    filter_adapter
                        .call_method(
                            "SetDiscoveryFilter",
                            (filter_adapter.discovery_filter().await.into_dict(),),
                        )
                        .await
                },
                DiscoveryStartup {
                    start: async move {
                        start_adapter.call_method("StartDiscovery", ()).await
                    },
                    pre_state_baseline: async move { pre_state_baseline.wait().await },
                    discovering: async move { state_adapter.is_discovering().await },
                    post_start_baseline: async move { post_start_baseline.wait().await },
                },
                move || {
                    let adapter = stop_adapter.clone();
                    async move { adapter.call_method("StopDiscovery", ()).await }
                },
                registration_tx,
                command_rx,
                session,
            )
            .await;

            adapter
                .inner
                .release_exclusive_session(&adapter.dbus_path)
                .await;
            exit.finish(termination);
        });

        registration_rx.await.map_err(|_| {
            Error::new(ErrorKind::Internal(InternalErrorKind::DBusConnectionLost))
        })??;
        Ok(DiscoverySession {
            commands,
            termination: termination_rx,
        })
    }

    dbus_interface!();
    dbus_default_interface!(INTERFACE);

    /// Streams adapter property and device changes.
    ///
    /// The stream ends when the adapter is removed.
    pub async fn events(&self) -> Result<impl Stream<Item = AdapterEvent>> {
        let name = self.name.clone();
        let events = self.inner.events(self.dbus_path.clone(), true).await?;
        let stream = events.flat_map(move |event| match event {
            Event::ObjectAdded { object, .. } => match Device::parse_dbus_path(&object) {
                Some((adapter, address)) if adapter == *name => {
                    stream::once(async move { AdapterEvent::DeviceAdded(address) }).boxed()
                }
                _ => stream::empty().boxed(),
            },
            Event::ObjectRemoved { object, .. } => match Device::parse_dbus_path(&object) {
                Some((adapter, address)) if adapter == *name => {
                    stream::once(async move { AdapterEvent::DeviceRemoved(address) }).boxed()
                }
                _ => stream::empty().boxed(),
            },
            Event::PropertiesChanged { changed, .. } => stream::iter(
                AdapterProperty::from_prop_map(changed).into_iter().map(AdapterEvent::PropertyChanged),
            )
            .boxed(),
        });
        Ok(stream)
    }

    /// Registers an advertisement object to be sent over the LE
    /// Advertising channel.
    ///
    /// InvalidArguments error indicates that the object has
    /// invalid or conflicting properties.
    ///
    /// InvalidLength error indicates that the data
    /// provided generates a data packet which is too long.
    ///
    /// The properties of this object are parsed when it is
    /// registered, and any changes are ignored.
    ///
    /// If the same object is registered twice it will result in
    /// an AlreadyExists error.
    ///
    /// If the maximum number of advertisement instances is
    /// reached it will result in NotPermitted error.
    ///
    /// Drop the returned [AdvertisementHandle] to unregister the advertisement.
    pub async fn advertise(&self, le_advertisement: Advertisement) -> Result<AdvertisementHandle> {
        le_advertisement.register(self.inner.clone(), self.name.clone()).await
    }

    /// Registers a local GATT services hierarchy (GATT Server).
    ///
    /// Registering a service allows applications to publish a *local* GATT service,
    /// which then becomes available to remote devices.
    ///
    /// Drop the returned [ApplicationHandle](gatt::local::ApplicationHandle) to unregister the application.
    pub async fn serve_gatt_application(
        &self, gatt_application: gatt::local::Application,
    ) -> Result<gatt::local::ApplicationHandle> {
        gatt_application.register(self.inner.clone(), self.name.clone()).await
    }

    /// Registers local GATT profiles (GATT Client).
    ///
    /// By registering this type of object
    /// an application effectively indicates support for a specific GATT profile
    /// and requests automatic connections to be established to devices
    /// supporting it.
    ///
    /// Drop the returned [ProfileHandle](gatt::local::ProfileHandle) to unregister the application.
    pub async fn register_gatt_profile(
        &self, gatt_profile: gatt::local::Profile,
    ) -> Result<gatt::local::ProfileHandle> {
        gatt_profile.register(self.inner.clone(), self.name.clone()).await
    }

    // ===========================================================================================
    // Methods
    // ===========================================================================================

    /// This removes the remote device object for the given
    /// device address.
    ///
    /// It will remove also the pairing information.
    pub async fn remove_device(&self, address: Address) -> Result<()> {
        let path = Device::dbus_path(self.name(), address)?;
        let () = self.call_method("RemoveDevice", ((path),)).await?;
        Ok(())
    }

    /// This method connects to device without need of
    /// performing General Discovery.
    ///
    /// Connection mechanism is
    /// similar to Connect method from Device1 interface with
    /// exception that this method returns success when physical
    /// connection is established. After this method returns,
    /// services discovery will continue and any supported
    /// profile will be connected. There is no need for calling
    /// Connect on Device1 after this call. If connection was
    /// successful this method returns the created
    /// device object.
    ///
    /// Parameters are the following:
    ///
    /// * `address` -
    ///     The Bluetooth device address of the remote
    ///     device.
    /// * `address_type` -
    ///     The Bluetooth device Address Type. This is
    ///     address type that should be used for initial
    ///     connection.
    ///
    /// This method is experimental.
    pub async fn connect_device(&self, address: Address, address_type: AddressType) -> Result<Device> {
        let mut m = PropMap::new();
        m.insert("Address".to_string(), Variant(address.to_string().box_clone()));
        match address_type {
            AddressType::LePublic | AddressType::LeRandom => {
                m.insert("AddressType".to_string(), Variant(address_type.to_string().box_clone()));
            }
            AddressType::BrEdr => (),
        }
        let (_path,): (Path,) = self.call_method("ConnectDevice", (m,)).await?;

        self.device(address)
    }
}

define_properties!(
    Adapter,
    /// Bluetooth adapter property.
    pub AdapterProperty => {

        // ===========================================================================================
        // Adapter properties
        // ===========================================================================================

        /// The Bluetooth adapter address.
        property(
            Address, Address,
            dbus: (INTERFACE, "Address", String, MANDATORY),
            get: (address, v => { v.parse()? }),
        );

        /// The Bluetooth adapter address type.
        ///
        /// For dual-mode and BR/EDR
        /// only adapter this defaults to "public". Single mode LE
        /// adapters may have either value. With privacy enabled
        /// this contains type of Identity Address and not type of
        /// address used for connection.
        property(
            AddressType, AddressType,
            dbus: (INTERFACE, "AddressType", String, MANDATORY),
            get: (address_type, v => {v.parse()?}),
        );

        ///	The Bluetooth system name (pretty hostname).
        ///
        /// This property is either a static system default
        /// or controlled by an external daemon providing
        /// access to the pretty hostname configuration.
        property(
            SystemName, String,
            dbus: (INTERFACE, "Name", String, MANDATORY),
            get: (system_name, v => {v.to_owned()}),
        );

        /// The Bluetooth friendly name.
        ///
        /// This value can be changed.
        ///
        /// In case no alias is set, it will return the system
        /// provided name. Setting an empty string as alias will
        /// convert it back to the system provided name.
        ///
        /// When resetting the alias with an empty string, the
        /// property will default back to system name.
        ///
        /// On a well configured system, this property never
        /// needs to be changed since it defaults to the system
        /// name and provides the pretty hostname. Only if the
        /// local name needs to be different from the pretty
        /// hostname, this property should be used as last
        /// resort.
        property(
            Alias, String,
            dbus: (INTERFACE, "Alias", String, MANDATORY),
            get: (alias, v => {v.to_owned()}),
            set: (set_alias, v => {v}),
        );

        /// The Bluetooth class of device.
        ///
        ///	This property represents the value that is either
        ///	automatically configured by DMI/ACPI information
        ///	or provided as static configuration.
        property(
            Class, u32,
            dbus: (INTERFACE, "Class", u32, MANDATORY),
            get: (class, v => {v.to_owned()}),
        );

        /// Switch an adapter on or off. This will also set the
        /// appropriate connectable state of the controller.
        ///
        /// The value of this property is not persistent. After
        /// restart or unplugging of the adapter it will reset
        /// back to false.
        property(
            Powered, bool,
            dbus: (INTERFACE, "Powered", bool, MANDATORY),
            get: (is_powered, v => {v.to_owned()}),
            set: (set_powered, v => {v}),
        );

        /// Switch an adapter to discoverable or non-discoverable
        /// to either make it visible or hide it.
        ///
        /// This is a global
        /// setting and should only be used by the settings
        /// application.
        ///
        /// If the DiscoverableTimeout is set to a non-zero
        /// value then the system will set this value back to
        /// false after the timer expired.
        ///
        /// In case the adapter is switched off, setting this
        /// value will fail.
        ///
        /// When changing the Powered property the new state of
        /// this property will be updated via a PropertiesChanged
        /// signal.
        ///
        /// For any new adapter this settings defaults to false.
        ///
        /// To send Bluetooth LE advertisements use the
        /// [advertise](Adapter::advertise) method instead.
        property(
            Discoverable, bool,
            dbus: (INTERFACE, "Discoverable", bool, MANDATORY),
            get: (is_discoverable, v => {v.to_owned()}),
            set: (set_discoverable, v => {v}),
        );

        /// Switch an adapter to pairable or non-pairable.
        ///
        /// This is
        /// a global setting and should only be used by the
        /// settings application.
        ///
        /// Note that this property only affects incoming pairing
        /// requests.
        ///
        /// For any new adapter this settings defaults to true.
        property(
            Pairable, bool,
            dbus: (INTERFACE, "Pairable", bool, MANDATORY),
            get: (is_pairable, v => {v.to_owned()}),
            set: (set_pairable, v => {v}),
        );

        /// The pairable timeout in seconds.
        ///
        /// A value of zero
        /// means that the timeout is disabled and it will stay in
        /// pairable mode forever.
        ///
        /// The default value for pairable timeout should be
        /// disabled (value 0).
        property(
            PairableTimeout, u32,
            dbus: (INTERFACE, "PairableTimeout", u32, MANDATORY),
            get: (pairable_timeout, v => {v.to_owned()}),
            set: (set_pairable_timeout, v => {v}),
        );

        /// The discoverable timeout in seconds.
        ///
        /// A value of zero
        /// means that the timeout is disabled and it will stay in
        /// discoverable/limited mode forever.
        ///
        /// The default value for the discoverable timeout should
        /// be 180 seconds (3 minutes).
        property(
            DiscoverableTimeout, u32,
            dbus: (INTERFACE, "DiscoverableTimeout", u32, MANDATORY),
            get: (discoverable_timeout, v => {v.to_owned()}),
            set: (set_discoverable_timeout, v => {v}),
        );

        ///	Indicates that a device discovery procedure is active.
        property(
            Discovering, bool,
            dbus: (INTERFACE, "Discovering", bool, MANDATORY),
            get: (is_discovering, v => {v.to_owned()}),
        );

        /// List of 128-bit UUIDs that represents the available
        /// local services.
        property(
            Uuids, HashSet<Uuid>,
            dbus: (INTERFACE, "UUIDs", Vec<String>, OPTIONAL),
            get: (uuids, v => {
                v
                .iter()
                .map(|uuid| {
                    uuid.parse()
                        .map_err(|_| Error::new(ErrorKind::Internal(InternalErrorKind::InvalidUuid(uuid.to_string()))))
                })
                .collect::<Result<HashSet<Uuid>>>()?
            }),
        );

        /// Local Device ID information in modalias format
        /// used by the kernel and udev.
        property(
            Modalias, Modalias,
            dbus: (INTERFACE, "Modalias", String, OPTIONAL),
            get: (modalias, v => { v.parse()? }),
        );

        // ===========================================================================================
        // LE advertising manager properties
        // ===========================================================================================

        ///	Number of active advertising instances.
        property(
            ActiveAdvertisingInstances, u8,
            dbus: (adv::MANAGER_INTERFACE, "ActiveInstances", u8, MANDATORY),
            get: (active_advertising_instances, v => {v.to_owned()}),
        );

        ///	Number of available advertising instances.
        property(
            SupportedAdvertisingInstances, u8,
            dbus: (adv::MANAGER_INTERFACE, "SupportedInstances", u8, MANDATORY),
            get: (supported_advertising_instances, v => {v.to_owned()}),
        );

        /// List of supported system includes.
        property(
            SupportedAdvertisingSystemIncludes, BTreeSet<Feature>,
            dbus: (adv::MANAGER_INTERFACE, "SupportedIncludes", Vec<String>, MANDATORY),
            get: (supported_advertising_system_includes, v => {
                v.iter().filter_map(|s| s.parse().ok()).collect()
            }),
        );

        /// List of supported Secondary channels.
        ///
        /// Secondary
        /// channels can be used to advertise with the
        /// corresponding PHY.
        property(
            SupportedAdvertisingSecondaryChannels, BTreeSet<SecondaryChannel>,
            dbus: (adv::MANAGER_INTERFACE, "SupportedSecondaryChannels", Vec<String>, OPTIONAL),
            get: (supported_advertising_secondary_channels, v => {
                v.iter().filter_map(|s| s.parse().ok()).collect()
            }),
        );

        /// Enumerates Advertising-related controller capabilities
        /// useful to the client.
        property(
            SupportedAdvertisingCapabilities, Capabilities,
            dbus: (adv::MANAGER_INTERFACE, "SupportedCapabilities", HashMap<String, Variant<Box<dyn RefArg  + 'static>>>, OPTIONAL),
            get: (supported_advertising_capabilities, v => {
                Capabilities::from_dict(v)?
            }),
        );

        /// List of supported platform features.
        ///
        /// If no features
        /// are available on the platform, the SupportedFeatures
        /// array will be empty.
        property(
            SupportedAdvertisingFeatures, BTreeSet<PlatformFeature>,
            dbus: (adv::MANAGER_INTERFACE, "SupportedFeatures", Vec<String>, OPTIONAL),
            get: (supported_advertising_features, v => {
                v.iter().filter_map(|s| s.parse().ok()).collect()
            }),
        );
    }
);

/// Bluetooth adapter event.
#[cfg_attr(docsrs, doc(cfg(feature = "bluetoothd")))]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AdapterEvent {
    /// Bluetooth device with specified address was added.
    DeviceAdded(Address),
    /// Bluetooth device with specified address was removed.
    DeviceRemoved(Address),
    /// Bluetooth adapter property changed.
    PropertyChanged(AdapterProperty),
}

/// Transport parameter determines the type of scan.
#[cfg_attr(docsrs, doc(cfg(feature = "bluetoothd")))]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum DiscoveryTransport {
    /// interleaved scan
    #[strum(serialize = "auto")]
    Auto,
    /// BR/EDR inquiry
    #[strum(serialize = "bredr")]
    BrEdr,
    /// LE scan only
    #[strum(serialize = "le")]
    Le,
}

impl Default for DiscoveryTransport {
    fn default() -> Self {
        Self::Auto
    }
}

/// Bluetooth device discovery filter.
///
/// The default discovery filter does not restrict any devices and provides
/// [duplicate data](Self::duplicate_data).
#[cfg_attr(docsrs, doc(cfg(feature = "bluetoothd")))]
#[derive(Default, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiscoveryFilter {
    ///  Filter by service UUIDs, empty means match
    ///  _any_ UUID.
    ///
    ///  When a remote device is found that advertises
    ///  any UUID from UUIDs, it will be reported if:
    ///  - pathloss and RSSI are both empty.
    ///  - only pathloss param is set, device advertise
    ///    TX power, and computed pathloss is less than
    ///    pathloss param.
    ///  - only RSSI param is set, and received RSSI is
    ///    higher than RSSI param.
    pub uuids: HashSet<Uuid>,
    /// RSSI threshold value.
    ///
    /// PropertiesChanged signals will be emitted
    /// for already existing Device objects, with
    /// updated RSSI value. If one or more discovery
    /// filters have been set, the RSSI delta-threshold,
    /// that is imposed by StartDiscovery by default,
    /// will not be applied.
    pub rssi: Option<i16>,
    /// Pathloss threshold value.
    ///
    /// PropertiesChanged signals will be emitted
    /// for already existing Device objects, with
    /// updated Pathloss value.
    ///
    /// Must not be set when [`rssi`](Self::rssi) is set.
    pub pathloss: Option<u16>,
    /// Transport parameter determines the type of
    /// scan.
    ///
    /// Possible values:
    ///     "auto"  - interleaved scan
    ///     "bredr" - BR/EDR inquiry
    ///     "le"    - LE scan only
    ///
    /// If "le" or "bredr" Transport is requested,
    /// and the controller doesn't support it,
    /// org.bluez.Error.Failed error will be returned.
    ///
    /// If "auto" transport is requested, scan will use
    /// LE, BREDR, or both, depending on what's
    /// currently enabled on the controller.
    pub transport: DiscoveryTransport,
    /// Disables duplicate detection of advertisement data.
    ///
    /// When enabled PropertiesChanged signals will be
    /// generated for either ManufacturerData and
    /// ServiceData every time they are discovered.
    pub duplicate_data: bool,
    /// Make adapter discoverable while discovering.
    ///
    /// If the adapter is already discoverable setting
    /// this filter won't do anything.
    pub discoverable: bool,
    /// Discover devices where the pattern matches
    /// either the prefix of the address or
    /// device name which is convenient way to limited
    /// the number of device objects created during a
    /// discovery.
    ///
    /// When set disregards device discoverable flags.
    ///
    /// Note: The pattern matching is ignored if there
    /// are other client that don't set any pattern as
    /// it work as a logical OR, also setting empty
    /// string "" pattern will match any device found.
    pub pattern: Option<String>,
    #[doc(hidden)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _non_exhaustive: (),
}

impl DiscoveryFilter {
    fn into_dict(self) -> HashMap<&'static str, Variant<Box<dyn RefArg>>> {
        let mut hm: HashMap<&'static str, Variant<Box<dyn RefArg>>> = HashMap::new();
        let Self { uuids, rssi, pathloss, transport, duplicate_data, discoverable, pattern, _non_exhaustive } =
            self;
        hm.insert("UUIDs", Variant(Box::new(uuids.into_iter().map(|uuid| uuid.to_string()).collect::<Vec<_>>())));
        if let Some(rssi) = rssi {
            hm.insert("RSSI", Variant(Box::new(rssi)));
        }
        if let Some(pathloss) = pathloss {
            hm.insert("Pathloss", Variant(Box::new(pathloss)));
        }
        hm.insert("Transport", Variant(Box::new(transport.to_string())));

        // WORKAROUND: bluetoothd has a bug that causes it to crash when deserializing a bool
        //             from D-Bus on some architectures (at least 32-bit ARM). We can partly
        //             work around this by omitting the bools from the dictionary, if they match
        //             the default values.
        if duplicate_data {
            hm.insert("DuplicateData", Variant(Box::new(true)));
        }
        if discoverable {
            hm.insert("Discoverable", Variant(Box::new(true)));
        }

        if let Some(pattern) = pattern {
            hm.insert("Pattern", Variant(Box::new(pattern)));
        }
        hm
    }
}

#[cfg(test)]
mod aster_tests {
    use super::*;
    use std::{
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    fn session() -> (
        DiscoverySession,
        mpsc::Receiver<DiscoveryCommand>,
        watch::Sender<Option<DiscoveryTermination>>,
    ) {
        let (commands, command_rx) = mpsc::channel(1);
        let (termination, termination_rx) = watch::channel(None);
        (
            DiscoverySession {
                commands,
                termination: termination_rx,
            },
            command_rx,
            termination,
        )
    }

    #[tokio::test]
    async fn owned_discovery_stop_waits_for_ack_after_waiter_cancellation() {
        let (mut discovery, commands, termination) = session();
        let stops = Arc::new(AtomicUsize::new(0));
        let observed = stops.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let owner_started = started.clone();
        let allow_reply = Arc::new(tokio::sync::Notify::new());
        let owner_reply = allow_reply.clone();
        let (registration_reply, registration_result) = oneshot::channel();
        let (_session_tx, session_rx) = watch::channel(None);
        let owner = tokio::spawn(async move {
            let exit = run_discovery_owner(
                std::future::ready(Ok(stream::pending::<AdapterEvent>())),
                std::future::ready(Ok(())),
                DiscoveryStartup {
                    start: std::future::ready(Ok(())),
                    pre_state_baseline: std::future::ready(Ok(())),
                    discovering: std::future::ready(Ok(true)),
                    post_start_baseline: std::future::ready(Ok(())),
                },
                move || {
                    let observed = observed.clone();
                    let started = owner_started.clone();
                    let allow = owner_reply.clone();
                    async move {
                        observed.fetch_add(1, Ordering::AcqRel);
                        started.notify_one();
                        allow.notified().await;
                        Ok(())
                    }
                },
                registration_reply,
                commands,
                session_rx,
            )
            .await;
            exit.finish(termination);
        });
        registration_result.await.unwrap().unwrap();

        let mut stop = Box::pin(discovery.stop());
        std::future::poll_fn(|context| {
            assert!(stop.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        started.notified().await;
        assert_eq!(stops.load(Ordering::Acquire), 1);
        drop(stop);
        allow_reply.notify_one();
        owner.await.unwrap();
        assert_eq!(stops.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn pending_stop_observes_discovering_stopped() {
        let (mut discovery, commands, termination) = session();
        let (event_tx, event_rx) = mpsc::channel(1);
        let stop_started = Arc::new(tokio::sync::Notify::new());
        let owner_stop_started = stop_started.clone();
        let (registration_reply, registration_result) = oneshot::channel();
        let (_session_tx, session_rx) = watch::channel(None);
        let owner = tokio::spawn(async move {
            let exit = run_discovery_owner(
                std::future::ready(Ok(ReceiverStream::new(event_rx))),
                std::future::ready(Ok(())),
                DiscoveryStartup {
                    start: std::future::ready(Ok(())),
                    pre_state_baseline: std::future::ready(Ok(())),
                    discovering: std::future::ready(Ok(true)),
                    post_start_baseline: std::future::ready(Ok(())),
                },
                move || {
                    let started = owner_stop_started.clone();
                    async move {
                        started.notify_one();
                        std::future::pending::<Result<()>>().await
                    }
                },
                registration_reply,
                commands,
                session_rx,
            )
            .await;
            exit.finish(termination);
        });
        registration_result.await.unwrap().unwrap();

        let stopped = tokio::spawn(async move { discovery.stop().await });
        stop_started.notified().await;
        event_tx
            .send(AdapterEvent::PropertyChanged(
                AdapterProperty::Discovering(false),
            ))
            .await
            .unwrap();

        stopped.await.unwrap().unwrap();
        owner.await.unwrap();
    }

    #[tokio::test]
    async fn registration_cancellation_releases_before_event_subscription_finishes() {
        let (registration_reply, registration_result) = oneshot::channel();
        drop(registration_result);
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let stops = Arc::new(AtomicUsize::new(0));
        let observed = stops.clone();

        let exit = run_discovery_owner(
            std::future::pending::<Result<futures::stream::Pending<AdapterEvent>>>(),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::ready(Ok(())),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            move || {
                observed.fetch_add(1, Ordering::AcqRel);
                std::future::ready(Ok(()))
            },
            registration_reply,
            command_rx,
            session_rx,
        )
        .await;

        assert!(matches!(exit, DiscoveryOwnerExit::Released));
        assert_eq!(stops.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn ambiguous_start_failure_is_stopped_before_error_is_returned() {
        let (registration_reply, mut registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let stops = Arc::new(AtomicUsize::new(0));
        let observed = stops.clone();
        let start_error = Error::new(ErrorKind::Failed);

        let exit = run_discovery_owner(
            std::future::ready(Ok(stream::pending::<AdapterEvent>())),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::ready(Err(start_error.clone())),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            move || {
                observed.fetch_add(1, Ordering::AcqRel);
                std::future::ready(Ok(()))
            },
            registration_reply,
            command_rx,
            session_rx,
        )
        .await;

        assert_eq!(stops.load(Ordering::Acquire), 1);
        assert!(registration_result.try_recv().is_err());
        let (termination, _termination_rx) = watch::channel(None);
        exit.finish(termination);
        assert_eq!(registration_result.await.unwrap(), Err(start_error));
    }

    #[tokio::test]
    async fn cleanup_accepts_not_ready_as_proof_discovery_is_absent() {
        let mut events = stream::pending::<AdapterEvent>();
        let (_session_tx, mut session_rx) = watch::channel(None);
        let mut stop = || std::future::ready(Err(Error::new(ErrorKind::NotReady)));
        let mut cleanup = Box::pin(cleanup_unconfirmed_discovery(
            &mut events,
            &mut session_rx,
            &mut stop,
        ));

        let first_poll = std::future::poll_fn(|context| {
            std::task::Poll::Ready(cleanup.as_mut().poll(context))
        })
        .await;

        assert!(first_poll.is_ready());
    }

    #[tokio::test]
    async fn pending_start_observes_session_termination() {
        let (registration_reply, registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (session_tx, session_rx) = watch::channel(None);
        let mut owner = Box::pin(run_discovery_owner(
            std::future::ready(Ok(stream::pending::<AdapterEvent>())),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::pending::<Result<()>>(),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            || std::future::ready(Ok(())),
            registration_reply,
            command_rx,
            session_rx,
        ));

        let first_poll = std::future::poll_fn(|context| {
            std::task::Poll::Ready(owner.as_mut().poll(context))
        })
        .await;
        assert!(first_poll.is_pending());

        let session_error = Error::new(ErrorKind::Internal(InternalErrorKind::IngressOverflow));
        session_tx.send_replace(Some(session_error.clone()));
        let second_poll = std::future::poll_fn(|context| {
            std::task::Poll::Ready(owner.as_mut().poll(context))
        })
        .await;
        let std::task::Poll::Ready(exit) = second_poll else {
            panic!("session termination must stop registration");
        };
        assert!(matches!(
            &exit,
            DiscoveryOwnerExit::RegistrationTerminated(
                _,
                DiscoveryTermination::SessionEnded(error)
            ) if *error == session_error
        ));
        let (termination, _termination_rx) = watch::channel(None);
        exit.finish(termination);
        assert_eq!(registration_result.await.unwrap(), Err(session_error));
    }

    #[tokio::test]
    async fn queued_pre_start_false_does_not_terminate_started_discovery() {
        let (registration_reply, mut registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let events = stream::iter([AdapterEvent::PropertyChanged(
            AdapterProperty::Discovering(false),
        )])
        .chain(stream::pending());
        let mut owner = Box::pin(run_discovery_owner(
            std::future::ready(Ok(events)),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::ready(Ok(())),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            || std::future::ready(Ok(())),
            registration_reply,
            command_rx,
            session_rx,
        ));

        let first_poll = std::future::poll_fn(|context| {
            std::task::Poll::Ready(owner.as_mut().poll(context))
        })
        .await;

        assert!(first_poll.is_pending());
        assert_eq!(registration_result.try_recv().unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn pre_state_baseline_forwards_stale_false_before_registration() {
        let (registration_reply, mut registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let (event_tx, event_rx) = mpsc::channel(1);
        let _event_tx = event_tx.clone();
        let baseline_reached = Arc::new(AtomicUsize::new(0));
        let observed = baseline_reached.clone();
        let mut owner = Box::pin(run_discovery_owner(
            std::future::ready(Ok(ReceiverStream::new(event_rx))),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::ready(Ok(())),
                pre_state_baseline: async move {
                    event_tx
                        .send(AdapterEvent::PropertyChanged(
                            AdapterProperty::Discovering(false),
                        ))
                        .await
                        .unwrap();
                    observed.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            || std::future::ready(Ok(())),
            registration_reply,
            command_rx,
            session_rx,
        ));

        let first_poll = std::future::poll_fn(|context| {
            std::task::Poll::Ready(owner.as_mut().poll(context))
        })
        .await;

        assert!(first_poll.is_pending());
        assert_eq!(baseline_reached.load(Ordering::Acquire), 1);
        assert_eq!(registration_result.try_recv().unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn false_after_authoritative_state_prevents_registration() {
        let (registration_reply, registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let (event_tx, event_rx) = mpsc::channel(1);
        let exit = run_discovery_owner(
            std::future::ready(Ok(ReceiverStream::new(event_rx))),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::ready(Ok(())),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: async move {
                    event_tx
                        .send(AdapterEvent::PropertyChanged(
                            AdapterProperty::Discovering(false),
                        ))
                        .await
                        .unwrap();
                    Ok(())
                },
            },
            || std::future::ready(Ok(())),
            registration_reply,
            command_rx,
            session_rx,
        )
        .await;

        assert!(matches!(
            &exit,
            DiscoveryOwnerExit::RegistrationTerminated(
                _,
                DiscoveryTermination::DiscoveringStopped
            )
        ));
        let (termination, _termination_rx) = watch::channel(None);
        exit.finish(termination);
        assert_eq!(
            registration_result.await.unwrap(),
            Err(Error::new(ErrorKind::NotReady))
        );
    }

    #[tokio::test]
    async fn adapter_removal_before_registration_returns_not_found() {
        let (registration_reply, registration_result) = oneshot::channel();
        let (_commands, command_rx) = mpsc::channel(1);
        let (_session_tx, session_rx) = watch::channel(None);
        let exit = run_discovery_owner(
            std::future::ready(Ok(stream::empty::<AdapterEvent>())),
            std::future::ready(Ok(())),
            DiscoveryStartup {
                start: std::future::pending::<Result<()>>(),
                pre_state_baseline: std::future::ready(Ok(())),
                discovering: std::future::ready(Ok(true)),
                post_start_baseline: std::future::ready(Ok(())),
            },
            || std::future::ready(Ok(())),
            registration_reply,
            command_rx,
            session_rx,
        )
        .await;

        assert!(matches!(
            &exit,
            DiscoveryOwnerExit::RegistrationTerminated(
                _,
                DiscoveryTermination::AdapterRemoved
            )
        ));
        let (termination, _termination_rx) = watch::channel(None);
        exit.finish(termination);
        assert_eq!(
            registration_result.await.unwrap(),
            Err(Error::new(ErrorKind::NotFound))
        );
    }

    #[tokio::test]
    async fn owned_discovery_termination_is_persistent() {
        let (session, _commands, termination) = session();
        termination.send_replace(Some(DiscoveryTermination::DiscoveringStopped));
        assert_eq!(
            session.terminated().await,
            DiscoveryTermination::DiscoveringStopped
        );
    }
}
