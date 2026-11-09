//! Bluetooth LE advertising.

use dbus::{
    arg::{PropMap, RefArg, Variant},
    nonblock::{Proxy, SyncConnection},
};
use dbus_crossroads::{Crossroads, IfaceBuilder, IfaceToken};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    future::Future,
    sync::Arc,
    time::Duration,
};
use strum::{Display, EnumString};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

use crate::{
    method_call, read_dict, Adapter, Error, ErrorKind, InternalErrorKind, Result, SessionInner,
    SERVICE_NAME, TIMEOUT,
};

pub(crate) const MANAGER_INTERFACE: &str = "org.bluez.LEAdvertisingManager1";
pub(crate) const ADVERTISEMENT_INTERFACE: &str = "org.bluez.LEAdvertisement1";
pub(crate) const ADVERTISEMENT_PREFIX: &str = publish_path!("advertising/");

/// Determines the type of advertising packet requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Type {
    /// Broadcast
    #[strum(serialize = "broadcast")]
    Broadcast,
    /// Peripheral
    #[strum(serialize = "peripheral")]
    Peripheral,
}

impl Default for Type {
    fn default() -> Self {
        Self::Peripheral
    }
}

/// Secondary channel for advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SecondaryChannel {
    /// 1M
    #[strum(serialize = "1M")]
    OneM,
    /// 2M
    #[strum(serialize = "2M")]
    TwoM,
    /// Coded
    #[strum(serialize = "Coded")]
    Coded,
}

impl Default for SecondaryChannel {
    fn default() -> Self {
        Self::OneM
    }
}

/// Advertisement feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Feature {
    /// TX power.
    #[strum(serialize = "tx-power")]
    TxPower,
    /// Appearance.
    #[strum(serialize = "appearance")]
    Appearance,
    /// Local name.
    #[strum(serialize = "local-name")]
    LocalName,
}

/// LE advertising platform feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum PlatformFeature {
    /// Indicates whether platform can
    /// specify TX power on each
    /// advertising instance.
    #[strum(serialize = "CanSetTxPower")]
    CanSetTxPower,
    /// Indicates whether multiple
    /// advertising will be offloaded
    /// to the controller.
    #[strum(serialize = "HardwareOffload")]
    HardwareOffload,
}

/// Advertising-related controller capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Capabilities {
    /// Maximum advertising data length.
    pub max_advertisement_length: u8,
    /// Maximum advertising scan response length.
    pub max_scan_response_length: u8,
    /// Minimum advertising TX power (dBm).
    pub min_tx_power: i16,
    /// Maximum advertising TX power (dBm).
    pub max_tx_power: i16,
}

impl Capabilities {
    pub(crate) fn from_dict(dict: &HashMap<String, Variant<Box<dyn RefArg + 'static>>>) -> Result<Self> {
        Ok(Self {
            max_advertisement_length: *read_dict(dict, "MaxAdvLen")?,
            max_scan_response_length: *read_dict(dict, "MaxScnRspLen")?,
            min_tx_power: *read_dict(dict, "MinTxPower")?,
            max_tx_power: *read_dict(dict, "MaxTxPower")?,
        })
    }
}

/// Bluetooth LE advertisement data definition.
///
/// Specifies the Advertisement Data to be broadcast and some advertising
/// parameters.  Properties which are not present will not be included in the
/// data.  Required advertisement data types will always be included.
/// All UUIDs are 128-bit versions in the API, and 16 or 32-bit
/// versions of the same UUID will be used in the advertising data as appropriate.
///
/// Use [Adapter::advertise] to register a new advertisement.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Advertisement {
    /// Determines the type of advertising packet requested.
    pub advertisement_type: Type,
    /// List of UUIDs to include in the "Service UUID" field of
    /// the Advertising Data.
    pub service_uuids: BTreeSet<Uuid>,
    /// Manufacturer Data fields to include in
    /// the Advertising Data.
    ///
    /// Keys are the Manufacturer ID
    /// to associate with the data.
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
    /// Array of UUIDs to include in "Service Solicitation"
    /// Advertisement Data.
    pub solicit_uuids: BTreeSet<Uuid>,
    /// Service Data elements to include.
    ///
    /// The keys are the
    /// UUID to associate with the data.
    pub service_data: BTreeMap<Uuid, Vec<u8>>,
    /// Advertising Type to include in the Advertising
    /// Data.
    ///
    /// Key is the advertising type and value is the
    /// data as byte array.
    ///
    /// Note: Types already handled by other properties shall
    /// not be used.
    pub advertising_data: BTreeMap<u8, Vec<u8>>,
    /// Advertise as general discoverable.
    ///
    /// When present this
    /// will override adapter Discoverable property.
    ///
    /// Note: This property shall not be set when Type is set
    /// to broadcast. Additionally, Types that are official
    /// Bluetooth assigned numbers cannot be used. So for
    /// example the Type value of 0x0a cannot be used because
    /// it is assigned as the TX Power Level Type. But,
    /// currently the Type 0x0c is unassigned and can be used.
    pub discoverable: Option<bool>,
    /// The discoverable timeout in seconds.
    ///
    /// A value of zero
    /// means that the timeout is disabled and it will stay in
    /// discoverable/limited mode forever.
    ///
    /// Note: This property shall not be set when Type is set
    /// to broadcast.
    pub discoverable_timeout: Option<Duration>,
    /// List of system features to be included in the advertising
    /// packet.
    pub system_includes: BTreeSet<Feature>,
    /// Local name to be used in the advertising report.
    ///
    /// If the
    /// string is too big to fit into the packet it will be
    /// truncated.
    pub local_name: Option<String>,
    /// Appearance to be used in the advertising report.
    pub appearance: Option<u16>,
    /// Duration of the advertisement in seconds.
    ///
    /// If there are
    /// other applications advertising no duration is set the
    /// default is 2 seconds.
    pub duration: Option<Duration>,
    /// Timeout of the advertisement in seconds.
    ///
    /// This defines
    /// the lifetime of the advertisement.
    pub timeout: Option<Duration>,
    /// Secondary channel to be used.
    ///
    /// Primary channel is
    /// always set to "1M" except when "Coded" is set.
    pub secondary_channel: Option<SecondaryChannel>,
    /// Minimum advertising interval to be used by the
    /// advertising set, in milliseconds.
    ///
    /// Acceptable values
    /// are in the range [20ms, 10,485s]. If the provided
    /// MinInterval is larger than the provided MaxInterval,
    /// the registration will return failure.
    pub min_interval: Option<Duration>,
    /// Maximum advertising interval to be used by the
    /// advertising set, in milliseconds.
    ///
    /// Acceptable values
    /// are in the range [20ms, 10,485s]. If the provided
    /// MinInterval is larger than the provided MaxInterval,
    /// the registration will return failure.
    pub max_interval: Option<Duration>,
    /// Requested transmission power of this advertising set.
    ///
    /// The provided value is used only if the "CanSetTxPower"
    /// feature is enabled on the Advertising Manager. The
    /// provided value must be in range [-127 to +20], where
    /// units are in dBm.
    pub tx_power: Option<i16>,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

pub(crate) struct RegisteredAdvertisement {
    advertisement: Advertisement,
    release: watch::Sender<bool>,
}

impl Advertisement {
    pub(crate) fn register_interface(
        cr: &mut Crossroads,
    ) -> IfaceToken<Arc<RegisteredAdvertisement>> {
        cr.register(ADVERTISEMENT_INTERFACE, |ib: &mut IfaceBuilder<Arc<RegisteredAdvertisement>>| {
            cr_property!(ib, "Type", la => {
                Some(la.advertisement.advertisement_type.to_string())
            });
            cr_property!(ib, "ServiceUUIDs", la => {
                Some(la.advertisement.service_uuids.iter().map(|uuid| uuid.to_string()).collect::<Vec<_>>())
            });
            cr_property!(ib, "ManufacturerData", la => {
                Some(la.advertisement.manufacturer_data.clone().into_iter().map(|(k, v)| (k, Variant(v))).collect::<HashMap<_, _>>())
            });
            cr_property!(ib, "SolicitUUIDs", la => {
                Some(la.advertisement.solicit_uuids.iter().map(|uuid| uuid.to_string()).collect::<Vec<_>>())
            });
            cr_property!(ib, "ServiceData", la => {
                Some(la.advertisement.service_data.iter().map(|(k, v)| (k.to_string(), Variant(v.clone()))).collect::<HashMap<_, _>>())
            });
            cr_property!(ib, "Data", la => {
                Some(la.advertisement.advertising_data.iter().map(|(k, v)| (*k, Variant(v.clone()))).collect::<HashMap<_, _>>())
            });
            cr_property!(ib, "Discoverable", la => {
                la.advertisement.discoverable
            });
            cr_property!(ib, "DiscoverableTimeout", la => {
                la.advertisement.discoverable_timeout.map(|t| t.as_secs().min(u16::MAX as _) as u16)
            });
            cr_property!(ib, "Includes", la => {
                Some(la.advertisement.system_includes.iter().map(|v| v.to_string()).collect::<Vec<_>>())
            });
            cr_property!(ib, "LocalName", la => {
                la.advertisement.local_name.clone()
            });
            cr_property!(ib, "Appearance", la => {
                la.advertisement.appearance
            });
            cr_property!(ib, "Duration", la => {
                la.advertisement.duration.map(|t| t.as_secs().min(u16::MAX as _) as u16)
            });
            cr_property!(ib, "Timeout", la => {
                la.advertisement.timeout.map(|t| t.as_secs().min(u16::MAX as _) as u16)
            });
            cr_property!(ib, "SecondaryChannel", la => {
                la.advertisement.secondary_channel.map(|v| v.to_string())
            });
            cr_property!(ib, "MinInterval", la => {
                la.advertisement.min_interval.map(|t| t.as_millis().min(u32::MAX as _) as u32)
            });
            cr_property!(ib, "MaxInterval", la => {
                la.advertisement.max_interval.map(|t| t.as_millis().min(u32::MAX as _) as u32)
            });
            cr_property!(ib, "TxPower", la => {
                la.advertisement.tx_power
            });
            ib.method_with_cr_async("Release", (), (), |ctx, cr, ()| {
                method_call(ctx, cr, |registered: Arc<RegisteredAdvertisement>| async move {
                    registered.release.send_replace(true);
                    Ok(())
                })
            });
        })
    }

    pub(crate) async fn register(
        self, inner: Arc<SessionInner>, adapter_name: Arc<String>,
    ) -> Result<AdvertisementHandle> {
        let name = dbus::Path::new(format!("{}{}", ADVERTISEMENT_PREFIX, Uuid::new_v4().as_simple())).unwrap();
        let proxy = Proxy::new(
            SERVICE_NAME,
            Adapter::dbus_path(&adapter_name)?,
            TIMEOUT,
            inner.connection.clone(),
        );
        let (release, release_rx) = watch::channel(false);
        log::trace!("Publishing advertisement at {}", &name);

        {
            let mut cr = inner.crossroads.lock().await;
            cr.insert(
                name.clone(),
                &[inner.le_advertisment_token],
                Arc::new(RegisteredAdvertisement {
                    advertisement: self,
                    release,
                }),
            );
        }

        let (commands, command_rx) = mpsc::channel(1);
        let (registration_tx, registration_rx) = oneshot::channel();
        let owner_name = name.clone();
        let mut owner_release = release_rx.clone();
        let mut owner_session = inner.terminal.subscribe();
        let handle_session = inner.terminal.subscribe();
        tokio::spawn(async move {
            log::trace!("Registering advertisement at {}", &owner_name);
            let registration = proxy
                .method_call(
                    MANAGER_INTERFACE,
                    "RegisterAdvertisement",
                    (owner_name.clone(), PropMap::new()),
                )
                .await
                .map_err(Error::from);
            let exit = run_advertisement_owner(
                registration,
                registration_tx,
                command_rx,
                &mut owner_release,
                &mut owner_session,
                || unregister_advertisement(&proxy, &owner_name),
            )
            .await;

            log::trace!("Unpublishing advertisement at {}", &owner_name);
            let mut cr = inner.crossroads.lock().await;
            let _: Option<Arc<RegisteredAdvertisement>> = cr.remove(&owner_name);
            drop(cr);
            exit.finish();
        });

        registration_rx.await.map_err(|_| {
            Error::new(ErrorKind::Internal(InternalErrorKind::DBusConnectionLost))
        })??;
        Ok(AdvertisementHandle {
            name,
            commands,
            release: release_rx,
            session: handle_session,
        })
    }
}

enum AdvertisementCommand {
    Stop(oneshot::Sender<Result<()>>),
}

enum AdvertisementOwnerExit {
    RegistrationFailed(oneshot::Sender<Result<()>>, Error),
    Stopped(oneshot::Sender<Result<()>>),
    Released,
}

impl AdvertisementOwnerExit {
    fn finish(self) {
        match self {
            Self::RegistrationFailed(reply, error) => {
                let _ = reply.send(Err(error));
            }
            Self::Stopped(reply) => {
                let _ = reply.send(Ok(()));
            }
            Self::Released => {}
        }
    }
}

async fn unregister_advertisement(
    proxy: &Proxy<'_, Arc<SyncConnection>>,
    name: &dbus::Path<'static>,
) -> Result<()> {
    log::trace!("Unregistering advertisement at {}", name);
    proxy
        .method_call(
            MANAGER_INTERFACE,
            "UnregisterAdvertisement",
            (name.clone(),),
        )
        .await
        .map_err(Error::from)
}

async fn run_advertisement_owner<U, UFut>(
    registration: Result<()>,
    registration_reply: oneshot::Sender<Result<()>>,
    mut commands: mpsc::Receiver<AdvertisementCommand>,
    release: &mut watch::Receiver<bool>,
    session: &mut watch::Receiver<Option<Error>>,
    mut unregister: U,
) -> AdvertisementOwnerExit
where
    U: FnMut() -> UFut,
    UFut: Future<Output = Result<()>>,
{
    if let Err(error) = registration {
        cleanup_unconfirmed_advertisement(release, session, &mut unregister).await;
        return AdvertisementOwnerExit::RegistrationFailed(registration_reply, error);
    }

    let commands_open = registration_reply.send(Ok(())).is_ok();
    if !commands_open {
        cleanup_unconfirmed_advertisement(release, session, &mut unregister).await;
        return AdvertisementOwnerExit::Released;
    }

    loop {
        tokio::select! {
            command = commands.recv(), if commands_open => match command {
                Some(AdvertisementCommand::Stop(reply)) => {
                    let result = unregister().await;
                    if confirms_advertisement_absent(&result) {
                        return AdvertisementOwnerExit::Stopped(reply);
                    }
                    if let Err(error) = result {
                        let _ = reply.send(Err(error));
                    }
                },
                None => {
                    cleanup_unconfirmed_advertisement(release, session, &mut unregister).await;
                    return AdvertisementOwnerExit::Released;
                },
            },
            changed = release.changed() => {
                if changed.is_err() || *release.borrow_and_update() {
                    return AdvertisementOwnerExit::Released;
                }
            },
            changed = session.changed() => {
                if changed.is_err() || session.borrow_and_update().is_some() {
                    return AdvertisementOwnerExit::Released;
                }
            },
        }
    }
}

async fn cleanup_unconfirmed_advertisement<U, UFut>(
    release: &mut watch::Receiver<bool>,
    session: &mut watch::Receiver<Option<Error>>,
    unregister: &mut U,
) where
    U: FnMut() -> UFut,
    UFut: Future<Output = Result<()>>,
{
    loop {
        if confirms_advertisement_absent(&unregister().await) {
            return;
        }
        tokio::select! {
            changed = release.changed() => {
                if changed.is_err() || *release.borrow_and_update() {
                    return;
                }
            },
            changed = session.changed() => {
                if changed.is_err() || session.borrow_and_update().is_some() {
                    return;
                }
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
}

fn confirms_advertisement_absent(result: &Result<()>) -> bool {
    matches!(
        result,
        Ok(())
            | Err(Error {
                kind: ErrorKind::DoesNotExist | ErrorKind::NotFound | ErrorKind::NotRegistered,
                ..
            })
    )
}

/// Independently proven advertisement termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdvertisementTermination {
    /// BlueZ invoked `LEAdvertisement1.Release`.
    Released,
    /// The owning D-Bus session ended.
    SessionEnded(Error),
}

/// Handle to active Bluetooth LE advertisement.
///
/// Drop to unregister advertisement.
#[must_use = "AdvertisementHandle must be held for advertisement to be broadcasted"]
pub struct AdvertisementHandle {
    name: dbus::Path<'static>,
    commands: mpsc::Sender<AdvertisementCommand>,
    release: watch::Receiver<bool>,
    session: watch::Receiver<Option<Error>>,
}

impl AdvertisementHandle {
    /// Requests unregister and waits for BlueZ to acknowledge it.
    pub async fn stop(&mut self) -> Result<()> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(AdvertisementCommand::Stop(reply))
            .await
            .map_err(|_| Error::new(ErrorKind::NotRegistered))?;
        result
            .await
            .map_err(|_| Error::new(ErrorKind::NotRegistered))?
    }

    /// Waits for BlueZ release or terminal session loss.
    pub async fn terminated(&self) -> AdvertisementTermination {
        self.termination().await
    }

    /// Returns an owned waiter for BlueZ release or terminal session loss.
    pub fn termination(
        &self,
    ) -> impl Future<Output = AdvertisementTermination> + Send + 'static {
        let mut release = self.release.clone();
        let mut session = self.session.clone();
        async move {
            let mut release_open = true;
            let mut session_open = true;
            loop {
                if *release.borrow_and_update() {
                    return AdvertisementTermination::Released;
                }
                if let Some(error) = session.borrow_and_update().clone() {
                    return AdvertisementTermination::SessionEnded(error);
                }
                tokio::select! {
                    changed = release.changed(), if release_open => {
                        release_open = changed.is_ok();
                    },
                    changed = session.changed(), if session_open => {
                        session_open = changed.is_ok();
                    },
                    else => return AdvertisementTermination::SessionEnded(
                        Error::new(ErrorKind::Internal(InternalErrorKind::DBusConnectionLost))
                    ),
                }
            }
        }
    }
}

impl Drop for AdvertisementHandle {
    fn drop(&mut self) {
        // required for drop order
    }
}

impl fmt::Debug for AdvertisementHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AdvertisementHandle {{ {} }}", &self.name)
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

    fn test_handle() -> (
        AdvertisementHandle,
        mpsc::Receiver<AdvertisementCommand>,
        watch::Sender<bool>,
        watch::Sender<Option<Error>>,
    ) {
        let (commands, command_rx) = mpsc::channel(1);
        let (release, release_rx) = watch::channel(false);
        let (session, session_rx) = watch::channel(None);
        (
            AdvertisementHandle {
                name: "/org/bluez/aster_test".into(),
                commands,
                release: release_rx,
                session: session_rx,
            },
            command_rx,
            release,
            session,
        )
    }

    #[tokio::test]
    async fn stop_waits_for_owner_ack_and_survives_waiter_cancellation() {
        let (mut handle, commands, release, session) = test_handle();
        let unregisters = Arc::new(AtomicUsize::new(0));
        let observed = unregisters.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let owner_started = started.clone();
        let allow_reply = Arc::new(tokio::sync::Notify::new());
        let owner_reply = allow_reply.clone();
        let (registration_reply, registration_result) = oneshot::channel();
        let mut owner_release = release.subscribe();
        let mut owner_session = session.subscribe();
        let owner = tokio::spawn(async move {
            let exit = run_advertisement_owner(
                Ok(()),
                registration_reply,
                commands,
                &mut owner_release,
                &mut owner_session,
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
            )
            .await;
            exit.finish();
        });
        registration_result.await.unwrap().unwrap();

        let mut stop = Box::pin(handle.stop());
        std::future::poll_fn(|context| {
            assert!(stop.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        started.notified().await;
        assert_eq!(unregisters.load(Ordering::Acquire), 1);
        drop(stop);
        allow_reply.notify_one();
        owner.await.unwrap();
        assert_eq!(unregisters.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn failed_registration_attempts_cleanup_before_returning_error() {
        let (_handle, commands, release, session) = test_handle();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let signal_release = release.clone();
        let mut owner_release = release.subscribe();
        let mut owner_session = session.subscribe();
        let (registration_reply, mut registration_result) = oneshot::channel();
        let registration_error = Error::new(ErrorKind::Failed);

        let exit = run_advertisement_owner(
            Err(registration_error.clone()),
            registration_reply,
            commands,
            &mut owner_release,
            &mut owner_session,
            move || {
                observed.fetch_add(1, Ordering::AcqRel);
                signal_release.send_replace(true);
                std::future::ready(Err(Error::new(ErrorKind::Failed)))
            },
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(registration_result.try_recv().is_err());
        exit.finish();
        assert_eq!(registration_result.await.unwrap(), Err(registration_error));
    }

    #[tokio::test]
    async fn release_and_session_termination_are_persistent() {
        let (handle, _commands, release, _session) = test_handle();
        release.send_replace(true);
        assert_eq!(
            handle.terminated().await,
            AdvertisementTermination::Released
        );

        let (handle, _commands, _release, session) = test_handle();
        let error = Error::new(ErrorKind::Internal(InternalErrorKind::IngressOverflow));
        session.send_replace(Some(error.clone()));
        assert_eq!(
            handle.terminated().await,
            AdvertisementTermination::SessionEnded(error)
        );
    }

    #[tokio::test]
    async fn owned_termination_waiter_outlives_the_handle() {
        let (handle, _commands, release, _session) = test_handle();
        let termination = handle.termination();
        drop(handle);
        release.send_replace(true);

        assert_eq!(termination.await, AdvertisementTermination::Released);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_release_watch_does_not_starve_session_termination() {
        let (handle, _commands, release, session) = test_handle();
        drop(release);
        let waiter = tokio::spawn(async move { handle.terminated().await });
        tokio::task::yield_now().await;
        let error = Error::new(ErrorKind::Internal(InternalErrorKind::IngressOverflow));
        session.send_replace(Some(error.clone()));

        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), waiter)
                .await
                .unwrap()
                .unwrap(),
            AdvertisementTermination::SessionEnded(error)
        );
    }
}
