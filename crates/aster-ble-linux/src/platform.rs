use crate::{
    DriverError, DriverErrorKind, OpenCancellation, OpenRequest, ValidatedConfig, configuration,
    stream::{MtuBoundedStream, MtuProbe, NegotiatedMtu, SocketOpen},
};
use aster_ble_l2cap::BleL2capContact;
use bluer::{
    Address, AddressType, ErrorKind, InternalErrorKind,
    adv::Advertisement,
    l2cap::{Socket, SocketAddr, Stream},
};
use std::{fmt, future::Future, io, pin::Pin, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

const L2CAP_READINESS_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Bounded asynchronous socket-open result.
pub type OpenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SocketOpen, DriverError>> + Send + 'a>>;

/// Injected Linux socket boundary used by deterministic tests and the system BlueZ adapter.
pub trait SocketFactory: Send + Sync {
    /// Opens one stream for the already-validated exact request.
    fn open(&self, request: OpenRequest) -> OpenFuture<'_>;
}

/// One connected common carrier plus its complete-exchange ceiling.
pub struct OpenedContact {
    contact: Arc<BleL2capContact>,
    maximum_exchange_bytes: usize,
    mtu: MtuProbe,
}

impl fmt::Debug for OpenedContact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedContact")
            .field("contact", &"[REDACTED]")
            .field("maximum_exchange_bytes", &self.maximum_exchange_bytes)
            .field("negotiated_mtu", &self.negotiated_mtu())
            .finish()
    }
}

impl OpenedContact {
    /// Borrows the common ordered contact.
    pub fn contact(&self) -> &Arc<BleL2capContact> {
        &self.contact
    }

    /// Converts the driver result into the adapter-neutral runtime contact.
    pub fn into_contact(self) -> Arc<BleL2capContact> {
        self.contact
    }

    /// Maximum total bytes for the complete runtime exchange.
    pub const fn maximum_exchange_bytes(&self) -> usize {
        self.maximum_exchange_bytes
    }

    /// Returns both kernel-reported MTUs once they have been observed.
    ///
    /// Linux may not expose the send MTU immediately after connect. The
    /// measured stream refreshes this value after successful carrier I/O.
    pub fn negotiated_mtu(&self) -> Option<NegotiatedMtu> {
        self.mtu.observation()
    }
}

/// Opens a contact through an injected socket factory under cancellation and deadline.
pub async fn open_contact_with_factory(
    config: &ValidatedConfig,
    factory: &dyn SocketFactory,
    cancellation: &OpenCancellation,
) -> Result<OpenedContact, DriverError> {
    let open = factory.open(config.open_request());
    let opened_socket = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return Err(DriverError::new(
                DriverErrorKind::Cancelled,
                "platform open was cancelled",
            ));
        }
        result = timeout(config.open_timeout(), open) => match result {
            Ok(result) => result?,
            Err(_) => return Err(DriverError::new(
                DriverErrorKind::Timeout,
                "platform open exceeded its deadline",
            )),
        }
    };
    let SocketOpen { stream, mtu } = opened_socket;
    let stream = Box::new(MtuBoundedStream {
        stream,
        mtu: mtu.clone(),
        maximum_write_bytes: usize::MAX,
        largest_successful_write_bytes: 0,
    });
    let contact = BleL2capContact::new(
        stream,
        config.peer_locator()?,
        config.maximum_frame_bytes(),
        config.operation_timeout(),
    )
    .map_err(|_| configuration("validated carrier contact bounds were rejected"))?;
    Ok(OpenedContact {
        contact: Arc::new(contact),
        maximum_exchange_bytes: config.maximum_exchange_bytes(),
        mtu,
    })
}

/// BlueZ and kernel L2CAP socket implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct BluezSocketFactory;

impl SocketFactory for BluezSocketFactory {
    fn open(&self, request: OpenRequest) -> OpenFuture<'_> {
        Box::pin(open_bluez(request))
    }
}

/// Opens the configured contact using the system BlueZ daemon and kernel L2CAP.
///
/// This function observes controller power but never changes it.
pub async fn open_contact(
    config: &ValidatedConfig,
    cancellation: &OpenCancellation,
) -> Result<OpenedContact, DriverError> {
    open_contact_with_factory(config, &BluezSocketFactory, cancellation).await
}

async fn open_bluez(request: OpenRequest) -> Result<SocketOpen, DriverError> {
    let session = bluer::Session::new().await.map_err(map_bluer_error)?;
    match request {
        OpenRequest::Initiator {
            adapter_name,
            local,
            peer,
        } => {
            verify_adapter(&session, &adapter_name, local).await?;
            let socket = Socket::<Stream>::new_stream().map_err(map_io_error)?;
            socket.bind(local).map_err(map_io_error)?;
            let stream = socket.connect(peer).await.map_err(map_io_error)?;
            // BlueR may complete the async connect before the LE channel is
            // ready for I/O. The kernel exposes the send MTU once it is ready.
            wait_for_l2cap_readiness(|| stream.as_ref().send_mtu()).await?;
            Ok(SocketOpen::from_bluez(stream))
        }
        OpenRequest::Listener {
            adapter_name,
            local,
            expected_peer_address,
            expected_peer_address_type,
        } => {
            let adapter = verify_adapter(&session, &adapter_name, local).await?;
            let socket = Socket::<Stream>::new_stream().map_err(map_io_error)?;
            socket.bind(local).map_err(map_io_error)?;
            let listener = socket.listen(1).map_err(map_io_error)?;
            // Peripheral advertisements are connectable. Ring 1 provisions the
            // address and PSM out of band, so no discovery payload is emitted.
            let _advertisement = adapter
                .advertise(Advertisement::default())
                .await
                .map_err(map_bluer_error)?;
            let (stream, peer) = listener.accept().await.map_err(map_io_error)?;
            if peer.addr != expected_peer_address || peer.addr_type != expected_peer_address_type {
                return Err(DriverError::new(
                    DriverErrorKind::PeerRejected,
                    "listener rejected a non-provisioned Bluetooth peer",
                ));
            }
            Ok(SocketOpen::from_bluez(stream))
        }
    }
}

async fn wait_for_l2cap_readiness(
    mut probe_send_mtu: impl FnMut() -> io::Result<u16>,
) -> Result<(), DriverError> {
    loop {
        match probe_send_mtu() {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {
                sleep(L2CAP_READINESS_POLL_INTERVAL).await;
            }
            Err(error) => return Err(map_io_error(error)),
        }
    }
}

async fn verify_adapter(
    session: &bluer::Session,
    adapter_name: &str,
    local: SocketAddr,
) -> Result<bluer::Adapter, DriverError> {
    let names = session.adapter_names().await.map_err(map_bluer_error)?;
    classify_adapter_presence(&names, adapter_name)?;
    let adapter = session.adapter(adapter_name).map_err(map_bluer_error)?;
    classify_adapter_power(adapter.is_powered().await.map_err(map_bluer_error)?)?;
    let address = adapter.address().await.map_err(map_bluer_error)?;
    let address_type = adapter.address_type().await.map_err(map_bluer_error)?;
    classify_adapter_identity(local, address, address_type)?;
    Ok(adapter)
}

fn classify_adapter_presence(names: &[String], adapter_name: &str) -> Result<(), DriverError> {
    if !names.iter().any(|name| name == adapter_name) {
        return Err(DriverError::new(
            DriverErrorKind::Unavailable,
            "configured Bluetooth controller is unavailable",
        ));
    }
    Ok(())
}

fn classify_adapter_power(powered: bool) -> Result<(), DriverError> {
    if !powered {
        return Err(DriverError::new(
            DriverErrorKind::Unavailable,
            "configured Bluetooth controller is not powered",
        ));
    }
    Ok(())
}

fn classify_adapter_identity(
    expected: SocketAddr,
    observed_address: Address,
    observed_address_type: AddressType,
) -> Result<(), DriverError> {
    if observed_address != expected.addr || observed_address_type != expected.addr_type {
        return Err(DriverError::new(
            DriverErrorKind::Unavailable,
            "configured Bluetooth controller identity is unavailable",
        ));
    }
    Ok(())
}

fn map_bluer_error(error: bluer::Error) -> DriverError {
    let kind = match error.kind {
        ErrorKind::DoesNotExist
        | ErrorKind::NotAvailable
        | ErrorKind::NotAuthorized
        | ErrorKind::NotFound
        | ErrorKind::NotPermitted
        | ErrorKind::NotReady => DriverErrorKind::Unavailable,
        ErrorKind::AuthenticationTimeout => DriverErrorKind::Timeout,
        ErrorKind::InvalidArguments
        | ErrorKind::InvalidLength
        | ErrorKind::InvalidAddress(_)
        | ErrorKind::InvalidName(_) => DriverErrorKind::Configuration,
        ErrorKind::Internal(InternalErrorKind::DBusConnectionLost) => DriverErrorKind::Unavailable,
        ErrorKind::Internal(InternalErrorKind::Io(kind)) => classify_io_error(kind),
        _ => DriverErrorKind::Transport,
    };
    DriverError::new(kind, "BlueZ operation failed")
}

fn map_io_error(error: io::Error) -> DriverError {
    let kind = classify_io_error(error.kind());
    DriverError::new(kind, "kernel L2CAP operation failed")
}

fn classify_io_error(kind: io::ErrorKind) -> DriverErrorKind {
    match kind {
        io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NotConnected
        | io::ErrorKind::NotFound
        | io::ErrorKind::PermissionDenied => DriverErrorKind::Unavailable,
        io::ErrorKind::TimedOut => DriverErrorKind::Timeout,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => DriverErrorKind::Configuration,
        _ => DriverErrorKind::Transport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DriverConfig, FixedRole, LinkConfig, OpenFuture, SocketFactory};
    use std::{
        str::FromStr,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::sync::Notify;

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("test Bluetooth address")
    }

    fn config(role: FixedRole) -> DriverConfig {
        DriverConfig {
            link: LinkConfig {
                adapter_name: "hci7".to_owned(),
                local_address: address("02:00:00:00:00:01"),
                local_address_type: AddressType::LeRandom,
                peer_address: address("02:00:00:00:00:02"),
                peer_address_type: AddressType::LePublic,
                psm: 0x0081,
                maximum_frame_bytes: 2 * 1024 * 1024,
                maximum_exchange_bytes: 64 * 1024 * 1024,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
            role,
        }
    }

    struct ResultFactory {
        request: Mutex<Option<OpenRequest>>,
        result: Mutex<Option<Result<SocketOpen, DriverError>>>,
    }

    impl SocketFactory for ResultFactory {
        fn open(&self, request: OpenRequest) -> OpenFuture<'_> {
            *self.request.lock().unwrap() = Some(request);
            let result = self.result.lock().unwrap().take().unwrap();
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn injected_factory_builds_a_bounded_contact_without_bluez() {
        let (stream, _peer) = tokio::io::duplex(4096);
        let factory = ResultFactory {
            request: Mutex::new(None),
            result: Mutex::new(Some(Ok(SocketOpen::with_observed_mtu(
                Box::new(stream),
                128,
                96,
            )
            .unwrap()))),
        };
        let config = config(FixedRole::Initiator).validate().unwrap();

        let opened = open_contact_with_factory(&config, &factory, &OpenCancellation::new())
            .await
            .unwrap();

        assert_eq!(opened.maximum_exchange_bytes(), 64 * 1024 * 1024);
        let mtu = opened.negotiated_mtu().unwrap();
        assert_eq!(mtu.send_bytes(), 128);
        assert_eq!(mtu.receive_bytes(), 96);
        assert_eq!(
            factory.request.lock().unwrap().as_ref(),
            Some(&config.open_request())
        );
    }

    #[tokio::test]
    async fn connection_readiness_retries_not_connected_until_send_mtu_exists() {
        let attempts = AtomicUsize::new(0);

        wait_for_l2cap_readiness(|| {
            if attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                Err(io::Error::from(io::ErrorKind::NotConnected))
            } else {
                Ok(128)
            }
        })
        .await
        .unwrap();

        assert_eq!(attempts.load(Ordering::Acquire), 2);
    }

    #[test]
    fn controller_selection_classifies_absence_and_power_without_dbus() {
        let names = vec!["hci0".to_owned(), "hci2".to_owned()];
        let missing = classify_adapter_presence(&names, "hci7").unwrap_err();
        let unpowered = classify_adapter_power(false).unwrap_err();

        assert_eq!(missing.kind(), DriverErrorKind::Unavailable);
        assert_eq!(unpowered.kind(), DriverErrorKind::Unavailable);
        assert!(classify_adapter_presence(&names, "hci2").is_ok());
        assert!(classify_adapter_power(true).is_ok());
    }

    #[test]
    fn io_errors_map_to_closed_driver_categories() {
        assert_eq!(
            map_io_error(io::Error::from(io::ErrorKind::NotFound)).kind(),
            DriverErrorKind::Unavailable
        );
        assert_eq!(
            map_io_error(io::Error::from(io::ErrorKind::ConnectionRefused)).kind(),
            DriverErrorKind::Unavailable
        );
        assert_eq!(
            map_io_error(io::Error::from(io::ErrorKind::TimedOut)).kind(),
            DriverErrorKind::Timeout
        );
        assert_eq!(
            map_io_error(io::Error::from(io::ErrorKind::InvalidInput)).kind(),
            DriverErrorKind::Configuration
        );
        assert_eq!(
            map_io_error(io::Error::from(io::ErrorKind::Other)).kind(),
            DriverErrorKind::Transport
        );
    }

    #[test]
    fn bluez_loss_and_internal_io_absence_map_to_unavailable() {
        let daemon_loss = bluer::Error {
            kind: bluer::ErrorKind::Internal(bluer::InternalErrorKind::DBusConnectionLost),
            message: "sensitive daemon detail".to_owned(),
        };
        let controller_loss = bluer::Error {
            kind: bluer::ErrorKind::Internal(bluer::InternalErrorKind::Io(io::ErrorKind::NotFound)),
            message: "sensitive controller detail".to_owned(),
        };

        assert_eq!(
            map_bluer_error(daemon_loss).kind(),
            DriverErrorKind::Unavailable
        );
        assert_eq!(
            map_bluer_error(controller_loss).kind(),
            DriverErrorKind::Unavailable
        );
        assert_eq!(
            map_bluer_error(bluer::Error {
                kind: bluer::ErrorKind::InvalidArguments,
                message: "sensitive invalid detail".to_owned(),
            }),
            DriverError::new(DriverErrorKind::Configuration, "BlueZ operation failed")
        );
    }

    #[test]
    fn replaced_controller_identity_is_unavailable_not_invalid_configuration() {
        let expected = bluer::l2cap::SocketAddr::new(
            address("02:00:00:00:00:01"),
            AddressType::LeRandom,
            0x81,
        );
        let wrong_address = classify_adapter_identity(
            expected,
            address("02:00:00:00:00:09"),
            AddressType::LeRandom,
        )
        .unwrap_err();
        let wrong_type = classify_adapter_identity(
            expected,
            address("02:00:00:00:00:01"),
            AddressType::LePublic,
        )
        .unwrap_err();

        assert_eq!(wrong_address.kind(), DriverErrorKind::Unavailable);
        assert_eq!(wrong_type.kind(), DriverErrorKind::Unavailable);
    }

    struct PendingFactory {
        started: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }

    struct DropWitness(Arc<AtomicBool>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    impl SocketFactory for PendingFactory {
        fn open(&self, _request: OpenRequest) -> OpenFuture<'_> {
            let started = self.started.clone();
            let witness = DropWitness(self.dropped.clone());
            Box::pin(async move {
                let _witness = witness;
                started.notify_one();
                std::future::pending::<Result<SocketOpen, DriverError>>().await
            })
        }
    }

    #[tokio::test]
    async fn cancellation_drops_the_inflight_platform_operation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(Notify::new());
        let factory = PendingFactory {
            started: started.clone(),
            dropped: dropped.clone(),
        };
        let cancellation = OpenCancellation::new();
        let cancel_after_start = cancellation.clone();
        let task = tokio::spawn(async move {
            open_contact_with_factory(
                &config(FixedRole::Initiator).validate().unwrap(),
                &factory,
                &cancel_after_start,
            )
            .await
        });
        started.notified().await;
        cancellation.cancel();

        let error = task.await.unwrap().unwrap_err();

        assert_eq!(error.kind(), DriverErrorKind::Cancelled);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn open_timeout_drops_the_started_platform_operation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let factory = PendingFactory {
            started: Arc::new(Notify::new()),
            dropped: dropped.clone(),
        };
        let mut config = config(FixedRole::Listener);
        config.link.open_timeout = Duration::from_millis(1);

        let error = open_contact_with_factory(
            &config.validate().unwrap(),
            &factory,
            &OpenCancellation::new(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), DriverErrorKind::Timeout);
        assert!(dropped.load(Ordering::Acquire));
    }
}
