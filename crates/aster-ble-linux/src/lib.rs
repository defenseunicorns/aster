//! Linux BlueZ LE L2CAP evaluation driver.

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

mod config;
mod controller;
mod lifecycle;
mod policy;

pub use config::{
    DriverConfig, FixedRole, LinkConfig, OpenRequest, RING1_MAXIMUM_DEADLINE,
    RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, SupervisorConfig, ValidatedConfig,
    ValidatedLinkConfig, ValidatedSupervisorConfig,
};
pub use controller::{AvailabilityReason, BtleAvailability};
pub use lifecycle::{LinuxBtleEventSupervisor, SupervisorError, spawn_linux_btle_event_supervisor};

use aster_ble_l2cap::BleL2capContact;
use bluer::{
    Address, AddressType, ErrorKind, InternalErrorKind,
    adv::Advertisement,
    l2cap::{Socket, SocketAddr, Stream},
};
use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::{sleep, timeout},
};

const L2CAP_READINESS_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Closed failure categories surfaced by the Linux platform driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverErrorKind {
    /// Invalid local configuration.
    Configuration,
    /// Configured controller, permission, or peer is currently unavailable.
    Unavailable,
    /// A bounded platform operation exceeded its deadline.
    Timeout,
    /// The caller cancelled the in-flight platform operation.
    Cancelled,
    /// An unexpected transport or BlueZ failure occurred.
    Transport,
    /// A listener rejected a connection from a non-provisioned locator.
    PeerRejected,
}

/// Sanitized Linux driver error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverError {
    kind: DriverErrorKind,
    detail: &'static str,
}

impl DriverError {
    /// Creates an error from a closed category and non-sensitive static detail.
    pub const fn new(kind: DriverErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// Closed error category.
    pub const fn kind(&self) -> DriverErrorKind {
        self.kind
    }

    /// Sanitized diagnostic without controller or peer locators.
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Linux BTLE {:?}: {}", self.kind, self.detail)
    }
}

impl Error for DriverError {}

const fn configuration(detail: &'static str) -> DriverError {
    DriverError::new(DriverErrorKind::Configuration, detail)
}

/// Async byte stream accepted by the adapter-neutral carrier.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Type-erased platform byte stream used at the injected factory seam.
pub type BoxedStream = Box<dyn AsyncStream>;

/// Sanitized negotiated LE L2CAP MTUs observed on one connected socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedMtu {
    send_bytes: usize,
    receive_bytes: usize,
}

impl NegotiatedMtu {
    /// Kernel-reported maximum payload for one send operation.
    pub const fn send_bytes(self) -> usize {
        self.send_bytes
    }

    /// Kernel-reported maximum payload for one receive operation.
    pub const fn receive_bytes(self) -> usize {
        self.receive_bytes
    }
}

#[derive(Debug, Default)]
struct MtuState {
    send_bytes: AtomicUsize,
    receive_bytes: AtomicUsize,
}

#[derive(Clone, Debug, Default)]
struct MtuProbe(Arc<MtuState>);

impl MtuProbe {
    fn record_send(&self, bytes: usize) {
        if bytes > 0 {
            self.0.send_bytes.store(bytes, Ordering::Release);
        }
    }

    fn record_receive(&self, bytes: usize) {
        if bytes > 0 {
            self.0.receive_bytes.store(bytes, Ordering::Release);
        }
    }

    fn observation(&self) -> Option<NegotiatedMtu> {
        let send_bytes = self.0.send_bytes.load(Ordering::Acquire);
        let receive_bytes = self.0.receive_bytes.load(Ordering::Acquire);
        (send_bytes > 0 && receive_bytes > 0).then_some(NegotiatedMtu {
            send_bytes,
            receive_bytes,
        })
    }
}

/// One connected platform stream and its live, sanitized MTU observation.
pub struct SocketOpen {
    stream: BoxedStream,
    mtu: MtuProbe,
}

impl SocketOpen {
    /// Creates an injected socket result with already-observed nonzero MTUs.
    pub fn with_observed_mtu(
        stream: BoxedStream,
        send_bytes: usize,
        receive_bytes: usize,
    ) -> Result<Self, DriverError> {
        if send_bytes == 0
            || receive_bytes == 0
            || send_bytes > usize::from(u16::MAX)
            || receive_bytes > usize::from(u16::MAX)
        {
            return Err(configuration("observed L2CAP MTU is invalid"));
        }
        let mtu = MtuProbe::default();
        mtu.record_send(send_bytes);
        mtu.record_receive(receive_bytes);
        Ok(Self { stream, mtu })
    }

    fn from_bluez(stream: Stream) -> Self {
        let mtu = MtuProbe::default();
        let stream = MtuTrackingStream {
            stream,
            mtu: mtu.clone(),
        };
        stream.refresh();
        Self {
            stream: Box::new(stream),
            mtu,
        }
    }
}

struct MtuTrackingStream {
    stream: Stream,
    mtu: MtuProbe,
}

impl MtuTrackingStream {
    fn refresh(&self) {
        if let Ok(bytes) = self.stream.as_ref().send_mtu() {
            self.mtu.record_send(usize::from(bytes));
        }
        if let Ok(bytes) = self.stream.as_ref().recv_mtu() {
            self.mtu.record_receive(usize::from(bytes));
        }
    }
}

struct MtuBoundedStream {
    stream: BoxedStream,
    mtu: MtuProbe,
    maximum_write_bytes: usize,
    largest_successful_write_bytes: usize,
}

impl AsyncRead for MtuBoundedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for MtuBoundedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let send_bytes = self.mtu.0.send_bytes.load(Ordering::Acquire);
        if send_bytes == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        }
        let write_bytes = send_bytes.min(self.maximum_write_bytes);
        let buffer = &buffer[..buffer.len().min(write_bytes)];
        let attempted_bytes = buffer.len();
        let result = Pin::new(&mut self.stream).poll_write(context, buffer);
        // Linux segments one LE CoC SDU into peer-MPS-sized socket buffers and
        // allocates the complete SDU before queueing any byte. A large MTU and
        // small peer MPS can therefore exhaust the socket send-memory budget.
        // Adapt only this contact's platform write size after the kernel cannot
        // queue an attempted SDU; Aster framing and successful full-MTU peers
        // remain unchanged.
        match &result {
            Poll::Ready(Ok(written_bytes)) => {
                self.largest_successful_write_bytes =
                    self.largest_successful_write_bytes.max(*written_bytes);
            }
            Poll::Pending
                if attempted_bytes > self.largest_successful_write_bytes && attempted_bytes > 1 =>
            {
                self.maximum_write_bytes =
                    (attempted_bytes / 2).max(self.largest_successful_write_bytes);
                context.waker().wake_by_ref();
            }
            Poll::Ready(Err(_)) | Poll::Pending => {}
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl AsyncRead for MtuTrackingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            self.refresh();
        }
        result
    }
}

impl AsyncWrite for MtuTrackingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(context, buffer);
        if matches!(&result, Poll::Ready(Ok(_))) {
            self.refresh();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

/// Bounded asynchronous socket-open result.
pub type OpenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SocketOpen, DriverError>> + Send + 'a>>;

/// Injected Linux socket boundary used by deterministic tests and the system BlueZ adapter.
pub trait SocketFactory: Send + Sync {
    /// Opens one stream for the already-validated exact request.
    fn open(&self, request: OpenRequest) -> OpenFuture<'_>;
}

/// Cloneable cancellation signal for one platform-open attempt.
#[derive(Clone, Debug, Default)]
pub struct OpenCancellation {
    inner: Arc<OpenCancellationInner>,
}

#[derive(Debug, Default)]
struct OpenCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl OpenCancellation {
    /// Creates a signal in the active state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels current and future waiters.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
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
    use bluer::{Address, AddressType};
    use std::{
        io,
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

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
        assert_eq!(
            opened.negotiated_mtu(),
            Some(NegotiatedMtu {
                send_bytes: 128,
                receive_bytes: 96,
            })
        );
        assert_eq!(
            factory.request.lock().unwrap().as_ref(),
            Some(&config.open_request())
        );
    }

    struct RecordingWriteStream {
        writes: Arc<Mutex<Vec<usize>>>,
    }

    impl AsyncRead for RecordingWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    struct AllocationBoundedWriteStream {
        writes: Arc<Mutex<Vec<usize>>>,
        maximum_accepted_bytes: usize,
        oversized_attempt_seen: bool,
    }

    struct BackpressuredWriteStream {
        writes: Arc<Mutex<Vec<usize>>>,
        poll_count: usize,
    }

    struct NonWakingWriteStream {
        writes: Arc<Mutex<Vec<usize>>>,
        initial_partial_bytes: Option<usize>,
        poll_count: usize,
    }

    struct WakeCounter(AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AsyncRead for AllocationBoundedWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncRead for BackpressuredWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncRead for NonWakingWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for AllocationBoundedWriteStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buffer.len());
            if buffer.len() <= self.maximum_accepted_bytes {
                return Poll::Ready(Ok(buffer.len()));
            }
            if self.oversized_attempt_seen {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WouldBlock)));
            }
            self.oversized_attempt_seen = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for BackpressuredWriteStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buffer.len());
            self.poll_count += 1;
            if self.poll_count == 2 {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for NonWakingWriteStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buffer.len());
            self.poll_count += 1;
            match (self.initial_partial_bytes, self.poll_count) {
                (Some(bytes), 1) => Poll::Ready(Ok(bytes)),
                (Some(_), 2) | (None, 1) => Poll::Pending,
                _ => Poll::Ready(Ok(buffer.len())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingWriteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buffer.len());
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn mtu_bounded_stream_spans_one_record_across_platform_writes() {
        use tokio::io::AsyncWriteExt as _;

        let writes = Arc::new(Mutex::new(Vec::new()));
        let mtu = MtuProbe::default();
        mtu.record_send(64);
        mtu.record_receive(48);
        let mut stream = MtuBoundedStream {
            stream: Box::new(RecordingWriteStream {
                writes: writes.clone(),
            }),
            mtu,
            maximum_write_bytes: usize::MAX,
            largest_successful_write_bytes: 0,
        };

        stream.write_all(&[0x5a; 129]).await.unwrap();

        assert_eq!(*writes.lock().unwrap(), vec![64, 64, 1]);
    }

    #[tokio::test]
    async fn platform_write_adapts_after_a_large_sdu_cannot_be_queued() {
        use tokio::io::AsyncWriteExt as _;

        let writes = Arc::new(Mutex::new(Vec::new()));
        let mtu = MtuProbe::default();
        mtu.record_send(usize::from(u16::MAX));
        mtu.record_receive(672);
        let mut stream = MtuBoundedStream {
            stream: Box::new(AllocationBoundedWriteStream {
                writes: writes.clone(),
                maximum_accepted_bytes: 32_767,
                oversized_attempt_seen: false,
            }),
            mtu,
            maximum_write_bytes: usize::MAX,
            largest_successful_write_bytes: 0,
        };

        stream.write_all(&[0x5a; 65_535]).await.unwrap();

        assert_eq!(*writes.lock().unwrap(), vec![65_535, 32_767, 32_767, 1]);
    }

    #[tokio::test]
    async fn ordinary_backpressure_keeps_a_proven_platform_write_size() {
        use tokio::io::AsyncWriteExt as _;

        let writes = Arc::new(Mutex::new(Vec::new()));
        let mtu = MtuProbe::default();
        mtu.record_send(64);
        mtu.record_receive(48);
        let mut stream = MtuBoundedStream {
            stream: Box::new(BackpressuredWriteStream {
                writes: writes.clone(),
                poll_count: 0,
            }),
            mtu,
            maximum_write_bytes: usize::MAX,
            largest_successful_write_bytes: 0,
        };

        stream.write_all(&[0x5a; 128]).await.unwrap();

        assert_eq!(*writes.lock().unwrap(), vec![64, 64, 64]);
    }

    #[test]
    fn adaptive_write_self_wakes_when_only_a_smaller_retry_can_progress() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wake_counter.clone());
        let mut context = Context::from_waker(&waker);
        let mtu = MtuProbe::default();
        mtu.record_send(usize::from(u16::MAX));
        let mut stream = MtuBoundedStream {
            stream: Box::new(NonWakingWriteStream {
                writes: writes.clone(),
                initial_partial_bytes: None,
                poll_count: 0,
            }),
            mtu,
            maximum_write_bytes: usize::MAX,
            largest_successful_write_bytes: 0,
        };
        let buffer = vec![0x5a; 65_535];

        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut context, &buffer)
                .is_pending()
        );
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut context, &buffer),
            Poll::Ready(Ok(32_767))
        ));
        assert_eq!(*writes.lock().unwrap(), vec![65_535, 32_767]);
    }

    #[test]
    fn adaptive_write_never_drops_below_a_proven_partial_write_size() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wake_counter.clone());
        let mut context = Context::from_waker(&waker);
        let mtu = MtuProbe::default();
        mtu.record_send(64);
        let mut stream = MtuBoundedStream {
            stream: Box::new(NonWakingWriteStream {
                writes: writes.clone(),
                initial_partial_bytes: Some(40),
                poll_count: 0,
            }),
            mtu,
            maximum_write_bytes: usize::MAX,
            largest_successful_write_bytes: 0,
        };
        let buffer = [0x5a; 64];

        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut context, &buffer),
            Poll::Ready(Ok(40))
        ));
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut context, &buffer)
                .is_pending()
        );
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut context, &buffer),
            Poll::Ready(Ok(40))
        ));
        assert_eq!(*writes.lock().unwrap(), vec![64, 64, 40]);
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
