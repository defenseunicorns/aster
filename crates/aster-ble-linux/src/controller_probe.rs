#[cfg(test)]
mod tests {
    use super::{
        ControllerProbeBackend, ControllerProbeError, ControllerProbeFuture, ControllerProbeLimits,
        probe_controller,
    };
    use crate::{
        ControllerAdmissionPolicy, ControllerCandidate, ControllerFingerprint,
        LifecycleCancellation, ProbeDisposition, ProbeReason, UnsafeRule,
        normalize_controller_inventory,
    };
    use bluer::{Address, AddressType, l2cap::SocketAddr};
    use std::{str::FromStr, sync::Mutex, time::Duration};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        OpenSession,
        ReadPowered,
        ReadAddress,
        ReadAddressType,
        CreateSocket,
        Bind,
        LocalPsm,
        Listen,
        Close,
    }

    struct FakeBackend {
        operations: Mutex<Vec<Operation>>,
        powered: bool,
        address: Address,
        address_type: AddressType,
        failure: Mutex<Option<(Operation, ControllerProbeError)>>,
        bound: Mutex<Option<SocketAddr>>,
    }

    impl FakeBackend {
        fn compatible() -> Self {
            Self {
                operations: Mutex::new(Vec::new()),
                powered: true,
                address: address(),
                address_type: AddressType::LeRandom,
                failure: Mutex::new(None),
                bound: Mutex::new(None),
            }
        }

        fn with_failure(operation: Operation, error: ControllerProbeError) -> Self {
            Self {
                failure: Mutex::new(Some((operation, error))),
                ..Self::compatible()
            }
        }

        fn record(&self, operation: Operation) -> Result<(), ControllerProbeError> {
            self.operations.lock().unwrap().push(operation);
            let mut failure = self.failure.lock().unwrap();
            if let Some((failed_operation, error)) = *failure {
                if failed_operation == operation {
                    *failure = None;
                    return Err(error);
                }
            }
            Ok(())
        }
    }

    impl ControllerProbeBackend for FakeBackend {
        type Session = ();
        type Socket = ();
        type Listener = ();

        fn open_session(&self) -> ControllerProbeFuture<'_, Self::Session> {
            Box::pin(async move {
                self.record(Operation::OpenSession)?;
                Ok(())
            })
        }

        fn powered<'a>(
            &'a self,
            _session: &'a Self::Session,
            _candidate: &'a ControllerCandidate,
        ) -> ControllerProbeFuture<'a, bool> {
            Box::pin(async move {
                self.record(Operation::ReadPowered)?;
                Ok(self.powered)
            })
        }

        fn address<'a>(
            &'a self,
            _session: &'a Self::Session,
            _candidate: &'a ControllerCandidate,
        ) -> ControllerProbeFuture<'a, Address> {
            Box::pin(async move {
                self.record(Operation::ReadAddress)?;
                Ok(self.address)
            })
        }

        fn address_type<'a>(
            &'a self,
            _session: &'a Self::Session,
            _candidate: &'a ControllerCandidate,
        ) -> ControllerProbeFuture<'a, AddressType> {
            Box::pin(async move {
                self.record(Operation::ReadAddressType)?;
                Ok(self.address_type)
            })
        }

        fn create_socket(&self) -> ControllerProbeFuture<'_, Self::Socket> {
            Box::pin(async move {
                self.record(Operation::CreateSocket)?;
                Ok(())
            })
        }

        fn bind<'a>(
            &'a self,
            _socket: &'a Self::Socket,
            local: SocketAddr,
        ) -> ControllerProbeFuture<'a, ()> {
            Box::pin(async move {
                self.record(Operation::Bind)?;
                *self.bound.lock().unwrap() = Some(local);
                Ok(())
            })
        }

        fn local_psm<'a>(&'a self, _socket: &'a Self::Socket) -> ControllerProbeFuture<'a, u16> {
            Box::pin(async move {
                self.record(Operation::LocalPsm)?;
                Ok(0x0081)
            })
        }

        fn listen(&self, _socket: Self::Socket) -> ControllerProbeFuture<'_, Self::Listener> {
            Box::pin(async move {
                self.record(Operation::Listen)?;
                Ok(())
            })
        }

        fn close(&self, _listener: Self::Listener) -> ControllerProbeFuture<'_, ()> {
            Box::pin(async move {
                self.record(Operation::Close)?;
                Ok(())
            })
        }
    }

    fn address() -> Address {
        Address::from_str("02:00:00:00:00:01").unwrap()
    }

    fn candidate() -> ControllerCandidate {
        candidate_with(address(), AddressType::LeRandom)
    }

    fn candidate_with(address: Address, address_type: AddressType) -> ControllerCandidate {
        ControllerCandidate::new("hci0".to_owned(), address, address_type)
    }

    fn limits() -> ControllerProbeLimits {
        ControllerProbeLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(3),
        )
    }

    async fn probe(backend: &FakeBackend) -> ProbeDisposition {
        probe_controller(
            backend,
            &candidate(),
            &ControllerFingerprint::default(),
            &ControllerAdmissionPolicy::default(),
            &LifecycleCancellation::new(),
            limits(),
        )
        .await
    }

    #[tokio::test]
    async fn probe_success_is_compatible() {
        assert_eq!(
            probe(&FakeBackend::compatible()).await,
            ProbeDisposition::Compatible
        );
    }

    #[tokio::test]
    async fn unsupported_address_family_is_incompatible() {
        let backend = FakeBackend {
            address_type: AddressType::BrEdr,
            ..FakeBackend::compatible()
        };

        assert_eq!(
            probe_controller(
                &backend,
                &candidate_with(address(), AddressType::BrEdr),
                &ControllerFingerprint::default(),
                &ControllerAdmissionPolicy::default(),
                &LifecycleCancellation::new(),
                limits(),
            )
            .await,
            ProbeDisposition::Incompatible(ProbeReason::UnsupportedAddressFamily)
        );
    }

    #[tokio::test]
    async fn permission_resource_timeout_and_unknown_are_indeterminate() {
        for (error, reason) in [
            (
                ControllerProbeError::PermissionDenied,
                ProbeReason::PermissionDenied,
            ),
            (
                ControllerProbeError::ResourceExhausted,
                ProbeReason::ResourceExhausted,
            ),
            (
                ControllerProbeError::DeadlineExceeded,
                ProbeReason::DeadlineExceeded,
            ),
            (
                ControllerProbeError::UnknownPlatformError,
                ProbeReason::UnknownPlatformError,
            ),
        ] {
            let backend = FakeBackend::with_failure(Operation::OpenSession, error);
            assert_eq!(
                probe(&backend).await,
                ProbeDisposition::Indeterminate(reason)
            );
        }
    }

    #[tokio::test]
    async fn cancelled_probe_is_indeterminate() {
        let backend = FakeBackend::compatible();
        let cancellation = LifecycleCancellation::new();
        cancellation.cancel();

        assert_eq!(
            probe_controller(
                &backend,
                &candidate(),
                &ControllerFingerprint::default(),
                &ControllerAdmissionPolicy::default(),
                &cancellation,
                limits(),
            )
            .await,
            ProbeDisposition::Indeterminate(ProbeReason::Cancelled)
        );
    }

    #[tokio::test]
    async fn unpowered_and_removed_are_indeterminate() {
        let unpowered = FakeBackend {
            powered: false,
            ..FakeBackend::compatible()
        };
        let removed =
            FakeBackend::with_failure(Operation::ReadAddress, ControllerProbeError::Removed);

        assert_eq!(
            probe(&unpowered).await,
            ProbeDisposition::Indeterminate(ProbeReason::ControllerUnpowered)
        );
        assert_eq!(
            probe(&removed).await,
            ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable)
        );
    }

    #[tokio::test]
    async fn unsafe_rule_blocks_before_socket_open() {
        let backend = FakeBackend::compatible();
        let policy = ControllerAdmissionPolicy::with_rows(
            false,
            Vec::new(),
            vec![UnsafeRule::exact(ControllerFingerprint::default())],
        );

        assert_eq!(
            probe_controller(
                &backend,
                &candidate(),
                &ControllerFingerprint::default(),
                &policy,
                &LifecycleCancellation::new(),
                limits(),
            )
            .await,
            ProbeDisposition::Blocked(ProbeReason::KnownUnsafe)
        );
        assert!(backend.operations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_failure_is_indeterminate() {
        let backend =
            FakeBackend::with_failure(Operation::Close, ControllerProbeError::UnknownPlatformError);

        assert_eq!(
            probe(&backend).await,
            ProbeDisposition::Indeterminate(ProbeReason::UnknownPlatformError)
        );
    }

    #[tokio::test]
    async fn wildcard_observed_address_is_indeterminate_before_socket_creation() {
        let backend = FakeBackend {
            address: Address::any(),
            ..FakeBackend::compatible()
        };

        assert_eq!(
            probe(&backend).await,
            ProbeDisposition::Indeterminate(ProbeReason::UnknownPlatformError)
        );
        assert!(
            !backend
                .operations
                .lock()
                .unwrap()
                .contains(&Operation::CreateSocket)
        );
    }

    #[tokio::test]
    async fn candidate_without_snapshot_is_indeterminate_before_session_creation() {
        let backend = FakeBackend::compatible();
        let candidate = normalize_controller_inventory(vec!["hci0".to_owned()], None, None)
            .candidates()[0]
            .clone();

        assert_eq!(
            probe_controller(
                &backend,
                &candidate,
                &ControllerFingerprint::default(),
                &ControllerAdmissionPolicy::default(),
                &LifecycleCancellation::new(),
                limits(),
            )
            .await,
            ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable)
        );
        assert!(backend.operations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn observed_identity_mismatch_is_indeterminate_before_socket_creation() {
        let backend = FakeBackend {
            address: Address::from_str("02:00:00:00:00:09").unwrap(),
            ..FakeBackend::compatible()
        };

        assert_eq!(
            probe(&backend).await,
            ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable)
        );
        assert!(
            !backend
                .operations
                .lock()
                .unwrap()
                .contains(&Operation::CreateSocket)
        );
    }

    #[tokio::test]
    async fn probe_runs_passive_local_operations_in_order() {
        let backend = FakeBackend::compatible();

        assert_eq!(probe(&backend).await, ProbeDisposition::Compatible);
        assert_eq!(
            *backend.operations.lock().unwrap(),
            vec![
                Operation::OpenSession,
                Operation::ReadPowered,
                Operation::ReadAddress,
                Operation::ReadAddressType,
                Operation::CreateSocket,
                Operation::Bind,
                Operation::LocalPsm,
                Operation::Listen,
                Operation::Close,
            ]
        );
        assert_eq!(
            backend
                .bound
                .lock()
                .unwrap()
                .as_ref()
                .map(|local| local.psm),
            Some(0)
        );
    }
}
use crate::{
    ControllerAdmissionPolicy, ControllerCandidate, ControllerFingerprint, ControllerSnapshot,
    LifecycleCancellation, ProbeDisposition, ProbeReason,
    platform::socket::{map_probe_bluer_error, map_probe_io_error, validate_dynamic_le_psm},
};
use bluer::{
    Address, AddressType,
    l2cap::{Socket, SocketAddr, Stream, StreamListener},
};
use std::{future::Future, pin::Pin, time::Duration};
use tokio::time::timeout;

/// Closed controller-probe failures produced at the BlueZ and kernel boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerProbeError {
    /// The address family is not LE public or LE random.
    UnsupportedAddressFamily,
    /// BlueZ does not support the required protocol operation.
    UnsupportedProtocol,
    /// The kernel does not support LE connection-oriented channels.
    UnsupportedLeCoc,
    /// BlueZ or its D-Bus session became unavailable.
    BluezUnavailable,
    /// The controller was not powered during the probe.
    ControllerUnpowered,
    /// The service identity was denied the required operation.
    PermissionDenied,
    /// A local bounded resource was unavailable.
    ResourceExhausted,
    /// A deadline expired before an operation completed.
    DeadlineExceeded,
    /// The candidate disappeared while its properties were being read.
    Removed,
    /// A cancellation signal ended the probe.
    Cancelled,
    /// An otherwise unclassified typed platform failure occurred.
    UnknownPlatformError,
}

impl ControllerProbeError {
    const fn disposition(self) -> ProbeDisposition {
        match self {
            Self::UnsupportedAddressFamily => {
                ProbeDisposition::Incompatible(ProbeReason::UnsupportedAddressFamily)
            }
            Self::UnsupportedProtocol => {
                ProbeDisposition::Incompatible(ProbeReason::UnsupportedProtocol)
            }
            Self::UnsupportedLeCoc => ProbeDisposition::Incompatible(ProbeReason::UnsupportedLeCoc),
            Self::BluezUnavailable | Self::Removed => {
                ProbeDisposition::Indeterminate(ProbeReason::BluezUnavailable)
            }
            Self::ControllerUnpowered => {
                ProbeDisposition::Indeterminate(ProbeReason::ControllerUnpowered)
            }
            Self::PermissionDenied => {
                ProbeDisposition::Indeterminate(ProbeReason::PermissionDenied)
            }
            Self::ResourceExhausted => {
                ProbeDisposition::Indeterminate(ProbeReason::ResourceExhausted)
            }
            Self::DeadlineExceeded => {
                ProbeDisposition::Indeterminate(ProbeReason::DeadlineExceeded)
            }
            Self::Cancelled => ProbeDisposition::Indeterminate(ProbeReason::Cancelled),
            Self::UnknownPlatformError => {
                ProbeDisposition::Indeterminate(ProbeReason::UnknownPlatformError)
            }
        }
    }
}

/// Boxed asynchronous passive controller-probe operation.
pub type ControllerProbeFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ControllerProbeError>> + Send + 'a>>;

/// Passive BlueZ and kernel operations required to preflight one controller.
///
/// Deliberately absent: advertisement, scanning, power/reset, pairing/bonding,
/// device mutation, disconnect, and configuration operations.
pub trait ControllerProbeBackend: Send + Sync {
    /// Opaque BlueZ session retained for all property reads in one attempt.
    type Session: Send;
    /// Opaque unconnected LE CoC socket.
    type Socket: Send;
    /// Opaque passive listener that owns the acquired socket.
    type Listener: Send;

    /// Opens a BlueZ session.
    fn open_session(&self) -> ControllerProbeFuture<'_, Self::Session>;
    /// Reads the controller powered property.
    fn powered<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, bool>;
    /// Reads the exact controller address.
    fn address<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, Address>;
    /// Reads the controller address family.
    fn address_type<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, AddressType>;
    /// Creates an unconnected LE CoC socket.
    fn create_socket(&self) -> ControllerProbeFuture<'_, Self::Socket>;
    /// Binds the socket to the observed LE address with PSM zero.
    fn bind<'a>(
        &'a self,
        socket: &'a Self::Socket,
        local: SocketAddr,
    ) -> ControllerProbeFuture<'a, ()>;
    /// Reads the dynamically allocated local PSM after bind.
    fn local_psm<'a>(&'a self, socket: &'a Self::Socket) -> ControllerProbeFuture<'a, u16>;
    /// Listens on the dynamically allocated PSM.
    fn listen(&self, socket: Self::Socket) -> ControllerProbeFuture<'_, Self::Listener>;
    /// Closes the listener and its socket.
    fn close(&self, listener: Self::Listener) -> ControllerProbeFuture<'_, ()>;
}

/// Caller-supplied bounds for one serialized passive probe sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerProbeLimits {
    operation: Duration,
    candidate: Duration,
    sweep: Duration,
}

impl ControllerProbeLimits {
    /// Creates operation, candidate, and whole-sweep bounds in that order.
    pub const fn new(operation: Duration, candidate: Duration, sweep: Duration) -> Self {
        Self {
            operation,
            candidate,
            sweep,
        }
    }

    pub(crate) const fn operation(self) -> Duration {
        self.operation
    }

    pub(crate) const fn candidate(self) -> Duration {
        self.candidate
    }

    pub(crate) const fn sweep(self) -> Duration {
        self.sweep
    }
}

/// Production backend using only passive public BlueZ and kernel operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct BluezControllerProbeBackend;

impl ControllerProbeBackend for BluezControllerProbeBackend {
    type Session = bluer::Session;
    type Socket = Socket<Stream>;
    type Listener = StreamListener;

    fn open_session(&self) -> ControllerProbeFuture<'_, Self::Session> {
        Box::pin(async { bluer::Session::new().await.map_err(map_probe_bluer_error) })
    }

    fn powered<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, bool> {
        Box::pin(async move {
            session
                .adapter(candidate.name())
                .map_err(map_probe_bluer_error)?
                .is_powered()
                .await
                .map_err(map_probe_bluer_error)
        })
    }

    fn address<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, Address> {
        Box::pin(async move {
            session
                .adapter(candidate.name())
                .map_err(map_probe_bluer_error)?
                .address()
                .await
                .map_err(map_probe_bluer_error)
        })
    }

    fn address_type<'a>(
        &'a self,
        session: &'a Self::Session,
        candidate: &'a ControllerCandidate,
    ) -> ControllerProbeFuture<'a, AddressType> {
        Box::pin(async move {
            session
                .adapter(candidate.name())
                .map_err(map_probe_bluer_error)?
                .address_type()
                .await
                .map_err(map_probe_bluer_error)
        })
    }

    fn create_socket(&self) -> ControllerProbeFuture<'_, Self::Socket> {
        Box::pin(async { Socket::<Stream>::new_stream().map_err(map_probe_io_error) })
    }

    fn bind<'a>(
        &'a self,
        socket: &'a Self::Socket,
        local: SocketAddr,
    ) -> ControllerProbeFuture<'a, ()> {
        Box::pin(async move { socket.bind(local).map_err(map_probe_io_error) })
    }

    fn local_psm<'a>(&'a self, socket: &'a Self::Socket) -> ControllerProbeFuture<'a, u16> {
        Box::pin(async move {
            socket
                .local_addr()
                .map(|address| address.psm)
                .map_err(map_probe_io_error)
        })
    }

    fn listen(&self, socket: Self::Socket) -> ControllerProbeFuture<'_, Self::Listener> {
        Box::pin(async move { socket.listen(1).map_err(map_probe_io_error) })
    }

    fn close(&self, listener: Self::Listener) -> ControllerProbeFuture<'_, ()> {
        Box::pin(async move {
            drop(listener);
            Ok(())
        })
    }
}

/// Runs a bounded, non-RF passive compatibility probe for one candidate.
pub async fn probe_controller<B: ControllerProbeBackend>(
    backend: &B,
    candidate: &ControllerCandidate,
    fingerprint: &ControllerFingerprint,
    policy: &ControllerAdmissionPolicy,
    cancellation: &LifecycleCancellation,
    limits: ControllerProbeLimits,
) -> ProbeDisposition {
    if cancellation.is_cancelled() {
        return ControllerProbeError::Cancelled.disposition();
    }
    let Some(snapshot) = candidate.snapshot() else {
        return ControllerProbeError::Removed.disposition();
    };
    let admission = policy.admit(fingerprint);
    if admission.disposition() != ProbeDisposition::Compatible {
        return admission.disposition();
    }

    tokio::select! {
        biased;
        () = cancellation.cancelled() => ControllerProbeError::Cancelled.disposition(),
        result = timeout(limits.sweep, timeout(limits.candidate, probe_candidate(backend, candidate, snapshot, cancellation, limits.operation))) => {
            match result {
                Err(_) | Ok(Err(_)) => ControllerProbeError::DeadlineExceeded.disposition(),
                Ok(Ok(result)) => result.unwrap_or_else(ControllerProbeError::disposition),
            }
        }
    }
}

async fn probe_candidate<B: ControllerProbeBackend>(
    backend: &B,
    candidate: &ControllerCandidate,
    snapshot: ControllerSnapshot,
    cancellation: &LifecycleCancellation,
    operation_limit: Duration,
) -> Result<ProbeDisposition, ControllerProbeError> {
    let session = probe_operation(cancellation, operation_limit, backend.open_session()).await?;
    if !probe_operation(
        cancellation,
        operation_limit,
        backend.powered(&session, candidate),
    )
    .await?
    {
        return Err(ControllerProbeError::ControllerUnpowered);
    }
    let address = probe_operation(
        cancellation,
        operation_limit,
        backend.address(&session, candidate),
    )
    .await?;
    let address_type = probe_operation(
        cancellation,
        operation_limit,
        backend.address_type(&session, candidate),
    )
    .await?;
    if address == Address::any() {
        return Err(ControllerProbeError::UnknownPlatformError);
    }
    if address != snapshot.address() || address_type != snapshot.address_type() {
        return Err(ControllerProbeError::Removed);
    }
    if !matches!(address_type, AddressType::LePublic | AddressType::LeRandom) {
        return Err(ControllerProbeError::UnsupportedAddressFamily);
    }
    let socket = probe_operation(cancellation, operation_limit, backend.create_socket()).await?;
    probe_operation(
        cancellation,
        operation_limit,
        backend.bind(&socket, SocketAddr::new(address, address_type, 0)),
    )
    .await?;
    let psm = probe_operation(cancellation, operation_limit, backend.local_psm(&socket)).await?;
    validate_dynamic_le_psm(psm).map_err(|()| ControllerProbeError::UnsupportedLeCoc)?;
    let listener = probe_operation(cancellation, operation_limit, backend.listen(socket)).await?;
    probe_operation(cancellation, operation_limit, backend.close(listener)).await?;
    Ok(ProbeDisposition::Compatible)
}

async fn probe_operation<T>(
    cancellation: &LifecycleCancellation,
    operation_limit: Duration,
    operation: ControllerProbeFuture<'_, T>,
) -> Result<T, ControllerProbeError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(ControllerProbeError::Cancelled),
        result = timeout(operation_limit, operation) => result.unwrap_or(Err(ControllerProbeError::DeadlineExceeded)),
    }
}
