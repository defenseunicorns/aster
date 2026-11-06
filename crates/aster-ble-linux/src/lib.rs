//! Linux BlueZ LE L2CAP evaluation driver.

#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

mod config;
mod controller;
mod discovery;
mod discovery_record;
mod lifecycle;
mod peer;
mod platform;
mod policy;
mod stream;

pub use config::{
    DriverConfig, FixedRole, LinkConfig, OpenRequest, RING1_MAXIMUM_DEADLINE,
    RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES, SupervisorConfig, ValidatedConfig,
    ValidatedLinkConfig, ValidatedSupervisorConfig,
};
pub use controller::{AvailabilityReason, BtleAvailability};
pub use discovery::{
    AttemptKind, CanonicalLocator, CanonicalLocatorError, DiscoveryAdmission, DiscoveryCandidate,
    ObservationOutcome, ObservationRejection, ScanStartOutcome, ScanState, ScanStopReason,
    ScanWindowCounters,
};
pub use discovery_record::{
    ASTER_ROSTER_BEACON_V1_BYTES, ASTER_ROSTER_SERVICE_UUID, AsterRosterBeaconV1,
    DiscoveryCredential, DiscoveryCredentialError, DiscoveryGeneration, DiscoveryRecordError,
    DiscoverySecret, LeasedDiscoveryCredentialSet,
};
pub use lifecycle::{LinuxBtleEventSupervisor, SupervisorError, spawn_linux_btle_event_supervisor};
pub use platform::{
    BluezSocketFactory, OpenFuture, OpenedContact, SocketFactory, open_contact,
    open_contact_with_factory,
};
pub use stream::{NegotiatedMtu, SocketOpen};

use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Notify,
};

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

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
