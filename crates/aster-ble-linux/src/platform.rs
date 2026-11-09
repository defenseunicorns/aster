pub(crate) mod discovery;
pub(crate) mod socket;

use crate::{DriverError, DriverErrorKind};
use bluer::{ErrorKind, InternalErrorKind};
use std::io;

pub use socket::{
    BluezSocketFactory, OpenFuture, OpenedContact, SocketFactory, open_contact,
    open_contact_with_factory,
};

pub(crate) fn map_bluer_error(error: bluer::Error) -> DriverError {
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

pub(crate) fn map_io_error(error: io::Error) -> DriverError {
    let kind = classify_io_error(error.kind());
    DriverError::new(kind, "kernel L2CAP operation failed")
}

pub(crate) const fn classify_io_error(kind: io::ErrorKind) -> DriverErrorKind {
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
