//! Owned selected-contact handle with explicit Iroh-only capabilities.

use aster_contact::{
    CarrierPeerEvidence, ContactError, ContactErrorKind, ContactFuture, ContactPreflight,
    ContactRequestHandler, OrderedContact,
};
use std::{fmt, sync::Arc};

/// One owned adapter-neutral contact selected for a runtime session.
#[derive(Clone)]
#[allow(dead_code)] // Variants are consumed incrementally by the Task 4 runtime migration.
pub(crate) enum SelectedContact {
    Iroh(aster_iroh::Connection),
    Ordered(Arc<dyn OrderedContact>),
}

impl SelectedContact {
    #[allow(dead_code)] // Consumed by the Iroh compatibility entrypoint migration.
    pub(crate) const fn from_iroh(connection: aster_iroh::Connection) -> Self {
        Self::Iroh(connection)
    }

    #[allow(dead_code)] // The Linux Ring 1 driver consumes this in Task 5.
    pub(crate) fn from_ordered(contact: Arc<dyn OrderedContact>) -> Self {
        Self::Ordered(contact)
    }

    /// Exposes the exact Iroh capability only to paths that require it.
    pub(crate) const fn iroh(&self) -> Option<&aster_iroh::Connection> {
        match self {
            Self::Iroh(connection) => Some(connection),
            Self::Ordered(_) => None,
        }
    }

    pub(crate) fn require_iroh(&self) -> Result<&aster_iroh::Connection, ContactError> {
        self.iroh().ok_or_else(|| {
            ContactError::new(
                ContactErrorKind::Unsupported,
                "selected contact does not provide the Iroh-only stream capability",
            )
        })
    }
}

impl fmt::Debug for SelectedContact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedContact")
            .field(
                "kind",
                &match self {
                    Self::Iroh(_) => "iroh",
                    Self::Ordered(_) => "ordered",
                },
            )
            .field("peer", &"[REDACTED]")
            .finish()
    }
}

impl OrderedContact for SelectedContact {
    fn peer_evidence(&self) -> CarrierPeerEvidence {
        match self {
            Self::Iroh(connection) => OrderedContact::peer_evidence(connection),
            Self::Ordered(contact) => contact.peer_evidence(),
        }
    }

    fn max_frame_bytes(&self) -> usize {
        match self {
            Self::Iroh(connection) => OrderedContact::max_frame_bytes(connection),
            Self::Ordered(contact) => contact.max_frame_bytes(),
        }
    }

    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>> {
        match self {
            Self::Iroh(connection) => {
                OrderedContact::request_with_total_limit(connection, request, total_limit)
            }
            Self::Ordered(contact) => contact.request_with_total_limit(request, total_limit),
        }
    }

    fn request_with_total_limit_checked<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
        before_write: ContactPreflight<'a>,
    ) -> ContactFuture<'a, Vec<u8>> {
        match self {
            Self::Iroh(connection) => OrderedContact::request_with_total_limit_checked(
                connection,
                request,
                total_limit,
                before_write,
            ),
            Self::Ordered(contact) => {
                contact.request_with_total_limit_checked(request, total_limit, before_write)
            }
        }
    }

    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool> {
        match self {
            Self::Iroh(connection) => {
                OrderedContact::respond_once_with_total_limit(connection, total_limit, handler)
            }
            Self::Ordered(contact) => contact.respond_once_with_total_limit(total_limit, handler),
        }
    }

    fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
        match self {
            Self::Iroh(connection) => OrderedContact::finish_as_initiator(connection),
            Self::Ordered(contact) => contact.finish_as_initiator(),
        }
    }

    fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
        match self {
            Self::Iroh(connection) => OrderedContact::finish_as_responder(connection),
            Self::Ordered(contact) => contact.finish_as_responder(),
        }
    }

    fn close(&self) {
        match self {
            Self::Iroh(connection) => OrderedContact::close(connection),
            Self::Ordered(contact) => contact.close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_ble_l2cap::BleL2capContact;
    use aster_contact::{ContactErrorKind, TransientLocator};
    use std::time::Duration;
    use tokio::io::duplex;

    #[test]
    fn neutral_contact_has_no_implicit_iroh_fallback() {
        let (stream, _) = duplex(32);
        let contact = BleL2capContact::new(
            stream,
            TransientLocator::new(b"peer".to_vec()).unwrap(),
            1024,
            Duration::from_secs(1),
        )
        .unwrap();
        let selected = SelectedContact::from_ordered(Arc::new(contact));

        assert!(selected.iroh().is_none());
        let Err(error) = selected.require_iroh() else {
            panic!("neutral contact must not expose Iroh");
        };
        assert_eq!(error.kind(), ContactErrorKind::Unsupported);
        assert!(matches!(
            selected.peer_evidence(),
            CarrierPeerEvidence::UnauthenticatedLocator { .. }
        ));
    }
}
