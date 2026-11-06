//! Adapter-neutral ordered carrier contact contract for Aster.

#![forbid(unsafe_code)]

use std::{error::Error, fmt, future::Future, pin::Pin};

/// Fixed byte width of a stable authenticated carrier identity.
pub const STABLE_CARRIER_ID_BYTES: usize = 32;

/// Maximum carrier-local bytes retained for an unauthenticated locator.
pub const MAX_TRANSIENT_LOCATOR_BYTES: usize = 256;

/// Maximum diagnostic bytes retained in one contact error.
pub const MAX_CONTACT_ERROR_DETAIL_BYTES: usize = 256;

/// Stable identity authenticated independently by a carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StableCarrierId([u8; STABLE_CARRIER_ID_BYTES]);

impl StableCarrierId {
    /// Wraps one exact fixed-width carrier identity.
    pub const fn new(bytes: [u8; STABLE_CARRIER_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact identity bytes.
    pub const fn as_bytes(&self) -> &[u8; STABLE_CARRIER_ID_BYTES] {
        &self.0
    }
}

/// Bounded carrier-local locator that grants no authenticated identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientLocator(Vec<u8>);

impl TransientLocator {
    /// Validates and retains a nonempty bounded locator.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ContactError> {
        if bytes.is_empty() {
            return Err(ContactError::new(
                ContactErrorKind::Configuration,
                "transient carrier locator is empty",
            ));
        }
        if bytes.len() > MAX_TRANSIENT_LOCATOR_BYTES {
            return Err(ContactError::new(
                ContactErrorKind::Bounds,
                "transient carrier locator exceeds its byte bound",
            ));
        }
        Ok(Self(bytes))
    }

    /// Borrows the opaque carrier-local locator bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Whether a contact can derive a session channel binding for caller context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelBindingCapability {
    /// The carrier cannot supply an independently authenticated binding.
    Unavailable,
    /// The carrier can derive a binding for bounded caller-owned context.
    Derivable,
}

/// Typed carrier evidence observed before the Aster mission handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CarrierPeerEvidence {
    /// The carrier independently authenticated a stable peer identity.
    AuthenticatedCarrier {
        /// Exact carrier-authenticated stable identity.
        stable_carrier_id: StableCarrierId,
        /// Channel-binding capability of this exact contact.
        channel_binding: ChannelBindingCapability,
    },
    /// The carrier supplied only a transient locator with no identity authority.
    UnauthenticatedLocator {
        /// Opaque carrier-local locator.
        transient_locator: TransientLocator,
    },
}

impl CarrierPeerEvidence {
    /// Returns a stable carrier identity only when the carrier authenticated it.
    pub const fn stable_carrier_id(&self) -> Option<StableCarrierId> {
        match self {
            Self::AuthenticatedCarrier {
                stable_carrier_id, ..
            } => Some(*stable_carrier_id),
            Self::UnauthenticatedLocator { .. } => None,
        }
    }

    /// Returns the channel-binding capability without promoting a locator.
    pub const fn channel_binding_capability(&self) -> ChannelBindingCapability {
        match self {
            Self::AuthenticatedCarrier {
                channel_binding, ..
            } => *channel_binding,
            Self::UnauthenticatedLocator { .. } => ChannelBindingCapability::Unavailable,
        }
    }
}

/// Closed adapter-neutral category for one contact operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactErrorKind {
    /// Invalid local configuration or caller input.
    Configuration,
    /// The adapter or controller is currently unavailable.
    Unavailable,
    /// The operation exceeded its deadline.
    Timeout,
    /// The carrier operation failed without a more specific safe classification.
    Transport,
    /// A caller or remote value exceeded a declared bound.
    Bounds,
    /// The carrier rejected an unauthenticated or unauthorized peer.
    Unauthorized,
    /// The peer or higher layer contradicted the contact protocol.
    Protocol,
    /// The contact does not implement the requested optional capability.
    Unsupported,
}

/// Bounded contact failure with a closed category and sanitized diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactError {
    kind: ContactErrorKind,
    detail: String,
}

impl ContactError {
    /// Creates an error while truncating diagnostics at a UTF-8 boundary.
    pub fn new(kind: ContactErrorKind, detail: impl Into<String>) -> Self {
        let mut detail: String = detail
            .into()
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        if detail.len() > MAX_CONTACT_ERROR_DETAIL_BYTES {
            let mut end = MAX_CONTACT_ERROR_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self { kind, detail }
    }

    /// Returns the closed error category.
    pub const fn kind(&self) -> ContactErrorKind {
        self.kind
    }

    /// Returns bounded diagnostic text.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ContactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "contact {:?}: {}", self.kind, self.detail)
    }
}

impl Error for ContactError {}

/// Boxed future returned by object-safe ordered-contact operations.
pub type ContactFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ContactError>> + Send + 'a>>;

/// One synchronous bounded request handler owned by a contact response.
pub type ContactRequestHandler<'a> =
    Box<dyn FnOnce(&[u8]) -> Result<(Vec<u8>, bool), ContactError> + Send + 'a>;

/// Synchronous authorization recheck executed adjacent to the first write.
pub type ContactPreflight<'a> = Box<dyn FnOnce() -> Result<(), ContactError> + Send + 'a>;

/// Adapter-neutral bounded ordered request/response contact.
///
/// A caller must serialize exchange and finish operations for one contact.
/// Implementations may reject or close a contact when those operations overlap.
pub trait OrderedContact: Send + Sync {
    /// Returns typed evidence for the remote carrier peer.
    fn peer_evidence(&self) -> CarrierPeerEvidence;

    /// Returns the maximum protected frame accepted by this contact.
    fn max_frame_bytes(&self) -> usize;

    /// Sends one request and receives its response under an aggregate byte bound.
    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>>;

    /// Sends one bounded exchange after a carrier-adjacent authorization check.
    fn request_with_total_limit_checked<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
        before_write: ContactPreflight<'a>,
    ) -> ContactFuture<'a, Vec<u8>>;

    /// Receives one request and sends the synchronous handler's bounded response.
    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool>;

    /// Proves final-response consumption and waits for orderly responder close.
    fn finish_as_initiator(&self) -> ContactFuture<'_, ()>;

    /// Waits for final-response consumption and closes the contact orderly.
    fn finish_as_responder(&self) -> ContactFuture<'_, ()>;

    /// Closes the transient contact synchronously.
    fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_locator_rejects_empty_and_oversized_values() {
        let empty = TransientLocator::new(Vec::new()).unwrap_err();
        assert_eq!(empty.kind(), ContactErrorKind::Configuration);

        let oversized =
            TransientLocator::new(vec![7; MAX_TRANSIENT_LOCATOR_BYTES + 1]).unwrap_err();
        assert_eq!(oversized.kind(), ContactErrorKind::Bounds);
    }

    #[test]
    fn unauthenticated_locator_exposes_no_stable_identity_or_channel_binding() {
        let locator = TransientLocator::new(vec![0x01, 0x02, 0x03]).unwrap();
        let evidence = CarrierPeerEvidence::UnauthenticatedLocator {
            transient_locator: locator,
        };

        assert_eq!(evidence.stable_carrier_id(), None);
        assert_eq!(
            evidence.channel_binding_capability(),
            ChannelBindingCapability::Unavailable
        );
    }

    #[test]
    fn authenticated_evidence_exposes_exact_stable_identity_and_binding_capability() {
        let stable_carrier_id = StableCarrierId::new([0x5a; 32]);
        let evidence = CarrierPeerEvidence::AuthenticatedCarrier {
            stable_carrier_id,
            channel_binding: ChannelBindingCapability::Derivable,
        };

        assert_eq!(evidence.stable_carrier_id(), Some(stable_carrier_id));
        assert_eq!(stable_carrier_id.as_bytes(), &[0x5a; 32]);
        assert_eq!(
            evidence.channel_binding_capability(),
            ChannelBindingCapability::Derivable
        );
    }

    #[test]
    fn contact_error_detail_is_bounded_at_a_utf8_boundary() {
        let error = ContactError::new(
            ContactErrorKind::Protocol,
            "é".repeat(MAX_CONTACT_ERROR_DETAIL_BYTES),
        );

        assert!(error.detail().len() <= MAX_CONTACT_ERROR_DETAIL_BYTES);
        assert!(error.detail().is_char_boundary(error.detail().len()));
    }

    #[test]
    fn contact_error_detail_contains_no_control_characters() {
        let error = ContactError::new(
            ContactErrorKind::Transport,
            "remote\nvalue\twith\u{7f}controls",
        );

        assert!(!error.detail().chars().any(char::is_control));
    }

    #[test]
    fn ordered_contact_remains_object_safe() {
        fn accepts_trait_object(_contact: &dyn OrderedContact) {}

        let assertion: fn(&dyn OrderedContact) = accepts_trait_object;
        let _ = assertion;
    }
}
