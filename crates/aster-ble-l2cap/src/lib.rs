//! Bounded adapter-neutral ordered contact over an LE L2CAP byte stream.

#![forbid(unsafe_code)]

use aster_contact::{
    CarrierPeerEvidence, ContactError, ContactErrorKind, ContactFuture, ContactRequestHandler,
    OrderedContact, TransientLocator,
};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, Notify},
    time::timeout,
};

const TAG_REQUEST: u8 = 1;
const TAG_RESPONSE_MORE: u8 = 2;
const TAG_RESPONSE_COMPLETE: u8 = 3;
const TAG_FINISH: u8 = 4;
const TAG_FINISH_ACK: u8 = 5;
const TAG_REJECT_BOUNDS: u8 = 6;
const TAG_REJECT_PROTOCOL: u8 = 7;
const HEADER_BYTES: usize = 5;

trait AsyncContactIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncContactIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// One bounded ordered contact carried by an LE L2CAP byte stream.
pub struct BleL2capContact {
    io: Mutex<Box<dyn AsyncContactIo>>,
    locator: TransientLocator,
    maximum_frame_bytes: usize,
    operation_timeout: Duration,
    operation_active: AtomicBool,
    closed: AtomicBool,
    close_notify: Notify,
}

impl std::fmt::Debug for BleL2capContact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BleL2capContact")
            .field("maximum_frame_bytes", &self.maximum_frame_bytes)
            .field("operation_timeout", &self.operation_timeout)
            .field("locator", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl BleL2capContact {
    /// Wraps one already-connected ordered platform stream.
    pub fn new<T>(
        io: T,
        locator: TransientLocator,
        maximum_frame_bytes: usize,
        operation_timeout: Duration,
    ) -> Result<Self, ContactError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if maximum_frame_bytes == 0 || maximum_frame_bytes > u32::MAX as usize {
            return Err(ContactError::new(
                ContactErrorKind::Configuration,
                "LE L2CAP contact frame bound is invalid",
            ));
        }
        if operation_timeout.is_zero() {
            return Err(ContactError::new(
                ContactErrorKind::Configuration,
                "LE L2CAP contact timeout is zero",
            ));
        }
        Ok(Self {
            io: Mutex::new(Box::new(io)),
            locator,
            maximum_frame_bytes,
            operation_timeout,
            operation_active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        })
    }

    fn ensure_open(&self) -> Result<(), ContactError> {
        if self.closed.load(Ordering::Acquire) {
            Err(ContactError::new(
                ContactErrorKind::Unavailable,
                "LE L2CAP contact is closed",
            ))
        } else {
            Ok(())
        }
    }

    async fn run_operation<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, ContactError>>,
    ) -> Result<T, ContactError> {
        if self
            .operation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ContactError::new(
                ContactErrorKind::Unavailable,
                "LE L2CAP contact already has an active operation",
            ));
        }
        let _active = ActiveOperation(&self.operation_active);
        self.ensure_open()?;
        let result = tokio::select! {
            biased;
            _ = self.close_notify.notified() => Err(ContactError::new(
                ContactErrorKind::Unavailable,
                "LE L2CAP contact closed during operation",
            )),
            result = timeout(self.operation_timeout, operation) => match result {
                Ok(result) => result,
                Err(_) => Err(ContactError::new(
                    ContactErrorKind::Timeout,
                    "LE L2CAP contact operation timed out",
                )),
            }
        };
        if result.is_err() {
            // A failed or cancelled byte-stream operation leaves turn position
            // uncertain, so this contact cannot be safely reused.
            self.close();
        }
        result
    }

    async fn write_record(
        io: &mut dyn AsyncContactIo,
        tag: u8,
        payload: &[u8],
        maximum: usize,
    ) -> Result<(), ContactError> {
        if payload.len() > maximum {
            return Err(ContactError::new(
                ContactErrorKind::Bounds,
                "LE L2CAP contact frame exceeds its bound",
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            ContactError::new(ContactErrorKind::Bounds, "LE L2CAP frame length overflow")
        })?;
        let mut header = [0u8; HEADER_BYTES];
        header[0] = tag;
        header[1..].copy_from_slice(&length.to_be_bytes());
        io.write_all(&header).await.map_err(io_error)?;
        io.write_all(payload).await.map_err(io_error)?;
        io.flush().await.map_err(io_error)
    }

    async fn read_record(
        io: &mut dyn AsyncContactIo,
        maximum: usize,
    ) -> Result<(u8, Vec<u8>), ContactError> {
        let mut header = [0u8; HEADER_BYTES];
        io.read_exact(&mut header).await.map_err(io_error)?;
        let (tag, length) = decode_record_header(header, maximum)?;
        let mut payload = vec![0u8; length];
        io.read_exact(&mut payload).await.map_err(io_error)?;
        Ok((tag, payload))
    }
}

fn decode_record_header(
    header: [u8; HEADER_BYTES],
    maximum: usize,
) -> Result<(u8, usize), ContactError> {
    let length = u32::from_be_bytes(header[1..].try_into().expect("four-byte length"));
    let length = usize::try_from(length).map_err(|_| {
        ContactError::new(ContactErrorKind::Bounds, "LE L2CAP frame length overflow")
    })?;
    if length > maximum {
        return Err(ContactError::new(
            ContactErrorKind::Bounds,
            "LE L2CAP peer frame exceeds its bound",
        ));
    }
    Ok((header[0], length))
}

/// Exercises the production carrier-local record header and body bounds.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_inspect_record(input: &[u8], maximum: usize) -> bool {
    let Some(header) = input.get(..HEADER_BYTES) else {
        return false;
    };
    let header = <[u8; HEADER_BYTES]>::try_from(header).expect("header has exact width");
    let Ok((_, length)) = decode_record_header(header, maximum) else {
        return false;
    };
    let Some(end) = HEADER_BYTES.checked_add(length) else {
        return false;
    };
    input.get(HEADER_BYTES..end).is_some()
}

struct ActiveOperation<'a>(&'a AtomicBool);

impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn io_error(error: io::Error) -> ContactError {
    let kind = match error.kind() {
        io::ErrorKind::TimedOut => ContactErrorKind::Timeout,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => ContactErrorKind::Unavailable,
        _ => ContactErrorKind::Transport,
    };
    ContactError::new(kind, error.to_string())
}

impl OrderedContact for BleL2capContact {
    fn peer_evidence(&self) -> CarrierPeerEvidence {
        CarrierPeerEvidence::UnauthenticatedLocator {
            transient_locator: self.locator.clone(),
        }
    }

    fn max_frame_bytes(&self) -> usize {
        self.maximum_frame_bytes
    }

    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if request.len() > self.maximum_frame_bytes || request.len() > total_limit {
                return Err(ContactError::new(
                    ContactErrorKind::Bounds,
                    "LE L2CAP request exceeds its exchange bound",
                ));
            }
            self.run_operation(async {
                let mut io = self.io.lock().await;
                Self::write_record(&mut **io, TAG_REQUEST, request, self.maximum_frame_bytes)
                    .await?;
                let response_maximum = self
                    .maximum_frame_bytes
                    .min(total_limit.saturating_sub(request.len()));
                let (tag, response) = Self::read_record(&mut **io, response_maximum).await?;
                match tag {
                    TAG_RESPONSE_MORE | TAG_RESPONSE_COMPLETE => Ok(response),
                    TAG_REJECT_BOUNDS => Err(ContactError::new(
                        ContactErrorKind::Bounds,
                        "LE L2CAP peer rejected exchange bounds",
                    )),
                    TAG_REJECT_PROTOCOL => Err(ContactError::new(
                        ContactErrorKind::Protocol,
                        "LE L2CAP peer rejected contact exchange",
                    )),
                    _ => Err(ContactError::new(
                        ContactErrorKind::Protocol,
                        "LE L2CAP response has an invalid turn marker",
                    )),
                }
            })
            .await
        })
    }

    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool> {
        Box::pin(async move {
            self.run_operation(async {
                let mut io = self.io.lock().await;
                let request_maximum = self.maximum_frame_bytes.min(total_limit);
                let (tag, request) = Self::read_record(&mut **io, request_maximum).await?;
                if tag != TAG_REQUEST {
                    return Err(ContactError::new(
                        ContactErrorKind::Protocol,
                        "LE L2CAP request has an invalid turn marker",
                    ));
                }
                let (response, complete) = match handler(&request) {
                    Ok(response) => response,
                    Err(error) => {
                        let _ = Self::write_record(
                            &mut **io,
                            TAG_REJECT_PROTOCOL,
                            &[],
                            self.maximum_frame_bytes,
                        )
                        .await;
                        return Err(error);
                    }
                };
                let response_maximum = self
                    .maximum_frame_bytes
                    .min(total_limit.saturating_sub(request.len()));
                if response.len() > response_maximum {
                    Self::write_record(&mut **io, TAG_REJECT_BOUNDS, &[], self.maximum_frame_bytes)
                        .await?;
                    return Err(ContactError::new(
                        ContactErrorKind::Bounds,
                        "LE L2CAP response exceeds its exchange bound",
                    ));
                }
                let tag = if complete {
                    TAG_RESPONSE_COMPLETE
                } else {
                    TAG_RESPONSE_MORE
                };
                Self::write_record(&mut **io, tag, &response, response_maximum).await?;
                Ok(complete)
            })
            .await
        })
    }

    fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
        Box::pin(async move {
            let result = self
                .run_operation(async {
                    let mut io = self.io.lock().await;
                    Self::write_record(&mut **io, TAG_FINISH, &[], self.maximum_frame_bytes)
                        .await?;
                    let (tag, payload) = Self::read_record(&mut **io, 0).await?;
                    if tag != TAG_FINISH_ACK || !payload.is_empty() {
                        return Err(ContactError::new(
                            ContactErrorKind::Protocol,
                            "LE L2CAP finish acknowledgement is invalid",
                        ));
                    }
                    io.shutdown().await.map_err(io_error)
                })
                .await;
            if result.is_ok() {
                self.close();
            }
            result
        })
    }

    fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
        Box::pin(async move {
            let result = self
                .run_operation(async {
                    let mut io = self.io.lock().await;
                    let (tag, payload) = Self::read_record(&mut **io, 0).await?;
                    if tag != TAG_FINISH || !payload.is_empty() {
                        return Err(ContactError::new(
                            ContactErrorKind::Protocol,
                            "LE L2CAP finish request is invalid",
                        ));
                    }
                    Self::write_record(&mut **io, TAG_FINISH_ACK, &[], self.maximum_frame_bytes)
                        .await?;
                    io.shutdown().await.map_err(io_error)
                })
                .await;
            if result.is_ok() {
                self.close();
            }
            result
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.close_notify.notify_waiters();
        // There is at most one active operation. Retaining one permit closes the
        // race where close happens after the open check but before select polls.
        self.close_notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_contact::{
        CarrierPeerEvidence, ChannelBindingCapability, ContactErrorKind, OrderedContact,
        TransientLocator,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    fn contact(
        stream: DuplexStream,
        maximum: usize,
        operation_timeout: Duration,
    ) -> Arc<BleL2capContact> {
        Arc::new(
            BleL2capContact::new(
                stream,
                TransientLocator::new(b"peer".to_vec()).unwrap(),
                maximum,
                operation_timeout,
            )
            .unwrap(),
        )
    }

    async fn write_raw(stream: &mut DuplexStream, tag: u8, declared: u32, body: &[u8]) {
        stream.write_all(&[tag]).await.unwrap();
        stream.write_all(&declared.to_be_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    }

    fn pair(maximum: usize) -> (Arc<BleL2capContact>, Arc<BleL2capContact>) {
        let (left, right) = duplex(37);
        let left = BleL2capContact::new(
            left,
            TransientLocator::new(b"left".to_vec()).unwrap(),
            maximum,
            Duration::from_secs(1),
        )
        .unwrap();
        let right = BleL2capContact::new(
            right,
            TransientLocator::new(b"right".to_vec()).unwrap(),
            maximum,
            Duration::from_secs(1),
        )
        .unwrap();
        (Arc::new(left), Arc::new(right))
    }

    #[tokio::test]
    async fn ordered_contact_spans_platform_writes_and_finishes() {
        let (initiator, responder) = pair(4096);
        let expected = vec![0x5a; 1024];
        let responder_task = tokio::spawn({
            let responder = Arc::clone(&responder);
            let expected = expected.clone();
            async move {
                let complete = responder
                    .respond_once_with_total_limit(
                        2048,
                        Box::new(move |request| {
                            assert_eq!(request, expected);
                            Ok((b"accepted".to_vec(), true))
                        }),
                    )
                    .await
                    .unwrap();
                assert!(complete);
                responder.finish_as_responder().await.unwrap();
            }
        });
        let response = initiator
            .request_with_total_limit(&expected, 2048)
            .await
            .unwrap();
        assert_eq!(response, b"accepted");
        initiator.finish_as_initiator().await.unwrap();
        responder_task.await.unwrap();
    }

    #[tokio::test]
    async fn aggregate_limit_fails_without_response_delivery() {
        let (initiator, responder) = pair(64);
        let task = tokio::spawn(async move {
            responder
                .respond_once_with_total_limit(7, Box::new(|_| Ok((b"five!".to_vec(), false))))
                .await
                .unwrap_err()
        });
        let error = initiator
            .request_with_total_limit(b"four", 7)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Bounds);
        assert_eq!(task.await.unwrap().kind(), ContactErrorKind::Bounds);
    }

    #[tokio::test]
    async fn truncated_header_and_body_fail_as_transport_errors() {
        for bytes in [vec![TAG_REQUEST, 0, 0], vec![TAG_REQUEST, 0, 0, 0, 4, 1, 2]] {
            let (stream, mut peer) = duplex(32);
            let contact = contact(stream, 64, Duration::from_secs(1));
            peer.write_all(&bytes).await.unwrap();
            peer.shutdown().await.unwrap();
            let error = contact
                .respond_once_with_total_limit(64, Box::new(|_| Ok((Vec::new(), true))))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ContactErrorKind::Transport);
        }
    }

    #[tokio::test]
    async fn oversized_peer_frame_is_rejected_from_its_header() {
        let (stream, mut peer) = duplex(32);
        let contact = contact(stream, 8, Duration::from_secs(1));
        write_raw(&mut peer, TAG_REQUEST, 9, &[]).await;
        let error = contact
            .respond_once_with_total_limit(8, Box::new(|_| panic!("handler must not run")))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Bounds);
        assert_eq!(
            contact
                .respond_once_with_total_limit(8, Box::new(|_| Ok((Vec::new(), true))))
                .await
                .unwrap_err()
                .kind(),
            ContactErrorKind::Unavailable
        );
    }

    #[tokio::test]
    async fn wrong_turn_marker_is_rejected() {
        let (stream, mut peer) = duplex(32);
        let contact = contact(stream, 64, Duration::from_secs(1));
        let peer_task = tokio::spawn(async move {
            let mut header = [0u8; HEADER_BYTES];
            peer.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            let mut body = vec![0; length];
            peer.read_exact(&mut body).await.unwrap();
            write_raw(&mut peer, TAG_FINISH, 0, &[]).await;
        });
        let error = contact
            .request_with_total_limit(b"request", 64)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Protocol);
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn stalled_operation_times_out() {
        let (stream, _peer) = duplex(32);
        let contact = contact(stream, 64, Duration::from_millis(10));
        let error = contact
            .respond_once_with_total_limit(64, Box::new(|_| Ok((Vec::new(), true))))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Timeout);
    }

    #[tokio::test]
    async fn peer_close_fails_the_operation() {
        let (stream, peer) = duplex(32);
        let contact = contact(stream, 64, Duration::from_secs(1));
        drop(peer);
        let error = contact
            .request_with_total_limit(b"request", 64)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Transport);
    }

    #[tokio::test]
    async fn local_close_cancels_the_active_operation_and_rejects_later_work() {
        let (stream, _peer) = duplex(32);
        let contact = contact(stream, 64, Duration::from_secs(10));
        let operation = tokio::spawn({
            let contact = Arc::clone(&contact);
            async move {
                contact
                    .respond_once_with_total_limit(64, Box::new(|_| Ok((Vec::new(), true))))
                    .await
            }
        });
        tokio::task::yield_now().await;
        contact.close();
        assert_eq!(
            operation.await.unwrap().unwrap_err().kind(),
            ContactErrorKind::Unavailable
        );
        assert_eq!(
            contact
                .request_with_total_limit(b"later", 64)
                .await
                .unwrap_err()
                .kind(),
            ContactErrorKind::Unavailable
        );
    }

    #[tokio::test]
    async fn concurrent_operation_is_not_queued() {
        let (stream, _peer) = duplex(32);
        let contact = contact(stream, 64, Duration::from_secs(10));
        let first = tokio::spawn({
            let contact = Arc::clone(&contact);
            async move {
                contact
                    .respond_once_with_total_limit(64, Box::new(|_| Ok((Vec::new(), true))))
                    .await
            }
        });
        tokio::task::yield_now().await;
        let error = contact
            .request_with_total_limit(b"overlap", 64)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Unavailable);
        contact.close();
        let _ = first.await.unwrap();
    }

    #[tokio::test]
    async fn handler_rejection_is_exact_locally_and_protocol_remote() {
        let (initiator, responder) = pair(64);
        let responder_task = tokio::spawn(async move {
            responder
                .respond_once_with_total_limit(
                    64,
                    Box::new(|_| {
                        Err(ContactError::new(
                            ContactErrorKind::Unauthorized,
                            "mission identity rejected",
                        ))
                    }),
                )
                .await
                .unwrap_err()
        });
        let remote = initiator
            .request_with_total_limit(b"request", 64)
            .await
            .unwrap_err();
        assert_eq!(remote.kind(), ContactErrorKind::Protocol);
        let local = responder_task.await.unwrap();
        assert_eq!(local.kind(), ContactErrorKind::Unauthorized);
        assert_eq!(local.detail(), "mission identity rejected");
    }

    #[test]
    fn locator_evidence_never_becomes_authenticated_carrier_evidence() {
        let (left, _) = duplex(8);
        let contact = BleL2capContact::new(
            left,
            TransientLocator::new(b"public:01:02:03:04:05:06/psm:128".to_vec()).unwrap(),
            1024,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            contact.peer_evidence(),
            CarrierPeerEvidence::UnauthenticatedLocator { .. }
        ));
        assert_eq!(contact.peer_evidence().stable_carrier_id(), None);
        assert_eq!(
            contact.peer_evidence().channel_binding_capability(),
            ChannelBindingCapability::Unavailable
        );
    }

    #[test]
    fn zero_frame_bound_is_rejected() {
        let (left, _) = duplex(8);
        let error = BleL2capContact::new(
            left,
            TransientLocator::new(b"peer".to_vec()).unwrap(),
            0,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Configuration);
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let (left, _) = duplex(8);
        let error = BleL2capContact::new(
            left,
            TransientLocator::new(b"peer".to_vec()).unwrap(),
            64,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ContactErrorKind::Configuration);
    }
}
