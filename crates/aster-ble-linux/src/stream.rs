use crate::{BoxedStream, DriverError, configuration};
use bluer::l2cap::Stream;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
pub(crate) struct MtuProbe(Arc<MtuState>);

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

    pub(crate) fn observation(&self) -> Option<NegotiatedMtu> {
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
    pub(crate) stream: BoxedStream,
    pub(crate) mtu: MtuProbe,
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

    pub(crate) fn from_bluez(stream: Stream) -> Self {
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

pub(crate) struct MtuBoundedStream {
    pub(crate) stream: BoxedStream,
    pub(crate) mtu: MtuProbe,
    pub(crate) maximum_write_bytes: usize,
    pub(crate) largest_successful_write_bytes: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
}
