//! Plaintext, loopback-only health listener.

use std::{
    error::Error,
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{CONTENT_LENGTH, TRANSFER_ENCODING},
};
use http_body_util::Full;
use hyper::{
    body::{Body as _, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot, watch},
    task::JoinSet,
};

use crate::lifecycle::{HealthDecision, HealthEndpoint, LifecycleState, ServiceStatus};

const HEALTH_HEADER_BYTES: usize = 4 * 1024;
const HEALTH_TRANSPORT_BUFFER_BYTES: usize = 8 * 1024;
const HEALTH_HEADER_DEADLINE: Duration = Duration::from_secs(2);
const HEALTH_CONNECTION_LIMIT: usize = 16;

/// A sanitized health-listener error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthError {
    /// The loopback listener could not be bound or inspected.
    Listener,
    /// A connection could not be served.
    Serving,
}

impl fmt::Display for HealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listener => formatter.write_str("health listener is unavailable"),
            Self::Serving => formatter.write_str("health listener stopped unexpectedly"),
        }
    }
}

impl Error for HealthError {}

#[derive(Debug)]
struct HealthRequestClosed;

impl fmt::Display for HealthRequestClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("health connection closed")
    }
}

impl Error for HealthRequestClosed {}

/// A loopback health listener that has not begun serving.
pub struct BoundHealth {
    listener: TcpListener,
}

impl BoundHealth {
    /// Binds the separate plaintext listener only to a validated loopback address.
    pub async fn bind(address: SocketAddr) -> Result<Self, HealthError> {
        if !address.ip().is_loopback() {
            return Err(HealthError::Listener);
        }
        TcpListener::bind(address)
            .await
            .map(|listener| Self { listener })
            .map_err(|_| HealthError::Listener)
    }

    /// Returns the exact address selected by the operating system.
    pub fn local_addr(&self) -> Result<SocketAddr, HealthError> {
        self.listener
            .local_addr()
            .map_err(|_| HealthError::Listener)
    }

    /// Serves status-only health responses until the supplied shutdown signal.
    pub async fn serve(
        self,
        status: ServiceStatus,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), HealthError> {
        let permits = Arc::new(Semaphore::new(HEALTH_CONNECTION_LIMIT));
        let mut lifecycle = status.subscribe();
        let mut tasks = JoinSet::new();
        let result = loop {
            if status.state() == LifecycleState::Stopped {
                break Ok(());
            }
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break Ok(());
                    }
                }
                changed = lifecycle.changed() => {
                    if changed.is_err() || *lifecycle.borrow() == LifecycleState::Stopped {
                        break Ok(());
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => break Err(HealthError::Serving),
                    };
                    if status.state() == LifecycleState::Stopped {
                        break Ok(());
                    }
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        continue;
                    };
                    let status = status.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let (first_header_send, first_header_receive) = oneshot::channel();
                        let first_header_send = Arc::new(Mutex::new(Some(first_header_send)));
                        let service = service_fn(move |request| {
                            let status = status.clone();
                            let first_header_send = first_header_send.clone();
                            async move {
                                if let Some(send) = first_header_send
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .take()
                                {
                                    let _ = send.send(());
                                }
                                respond(&status, request).ok_or(HealthRequestClosed)
                            }
                        });
                        let mut builder = auto::Builder::new(TokioExecutor::new());
                        builder
                            .http1()
                            .timer(TokioTimer::new())
                            .max_buf_size(HEALTH_TRANSPORT_BUFFER_BYTES)
                            .header_read_timeout(HEALTH_HEADER_DEADLINE);
                        builder
                            .http2()
                            .max_header_list_size(HEALTH_HEADER_BYTES as u32);
                        let connection = builder.serve_connection(TokioIo::new(stream), service);
                        tokio::pin!(connection);
                        let first_header =
                            tokio::time::timeout(HEALTH_HEADER_DEADLINE, first_header_receive);
                        tokio::pin!(first_header);
                        tokio::select! {
                            _ = &mut connection => {}
                            first = &mut first_header => {
                                if first.is_ok() {
                                    let _ = connection.await;
                                }
                            }
                        }
                    });
                }
                Some(_) = tasks.join_next() => {}
            }
        };
        tasks.shutdown().await;
        result
    }
}

fn respond(status: &ServiceStatus, request: Request<Incoming>) -> Option<Response<Full<Bytes>>> {
    if !headers_fit(&request) {
        return Some(empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));
    }
    if request.method() != Method::GET {
        return Some(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    if !body_is_empty(&request) {
        return Some(empty(StatusCode::BAD_REQUEST));
    }
    let endpoint = match request.uri().path() {
        "/livez" => HealthEndpoint::Live,
        "/readyz" => HealthEndpoint::Ready,
        _ => return Some(empty(StatusCode::NOT_FOUND)),
    };
    match status.health(endpoint) {
        HealthDecision::Healthy => Some(empty(StatusCode::OK)),
        HealthDecision::Unhealthy => Some(empty(StatusCode::SERVICE_UNAVAILABLE)),
        HealthDecision::Absent => None,
    }
}

fn headers_fit(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())
                .and_then(|total| total.checked_add(2))
                .and_then(|total| total.checked_add(value.as_bytes().len()))
                .and_then(|total| total.checked_add(2))
        })
        .is_some_and(|total| total <= HEALTH_HEADER_BYTES)
}

fn body_is_empty(request: &Request<Incoming>) -> bool {
    let content_length_is_empty = request
        .headers()
        .get(CONTENT_LENGTH)
        .map(|value| value.as_bytes() == b"0")
        .unwrap_or(true);
    content_length_is_empty
        && !request.headers().contains_key(TRANSFER_ENCODING)
        && request.body().is_end_stream()
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    response
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::watch,
    };

    use super::*;

    async fn health(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to health listener");
        stream
            .write_all(request)
            .await
            .expect("write health request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut chunk = [0_u8; 512];
                let read = stream.read(&mut chunk).await.expect("read health response");
                assert!(read != 0, "health listener closed without a response");
                response.extend_from_slice(&chunk[..read]);
                assert!(
                    response.len() <= 2 * 1024,
                    "health response exceeds test bound"
                );
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    return;
                }
            }
        })
        .await
        .expect("health response header deadline");
        response
    }

    fn assert_empty(response: &[u8], expected_status: u16) {
        let response = std::str::from_utf8(response).expect("ASCII HTTP response");
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}")),
            "unexpected response: {response:?}"
        );
        assert!(
            response.ends_with("\r\n\r\n"),
            "response has no body: {response:?}"
        );
        assert!(!response.contains("failure"));
        assert!(!response.contains("node"));
        assert!(!response.contains("mission"));
        assert!(!response.contains("peer"));
        assert!(!response.contains("carrier"));
        assert!(!response.contains("queue"));
    }

    #[tokio::test]
    async fn health_reveals_only_status_and_rejects_body_method_and_path() {
        let status = ServiceStatus::starting();
        let listener = BoundHealth::bind("127.0.0.1:0".parse().expect("loopback address"))
            .await
            .expect("bind loopback health listener");
        let address = listener.local_addr().expect("health address");
        let (stop_send, stop_receive) = watch::channel(false);
        let task = tokio::spawn(listener.serve(status, stop_receive));

        assert_empty(
            &health(address, b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n").await,
            200,
        );
        assert_empty(
            &health(address, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n").await,
            404,
        );
        assert_empty(
            &health(address, b"POST /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n").await,
            405,
        );
        assert_empty(
            &health(
                address,
                b"GET /livez HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx",
            )
            .await,
            400,
        );
        let mut oversized = b"GET /livez HTTP/1.1\r\nHost: localhost\r\nX-Padding: ".to_vec();
        // Host consumes 17 bytes and X-Padding has 13 bytes of field syntax,
        // so 4,067 value bytes place parsed fields one byte over 4 KiB.
        oversized.extend(std::iter::repeat_n(b'a', 4_067));
        oversized.extend_from_slice(b"\r\n\r\n");
        assert_empty(&health(address, &oversized).await, 431);
        let mut at_limit = b"GET /livez HTTP/1.1\r\nHost: localhost\r\nX-Padding: ".to_vec();
        at_limit.extend(std::iter::repeat_n(b'a', 4_066));
        at_limit.extend_from_slice(b"\r\n\r\n");
        assert_empty(&health(address, &at_limit).await, 200);

        stop_send.send(true).expect("request health shutdown");
        task.await
            .expect("health task joins")
            .expect("health task succeeds");
    }

    #[tokio::test]
    async fn health_listener_rejects_non_loopback_before_binding() {
        assert!(
            BoundHealth::bind("0.0.0.0:0".parse().expect("address"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stopped_lifecycle_closes_listener_and_active_connections_without_a_response() {
        let status = ServiceStatus::starting();
        let listener = BoundHealth::bind("127.0.0.1:0".parse().expect("loopback address"))
            .await
            .expect("bind loopback health listener");
        let address = listener.local_addr().expect("health address");
        let (_stop_send, stop_receive) = watch::channel(false);
        let task = tokio::spawn(listener.serve(status.clone(), stop_receive));
        let mut active = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect active health request");
        active
            .write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .expect("start incomplete request");

        status.transition(LifecycleState::Ready).expect("ready");
        status
            .transition(LifecycleState::Draining)
            .expect("draining");
        status.transition(LifecycleState::Stopped).expect("stopped");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("serve stops promptly")
            .expect("serve task joins")
            .expect("serve succeeds");
        let mut response = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), active.read(&mut response))
            .await
            .expect("active connection closes")
        {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(bytes) => panic!("active connection received {bytes} response bytes"),
            Err(error) => panic!("unexpected active connection error: {error}"),
        }
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
}
