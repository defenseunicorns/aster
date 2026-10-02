//! Pre-body application admission and bounded plaintext loopback serving.

use std::{
    convert::Infallible,
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use connectrpc::{ConnectError, ConnectRpcBody, ConnectRpcService, ErrorCode, Router};
use http::{Method, Request, Response};
use http_body_util::Empty;
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto, graceful::GracefulShutdown},
    service::TowerToHyperService,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
};
use tower_service::Service;

use crate::{
    PublicOperation,
    config::AgentLimits,
    credentials::ReloadableClientToken,
    lifecycle::{LifecycleState, ServiceStatus},
    proto::aster::application::v1alpha1 as api,
    public_error,
};

const APPLICATION_HEADER_DEADLINE: Duration = Duration::from_secs(5);
const APPLICATION_TRANSPORT_BUFFER_BYTES: usize = 16 * 1024;
const APPLICATION_HTTP2_STREAMS: u32 = 32;
const APPLICATION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const APPLICATION_MAX_CONNECTION_AGE: Duration = Duration::from_secs(30 * 60);
const APPLICATION_CONNECTION_AGE_GRACE: Duration = Duration::from_secs(30);

/// One application-listener control state. Task 6 owns signal translation and
/// bounded supervisor ordering around these states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerStop {
    /// Continue accepting application connections.
    Run,
    /// Stop accepting and gracefully finish tracked connections.
    Drain,
    /// Cancel every tracked connection immediately.
    Force,
}

/// A sanitized application-listener failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    /// The loopback listener could not be bound or inspected.
    Listener,
    /// The listener stopped accepting connections unexpectedly.
    Serving,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listener => formatter.write_str("application listener is unavailable"),
            Self::Serving => formatter.write_str("application listener stopped unexpectedly"),
        }
    }
}

impl Error for ServerError {}

#[derive(Clone)]
struct ConnectionAuthState {
    inner: Arc<ConnectionAuthInner>,
}

struct ConnectionAuthInner {
    authenticated: AtomicBool,
    unauthenticated: Mutex<Option<OwnedSemaphorePermit>>,
    changed: watch::Sender<bool>,
    admitted_at: tokio::time::Instant,
    retiring: AtomicBool,
    activity: watch::Sender<ConnectionActivity>,
}

#[derive(Clone, Copy)]
struct ConnectionActivity {
    active: usize,
    idle_since: tokio::time::Instant,
}

struct ActiveRequest(ConnectionAuthState);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.inner.activity.send_modify(|activity| {
            activity.active -= 1;
            if activity.active == 0 {
                activity.idle_since = tokio::time::Instant::now();
            }
        });
    }
}

impl ConnectionAuthState {
    fn new(unauthenticated: OwnedSemaphorePermit) -> Self {
        Self::with_permit(Some(unauthenticated))
    }

    #[cfg(test)]
    fn detached() -> Self {
        Self::with_permit(None)
    }

    fn with_permit(unauthenticated: Option<OwnedSemaphorePermit>) -> Self {
        let (changed, _) = watch::channel(false);
        let admitted_at = tokio::time::Instant::now();
        let (activity, _) = watch::channel(ConnectionActivity {
            active: 0,
            idle_since: admitted_at,
        });
        Self {
            inner: Arc::new(ConnectionAuthInner {
                authenticated: AtomicBool::new(false),
                unauthenticated: Mutex::new(unauthenticated),
                changed,
                admitted_at,
                retiring: AtomicBool::new(false),
                activity,
            }),
        }
    }

    fn begin_request(&self) -> ActiveRequest {
        self.inner
            .activity
            .send_modify(|activity| activity.active += 1);
        ActiveRequest(self.clone())
    }

    fn mark_authenticated(&self) {
        if !self.inner.authenticated.swap(true, Ordering::AcqRel) {
            self.inner
                .unauthenticated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            self.inner.changed.send_replace(true);
        }
    }

    async fn authenticated(&self) {
        if self.inner.authenticated.load(Ordering::Acquire) {
            return;
        }
        let mut changed = self.inner.changed.subscribe();
        while !*changed.borrow() {
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum GateRejection {
    Authentication,
    Draining,
    StateUnavailable,
    ResourceExhaustion,
}

impl GateRejection {
    fn error(self) -> ConnectError {
        match self {
            Self::Authentication => public_error(
                ErrorCode::Unauthenticated,
                api::PublicErrorReason::AuthenticationFailed,
                PublicOperation::Unspecified,
                false,
                None,
            ),
            Self::Draining => public_error(
                ErrorCode::Unavailable,
                api::PublicErrorReason::Draining,
                PublicOperation::Unspecified,
                true,
                None,
            ),
            Self::StateUnavailable => public_error(
                ErrorCode::Unavailable,
                api::PublicErrorReason::StateUnavailable,
                PublicOperation::Unspecified,
                true,
                None,
            ),
            Self::ResourceExhaustion => public_error(
                ErrorCode::ResourceExhausted,
                api::PublicErrorReason::ResourceExhaustion,
                PublicOperation::Unspecified,
                true,
                None,
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct RejectionInterceptor;

impl RejectionInterceptor {
    fn error(ctx: &connectrpc::RequestContext) -> ConnectError {
        ctx.extensions()
            .get::<GateRejection>()
            .copied()
            .unwrap_or(GateRejection::StateUnavailable)
            .error()
    }
}

#[connectrpc::async_trait]
impl connectrpc::Interceptor for RejectionInterceptor {
    async fn intercept_unary(
        &self,
        request: connectrpc::interceptor::UnaryRequest,
        _next: connectrpc::Next<'_>,
    ) -> Result<connectrpc::interceptor::UnaryResponse, ConnectError> {
        Err(Self::error(&request.ctx))
    }

    async fn intercept_streaming(
        &self,
        request: connectrpc::interceptor::StreamRequest,
        _inbound: connectrpc::PayloadStream,
        _next: connectrpc::NextStream<'_>,
    ) -> Result<connectrpc::interceptor::StreamResponse, ConnectError> {
        Err(Self::error(&request.ctx))
    }
}

/// A Tower service that decides authentication and admission from request
/// headers before the original body can be read or decoded.
#[derive(Clone)]
pub struct PreBodyGate<S> {
    accepted: S,
    rejected: S,
    token: ReloadableClientToken,
    status: ServiceStatus,
    in_flight: Arc<Semaphore>,
    connection_auth: ConnectionAuthState,
    max_header_bytes: usize,
}

impl PreBodyGate<ConnectRpcService<Router>> {
    fn new(
        accepted: ConnectRpcService<Router>,
        token: ReloadableClientToken,
        status: ServiceStatus,
        in_flight: Arc<Semaphore>,
        connection_auth: ConnectionAuthState,
        max_header_bytes: usize,
    ) -> Self {
        let rejected =
            crate::event_service::configured_service(crate::event_service::rejection_router())
                .with_interceptor(RejectionInterceptor);
        Self {
            accepted,
            rejected,
            token,
            status,
            in_flight,
            connection_auth,
            max_header_bytes,
        }
    }
}

enum Admission {
    Accepted(OwnedSemaphorePermit),
    Rejected(GateRejection),
}

impl<B, S> Service<Request<B>> for PreBodyGate<S>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
    S: Service<Request<B>, Response = Response<ConnectRpcBody>, Error = Infallible>
        + Service<Request<Empty<Bytes>>, Response = Response<ConnectRpcBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    <S as Service<Request<B>>>::Future: Send + 'static,
    <S as Service<Request<Empty<Bytes>>>>::Future: Send + 'static,
{
    type Response = Response<PermitBody<ConnectRpcBody>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let admission = if !authorizes(&self.token, &request) {
            Admission::Rejected(GateRejection::Authentication)
        } else {
            self.connection_auth.mark_authenticated();
            match self.status.state() {
                LifecycleState::Ready => {
                    if self.connection_auth.inner.retiring.load(Ordering::Acquire)
                        || tokio::time::Instant::now()
                            >= self.connection_auth.inner.admitted_at
                                + APPLICATION_MAX_CONNECTION_AGE
                    {
                        Admission::Rejected(GateRejection::StateUnavailable)
                    } else if !headers_fit(&request, self.max_header_bytes) {
                        Admission::Rejected(GateRejection::ResourceExhaustion)
                    } else {
                        match self.in_flight.clone().try_acquire_owned() {
                            Ok(permit) => Admission::Accepted(permit),
                            Err(_) => Admission::Rejected(GateRejection::ResourceExhaustion),
                        }
                    }
                }
                LifecycleState::Draining => Admission::Rejected(GateRejection::Draining),
                LifecycleState::Starting | LifecycleState::Stopped | LifecycleState::Failed => {
                    Admission::Rejected(GateRejection::StateUnavailable)
                }
            }
        };
        let mut accepted = self.accepted.clone();
        let mut rejected = self.rejected.clone();
        let active_request = matches!(admission, Admission::Accepted(_))
            .then(|| self.connection_auth.begin_request());

        Box::pin(async move {
            match admission {
                Admission::Accepted(permit) => {
                    let mut response =
                        <S as Service<Request<B>>>::call(&mut accepted, request).await?;
                    let errors = crate::wire_error::WireErrors::for_response(&mut response);
                    Ok(response.map(|body| {
                        let mut body = PermitBody::new(body, permit);
                        body.errors = errors;
                        body.active_request = active_request;
                        body
                    }))
                }
                Admission::Rejected(rejection) => {
                    let protocol = connectrpc::Protocol::detect(request.headers());
                    let native_grpc = protocol
                        .as_ref()
                        .is_some_and(|protocol| protocol.protocol == connectrpc::Protocol::Grpc);
                    let (mut parts, body) = request.into_parts();
                    drop(body);
                    // Retain only the response framing choice. No rejected
                    // URI, query, compression, deadline, or protocol metadata
                    // may reach the framework's request validation paths.
                    let content_type = match protocol {
                        Some(p) if p.protocol == connectrpc::Protocol::Grpc => "application/grpc",
                        Some(p) if p.protocol == connectrpc::Protocol::GrpcWeb => {
                            "application/grpc-web+proto"
                        }
                        Some(p) if p.is_streaming => "application/connect+proto",
                        _ => "application/proto",
                    };
                    parts.headers.clear();
                    parts.headers.insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static(content_type),
                    );
                    parts.uri = http::Uri::from_static(
                        "/aster.application.v1alpha1.AsterApplicationService/GetStatus",
                    );
                    parts.method = Method::POST;
                    parts.extensions.insert(rejection);
                    let replacement = Request::from_parts(parts, Empty::<Bytes>::new());
                    let mut response =
                        <S as Service<Request<Empty<Bytes>>>>::call(&mut rejected, replacement)
                            .await?;
                    if native_grpc {
                        response.headers_mut().remove("grpc-status");
                        response.headers_mut().remove("grpc-message");
                    }
                    Ok(response.map(PermitBody::without_permit))
                }
            }
        })
    }
}

fn authorizes<B>(token: &ReloadableClientToken, request: &Request<B>) -> bool {
    let mut values = request
        .headers()
        .get_all(http::header::AUTHORIZATION)
        .iter();
    let provided = values.next();
    values.next().is_none() && token.authorizes(provided.map(http::HeaderValue::as_bytes))
}

fn headers_fit<B>(request: &Request<B>, limit: usize) -> bool {
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
        .is_some_and(|total| total <= limit)
}

fn first_authentication_deadline(
    admitted_at: tokio::time::Instant,
    timeout: Duration,
) -> tokio::time::Instant {
    admitted_at + timeout
}

async fn drive_connection<F>(
    connection: F,
    connection_auth: ConnectionAuthState,
    first_authentication_deadline: tokio::time::Instant,
) where
    F: Future,
{
    tokio::pin!(connection);
    let first_authentication = tokio::time::sleep_until(first_authentication_deadline);
    tokio::pin!(first_authentication);
    let mut activity = connection_auth.inner.activity.subscribe();
    let maximum_age = connection_auth.inner.admitted_at + APPLICATION_MAX_CONNECTION_AGE;
    let mut authenticated = false;
    let mut retiring = false;
    loop {
        let snapshot = *activity.borrow_and_update();
        tokio::select! {
            _ = connection.as_mut() => break,
            () = connection_auth.authenticated(), if !authenticated => authenticated = true,
            () = first_authentication.as_mut(), if !authenticated => break,
            _ = activity.changed() => {},
            () = tokio::time::sleep_until(snapshot.idle_since + APPLICATION_IDLE_TIMEOUT),
                if authenticated && snapshot.active == 0 => {
                    // Admission can change activity while the connection is
                    // polled in this same select. Never retire accepted work
                    // on an obsolete idle snapshot.
                    let current = *activity.borrow();
                    if current.active == 0 && current.idle_since + APPLICATION_IDLE_TIMEOUT <= tokio::time::Instant::now() {
                        break;
                    }
                },
            () = tokio::time::sleep_until(maximum_age), if !retiring => {
                retiring = true;
                connection_auth.inner.retiring.store(true, Ordering::Release);
            },
            () = tokio::time::sleep_until(maximum_age + APPLICATION_CONNECTION_AGE_GRACE) => break,
        }
    }
}

/// A response body that owns an in-flight permit until the complete body has
/// been consumed or the caller cancels by dropping it.
pub struct PermitBody<B> {
    inner: B,
    permit: Option<OwnedSemaphorePermit>,
    errors: crate::wire_error::WireErrors,
    active_request: Option<ActiveRequest>,
}

impl<B> PermitBody<B> {
    fn new(inner: B, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            permit: Some(permit),
            errors: Default::default(),
            active_request: None,
        }
    }

    fn without_permit(inner: B) -> Self {
        Self {
            inner,
            permit: None,
            errors: Default::default(),
            active_request: None,
        }
    }
}

impl<B> Body for PermitBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None)) || this.inner.is_end_stream() {
            this.permit.take();
            this.active_request.take();
        }
        result.map(|frame| frame.map(|frame| frame.map(|frame| this.errors.frame(frame))))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A plaintext loopback application listener that has not begun serving.
pub struct BoundAgent {
    listener: TcpListener,
}

impl BoundAgent {
    /// Binds the application listener only to loopback.
    pub async fn bind(address: SocketAddr) -> Result<Self, ServerError> {
        if !address.ip().is_loopback() {
            return Err(ServerError::Listener);
        }
        TcpListener::bind(address)
            .await
            .map(|listener| Self { listener })
            .map_err(|_| ServerError::Listener)
    }

    /// Returns the exact address selected by the operating system.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        self.listener
            .local_addr()
            .map_err(|_| ServerError::Listener)
    }

    /// Serves the supplied Event router with node-global admission limits.
    pub async fn serve(
        self,
        service: ConnectRpcService<Router>,
        token: ReloadableClientToken,
        status: ServiceStatus,
        limits: AgentLimits,
        mut stop: watch::Receiver<ServerStop>,
    ) -> Result<(), ServerError> {
        let total = Arc::new(Semaphore::new(limits.max_connections()));
        let unauthenticated = Arc::new(Semaphore::new(limits.max_unauthenticated_connections()));
        let in_flight = Arc::new(Semaphore::new(limits.max_in_flight_requests()));
        let graceful = GracefulShutdown::new();
        let mut connections = JoinSet::new();
        let result = loop {
            match *stop.borrow() {
                ServerStop::Run => {}
                ServerStop::Drain => break Ok(true),
                ServerStop::Force => break Ok(false),
            }

            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() {
                        break Err(ServerError::Serving);
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => break Err(ServerError::Serving),
                    };
                    let Ok(total_permit) = total.clone().try_acquire_owned() else {
                        continue;
                    };
                    let Ok(unauthenticated_permit) =
                        unauthenticated.clone().try_acquire_owned()
                    else {
                        continue;
                    };
                    let first_authentication_deadline = first_authentication_deadline(
                        tokio::time::Instant::now(),
                        limits.first_authentication_timeout(),
                    );

                    let connection_auth = ConnectionAuthState::new(unauthenticated_permit);
                    let gate = PreBodyGate::new(
                        service.clone(),
                        token.clone(),
                        status.clone(),
                        in_flight.clone(),
                        connection_auth.clone(),
                        limits.max_header_bytes(),
                    );
                    let watcher = graceful.watcher();
                    connections.spawn(async move {
                        let _total_permit = total_permit;
                        let mut builder = auto::Builder::new(TokioExecutor::new());
                        builder
                            .http1()
                            .timer(TokioTimer::new())
                            .header_read_timeout(APPLICATION_HEADER_DEADLINE)
                            .max_buf_size(APPLICATION_TRANSPORT_BUFFER_BYTES);
                        builder
                            .http2()
                            .timer(TokioTimer::new())
                            .keep_alive_interval(Some(Duration::from_secs(30)))
                            .keep_alive_timeout(Duration::from_secs(20))
                            .max_header_list_size(limits.max_header_bytes() as u32)
                            .max_concurrent_streams(APPLICATION_HTTP2_STREAMS);
                        drive_connection(
                            watcher.watch(builder.serve_connection(
                                TokioIo::new(stream),
                                TowerToHyperService::new(gate),
                            )),
                            connection_auth,
                            first_authentication_deadline,
                        )
                        .await;
                    });
                }
                Some(_) = connections.join_next() => {}
            }
        };

        match result {
            Ok(false) => connections.shutdown().await,
            Ok(true) => {
                let shutdown = graceful.shutdown();
                tokio::pin!(shutdown);
                loop {
                    tokio::select! {
                        () = shutdown.as_mut() => break,
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() == ServerStop::Force {
                                connections.shutdown().await;
                                return Ok(());
                            }
                        }
                    }
                }
                while connections.join_next().await.is_some() {}
            }
            Err(error) => {
                connections.shutdown().await;
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use buffa::Message as _;
    #[cfg(feature = "client")]
    use buffa::MessageName as _;
    use bytes::Bytes;
    #[cfg(feature = "client")]
    use connectrpc::{
        ConnectError, Protocol,
        client::{ClientConfig, ServiceTransport},
    };
    use connectrpc::{ConnectRpcService, ErrorCode, Router};
    use http::{Request, StatusCode, header::CONTENT_TYPE};
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::{Body, Frame};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        sync::{Semaphore, watch},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        ClientToken,
        config::AgentLimits,
        credentials::ReloadableClientToken,
        lifecycle::{LifecycleState, ServiceStatus},
        proto::aster::application::v1alpha1 as api,
    };

    const TEST_TOKEN: &[u8] = b"server-pre-body-test-token-00001";

    struct PanicOnPollBody;

    impl Body for PanicOnPollBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            panic!("rejected request body was polled")
        }
    }

    fn token() -> ReloadableClientToken {
        ReloadableClientToken::new(
            ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid test token"),
        )
    }

    fn ready() -> ServiceStatus {
        let status = ServiceStatus::starting();
        status.transition(LifecycleState::Ready).expect("ready");
        status
    }

    fn request_without_authorization(body: PanicOnPollBody) -> Request<PanicOnPollBody> {
        Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
            .header(CONTENT_TYPE, "application/proto")
            .body(body)
            .expect("request")
    }

    fn request_with_authorization(body: PanicOnPollBody) -> Request<PanicOnPollBody> {
        Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
            .header(CONTENT_TYPE, "application/proto")
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            )
            .body(body)
            .expect("request")
    }

    fn decode_base64(value: &str) -> Vec<u8> {
        fn sextet(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64 fixture"),
            }
        }

        let mut decoded = Vec::new();
        for chunk in value.as_bytes().chunks(4) {
            let a = sextet(chunk[0]);
            let b = sextet(chunk[1]);
            decoded.push((a << 2) | (b >> 4));
            if chunk.len() > 2 && chunk[2] != b'=' {
                let c = sextet(chunk[2]);
                decoded.push((b << 4) | (c >> 2));
                if chunk.len() > 3 && chunk[3] != b'=' {
                    decoded.push((c << 6) | sextet(chunk[3]));
                }
            }
        }
        decoded
    }

    async fn assert_public_error(
        response: http::Response<PermitBody<connectrpc::ConnectRpcBody>>,
        code: ErrorCode,
        reason: api::PublicErrorReason,
    ) {
        assert_eq!(response.status(), code.http_status());
        let body = response
            .into_body()
            .collect()
            .await
            .expect("infallible response body")
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("Connect error JSON");
        assert_eq!(json["code"], code.as_str());
        let detail = &json["details"][0];
        assert_eq!(
            detail["type"],
            "aster.application.v1alpha1.PublicErrorDetail"
        );
        let encoded = detail["value"].as_str().expect("encoded public detail");
        let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(encoded))
            .expect("decodable public detail");
        assert_eq!(detail.reason, reason);
    }

    #[cfg(feature = "client")]
    fn assert_authentication_error(error: &ConnectError, expected_type_url: &str, procedure: &str) {
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(error.message.as_deref(), Some("authentication failed"));
        assert_eq!(
            error.details.len(),
            1,
            "{procedure} omitted its public authentication detail: {error:?}"
        );
        let wire_detail = &error.details[0];
        assert_eq!(wire_detail.type_url, expected_type_url);
        assert!(wire_detail.debug.is_none());
        let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(
            wire_detail.value.as_deref().expect("encoded public detail"),
        ))
        .expect("decodable public detail");
        assert_eq!(detail.reason, api::PublicErrorReason::AuthenticationFailed);
        assert_eq!(detail.operation, "unspecified");
        assert!(!detail.retryable);
        assert_eq!(detail.retry_delay_ms, None);
    }

    #[cfg(feature = "client")]
    fn unauthenticated_client(
        protocol: Protocol,
    ) -> api::AsterApplicationServiceClient<ServiceTransport<PreBodyGate<ConnectRpcService<Router>>>>
    {
        let gate = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            Arc::new(Semaphore::new(1)),
            ConnectionAuthState::detached(),
            16 * 1024,
        );
        api::AsterApplicationServiceClient::new(
            ServiceTransport::new(gate),
            ClientConfig::new("http://localhost".parse().expect("base URI"))
                .with_protocol(protocol),
        )
    }

    #[cfg(feature = "client")]
    async fn assert_every_procedure_rejected(
        client: &api::AsterApplicationServiceClient<
            ServiceTransport<PreBodyGate<ConnectRpcService<Router>>>,
        >,
        expected_type_url: &str,
    ) {
        macro_rules! assert_unary_rejected {
            ($call:expr, $name:literal) => {{
                let error = match $call.await {
                    Ok(_) => panic!(concat!($name, " unexpectedly reached accepted router")),
                    Err(error) => error,
                };
                assert_authentication_error(&error, expected_type_url, $name);
            }};
        }

        assert_unary_rejected!(
            client.get_status(api::GetStatusRequest::default()),
            "GetStatus"
        );
        assert_unary_rejected!(
            client.publish_event(api::PublishEventRequest::default()),
            "PublishEvent"
        );
        assert_unary_rejected!(
            client.query_events(api::QueryEventsRequest::default()),
            "QueryEvents"
        );
        assert_unary_rejected!(
            client.create_event_subscription(api::CreateEventSubscriptionRequest::default()),
            "CreateEventSubscription"
        );
        assert_unary_rejected!(
            client.list_event_subscriptions(api::ListEventSubscriptionsRequest::default()),
            "ListEventSubscriptions"
        );
        assert_unary_rejected!(
            client.poll_events(api::PollEventsRequest::default()),
            "PollEvents"
        );
        assert_unary_rejected!(
            client.acknowledge_event(api::AcknowledgeEventRequest::default()),
            "AcknowledgeEvent"
        );
        assert_unary_rejected!(
            client.delete_event_subscription(api::DeleteEventSubscriptionRequest::default()),
            "DeleteEventSubscription"
        );
        assert_unary_rejected!(
            client.query_event_gaps(api::QueryEventGapsRequest::default()),
            "QueryEventGaps"
        );

        let mut stream = match client
            .stream_events(api::StreamEventsRequest::default())
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                assert_authentication_error(&error, expected_type_url, "StreamEvents");
                return;
            }
        };
        let error = stream
            .message()
            .await
            .expect_err("StreamEvents unexpectedly reached accepted router");
        assert_authentication_error(&error, expected_type_url, "StreamEvents");
    }

    #[tokio::test]
    async fn unauthenticated_request_is_rejected_without_polling_body() {
        let gate = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            Arc::new(Semaphore::new(1)),
            ConnectionAuthState::detached(),
            16 * 1024,
        );
        let response = gate
            .oneshot(request_without_authorization(PanicOnPollBody))
            .await
            .expect("infallible service");
        assert_public_error(
            response,
            ErrorCode::Unauthenticated,
            api::PublicErrorReason::AuthenticationFailed,
        )
        .await;
    }

    #[tokio::test]
    async fn rejected_protocol_metadata_cannot_override_authentication_or_echo_values() {
        // Break caught: compression/protocol parsing before the rejection
        // interceptor can replace authentication with a reflected input error.
        for content_type in [
            "application/proto",
            "application/connect+json",
            "application/grpc",
            "application/grpc-web",
        ] {
            let response = PreBodyGate::new(
                ConnectRpcService::new(Router::new()),
                token(),
                ready(),
                Arc::new(Semaphore::new(1)),
                ConnectionAuthState::detached(),
                16 * 1024,
            )
            .oneshot(
                Request::post("/SECRET_URI_CANARY?encoding=SECRET_QUERY_CANARY")
                    .header(CONTENT_TYPE, content_type)
                    .header("grpc-encoding", "SECRET_COMPRESSION_CANARY")
                    .header("content-encoding", "SECRET_COMPRESSION_CANARY")
                    .header("connect-protocol-version", "SECRET_VERSION_CANARY")
                    .body(PanicOnPollBody)
                    .unwrap(),
            )
            .await
            .unwrap();
            let headers = format!("{:?}", response.headers());
            let body = response.into_body().collect().await.unwrap();
            let trailers = format!("{:?}", body.trailers());
            let bytes = body.to_bytes();
            let wire = format!("{headers}{trailers}{}", String::from_utf8_lossy(&bytes));
            assert!(
                !wire.contains("SECRET_"),
                "request value escaped on {content_type}: {wire}"
            );
            assert!(
                wire.contains("authentication") || wire.contains("authentication%20failed"),
                "authentication contract lost: {wire}"
            );
        }
    }

    #[tokio::test]
    async fn framework_failures_are_sanitized_on_the_wire() {
        use connectrpc::handler_fn;
        for (content_type, header, value, path, body) in [
            (
                "application/grpc+json",
                "grpc-encoding",
                "identity",
                "PublishEvent",
                br#"{"priority":"SECRET_PRIORITY_CANARY"}"#.as_slice(),
            ),
            (
                "application/grpc-web+json",
                "grpc-encoding",
                "identity",
                "PublishEvent",
                br#"{"priority":"SECRET_PRIORITY_CANARY"}"#.as_slice(),
            ),
            (
                "application/json",
                "connect-protocol-version",
                "1",
                "PublishEvent",
                br#"{"priority":"SECRET_PRIORITY_CANARY"}"#.as_slice(),
            ),
            (
                "application/grpc",
                "grpc-encoding",
                "SECRET_COMPRESSION_CANARY",
                "PublishEvent",
                b"".as_slice(),
            ),
            (
                "application/grpc-web",
                "grpc-encoding",
                "SECRET_COMPRESSION_CANARY",
                "PublishEvent",
                b"".as_slice(),
            ),
            (
                "application/connect+json",
                "connect-content-encoding",
                "SECRET_COMPRESSION_CANARY",
                "StreamEvents",
                b"".as_slice(),
            ),
            (
                "application/proto",
                "connect-protocol-version",
                "SECRET_VERSION_CANARY",
                "SECRET_PATH_CANARY",
                b"".as_slice(),
            ),
        ] {
            let body = if content_type.ends_with("+json") && !body.is_empty() {
                let mut framed = vec![0];
                framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
                framed.extend_from_slice(body);
                Bytes::from(framed)
            } else {
                Bytes::copy_from_slice(body)
            };
            let router = Router::new().route(
                api::ASTER_APPLICATION_SERVICE_SERVICE_NAME,
                "PublishEvent",
                handler_fn(|_ctx, _request: api::PublishEventRequest| async {
                    Ok(connectrpc::Response::new(
                        api::PublishEventResponse::default(),
                    ))
                }),
            );
            let response = PreBodyGate::new(
                crate::event_service::configured_service(router),
                token(),
                ready(),
                Arc::new(Semaphore::new(1)),
                ConnectionAuthState::detached(),
                16 * 1024,
            )
            .oneshot(
                Request::post(format!(
                    "/aster.application.v1alpha1.AsterApplicationService/{path}"
                ))
                .header(CONTENT_TYPE, content_type)
                .header(header, value)
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                )
                .body(Full::new(body))
                .unwrap(),
            )
            .await
            .unwrap();
            let headers = format!("{:?}", response.headers());
            let collected = response.into_body().collect().await.unwrap();
            let trailers = format!("{:?}", collected.trailers());
            let bytes = collected.to_bytes();
            let wire = format!("{headers}{trailers}{}", String::from_utf8_lossy(&bytes));
            assert!(
                !wire.contains("SECRET_"),
                "framework reflected input on {content_type}: {wire}"
            );
            assert!(
                !wire.contains("failed to decode") && !wire.contains("unknown variant"),
                "raw framework diagnostic escaped: {wire}"
            );
            assert!(
                !wire.contains("grpc-status-details-bin"),
                "raw framework Status must not survive sanitization"
            );
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn stream_error_sanitization_preserves_large_event_payloads_across_protocols() {
        for protocol in [Protocol::Connect, Protocol::Grpc, Protocol::GrpcWeb] {
            let payload = b"\x80\x00\x00\x00\x01SECRET_EVENT_PAYLOAD".repeat(4096);
            let expected = payload.clone();
            let router = Router::new().route_server_stream(
                api::ASTER_APPLICATION_SERVICE_SERVICE_NAME,
                "StreamEvents",
                connectrpc::streaming_handler_fn(
                    move |_ctx, _request: api::StreamEventsRequest| {
                        let payload = payload.clone();
                        async move {
                            Ok(connectrpc::Response::new(Box::pin(futures::stream::iter([
                                Ok(api::StreamEventsResponse {
                                    event: Some(api::Event {
                                        payload,
                                        ..Default::default()
                                    })
                                    .into(),
                                    attempt: 2,
                                    ..Default::default()
                                }),
                                Err(ConnectError::internal("SECRET_FRAMEWORK_CANARY")),
                            ]))
                                as connectrpc::ServiceStream<api::StreamEventsResponse>))
                        }
                    },
                ),
            );
            let client = api::AsterApplicationServiceClient::new(
                ServiceTransport::new(PreBodyGate::new(
                    crate::event_service::configured_service(router),
                    token(),
                    ready(),
                    Arc::new(Semaphore::new(1)),
                    ConnectionAuthState::detached(),
                    16 * 1024,
                )),
                ClientConfig::new("http://localhost".parse().unwrap())
                    .with_protocol(protocol)
                    .with_default_header(
                        http::header::AUTHORIZATION,
                        format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                    ),
            );
            let mut stream = client
                .stream_events(api::StreamEventsRequest::default())
                .await
                .unwrap();
            let message = stream.message().await.unwrap().unwrap().to_owned_message();
            assert_eq!(message.event.as_option().unwrap().payload, expected);
            assert_eq!(message.attempt, 2);
            let error = stream.message().await.unwrap_err();
            assert_eq!(error.code, ErrorCode::Internal);
            assert_eq!(error.message.as_deref(), Some("request failed"));
            assert!(error.details.is_empty());
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test(start_paused = true)]
    async fn established_stream_obeys_server_deadline_and_returns_capacity() {
        // Break caught: a server-clamped deadline that stops only establishment
        // leaves an idle stream's global in-flight slot occupied indefinitely.
        let router = Router::new().route_server_stream(
            api::ASTER_APPLICATION_SERVICE_SERVICE_NAME,
            "StreamEvents",
            connectrpc::streaming_handler_fn(|_ctx, _request: api::StreamEventsRequest| async {
                Ok(connectrpc::Response::new(
                    Box::pin(futures::stream::pending::<
                        Result<api::StreamEventsResponse, ConnectError>,
                    >())
                        as connectrpc::ServiceStream<api::StreamEventsResponse>,
                ))
            }),
        );
        let permits = Arc::new(Semaphore::new(1));
        let client = api::AsterApplicationServiceClient::new(
            ServiceTransport::new(PreBodyGate::new(
                crate::event_service::configured_service(router),
                token(),
                ready(),
                permits.clone(),
                ConnectionAuthState::detached(),
                16 * 1024,
            )),
            ClientConfig::new("http://localhost".parse().unwrap())
                .with_default_timeout(Duration::from_secs(120))
                .with_default_header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let mut stream = client
            .stream_events(api::StreamEventsRequest::default())
            .await
            .unwrap();
        assert_eq!(permits.available_permits(), 0);
        let result = tokio::time::timeout(Duration::from_secs(31), stream.message()).await;
        assert!(
            result.is_ok(),
            "stream exceeded the server's 30-second deadline"
        );
        assert_eq!(
            result.unwrap().unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
        drop(stream);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn draining_request_is_rejected_without_polling_body() {
        let status = ready();
        status
            .transition(LifecycleState::Draining)
            .expect("draining");
        let response = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            status,
            Arc::new(Semaphore::new(1)),
            ConnectionAuthState::detached(),
            16 * 1024,
        )
        .oneshot(request_with_authorization(PanicOnPollBody))
        .await
        .expect("infallible service");
        assert_public_error(
            response,
            ErrorCode::Unavailable,
            api::PublicErrorReason::Draining,
        )
        .await;
    }

    #[tokio::test]
    async fn exhausted_in_flight_capacity_is_rejected_without_polling_body() {
        let response = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            Arc::new(Semaphore::new(0)),
            ConnectionAuthState::detached(),
            16 * 1024,
        )
        .oneshot(request_with_authorization(PanicOnPollBody))
        .await
        .expect("infallible service");
        assert_public_error(
            response,
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
        )
        .await;
    }

    #[tokio::test]
    async fn configured_header_budget_is_enforced_before_polling_body() {
        let response = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            Arc::new(Semaphore::new(1)),
            ConnectionAuthState::detached(),
            1,
        )
        .oneshot(request_with_authorization(PanicOnPollBody))
        .await
        .expect("infallible service");
        assert_public_error(
            response,
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
        )
        .await;
    }

    #[tokio::test]
    async fn missing_invalid_and_duplicate_bearers_are_indistinguishable() {
        async fn rejection(request: Request<PanicOnPollBody>) -> (StatusCode, Bytes) {
            let response = PreBodyGate::new(
                ConnectRpcService::new(Router::new()),
                token(),
                ready(),
                Arc::new(Semaphore::new(1)),
                ConnectionAuthState::detached(),
                16 * 1024,
            )
            .oneshot(request)
            .await
            .expect("infallible service");
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .expect("infallible response body")
                .to_bytes();
            (status, body)
        }

        let missing = rejection(request_without_authorization(PanicOnPollBody)).await;
        let invalid = rejection(
            Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
                .header(CONTENT_TYPE, "application/proto")
                .header(
                    http::header::AUTHORIZATION,
                    "Bearer invalid-credential-canary-0001",
                )
                .body(PanicOnPollBody)
                .expect("request"),
        )
        .await;
        let duplicate = rejection(
            Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
                .header(CONTENT_TYPE, "application/proto")
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                )
                .header(http::header::AUTHORIZATION, "Bearer invalid-duplicate")
                .body(PanicOnPollBody)
                .expect("request"),
        )
        .await;
        assert_eq!(missing, invalid);
        assert_eq!(missing, duplicate);
        assert!(!String::from_utf8_lossy(&invalid.1).contains("credential-canary"));
    }

    #[tokio::test]
    async fn in_flight_permit_releases_at_body_completion_and_cancellation() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = permits.clone().try_acquire_owned().expect("initial permit");
        let mut body = PermitBody::new(Full::new(Bytes::from_static(b"response")), permit);
        assert!(permits.clone().try_acquire_owned().is_err());
        assert!(body.frame().await.expect("response frame").is_ok());
        assert!(
            permits.clone().try_acquire_owned().is_ok(),
            "completed response must release its in-flight permit"
        );

        let permit = permits
            .clone()
            .try_acquire_owned()
            .expect("cancellation permit");
        let body = PermitBody::new(Full::new(Bytes::from_static(b"cancelled")), permit);
        assert!(permits.clone().try_acquire_owned().is_err());
        drop(body);
        assert!(permits.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn in_flight_capacity_is_node_global_across_connections() {
        let permits = Arc::new(Semaphore::new(1));
        let accepted = ConnectRpcService::new(Router::new());
        let first = PreBodyGate::new(
            accepted.clone(),
            token(),
            ready(),
            permits.clone(),
            ConnectionAuthState::detached(),
            16 * 1024,
        )
        .oneshot(
            Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
                .header(CONTENT_TYPE, "application/proto")
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                )
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("infallible service");

        let second = PreBodyGate::new(
            accepted,
            token(),
            ready(),
            permits.clone(),
            ConnectionAuthState::detached(),
            16 * 1024,
        )
        .oneshot(request_with_authorization(PanicOnPollBody))
        .await
        .expect("infallible service");
        assert_public_error(
            second,
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
        )
        .await;

        drop(first);
        assert!(
            permits.try_acquire_owned().is_ok(),
            "cancelling one connection response must return capacity globally"
        );
    }

    #[tokio::test]
    async fn unauthenticated_permit_releases_only_after_first_valid_bearer() {
        let unauthenticated = Arc::new(Semaphore::new(1));
        let state = ConnectionAuthState::new(
            unauthenticated
                .clone()
                .try_acquire_owned()
                .expect("connection permit"),
        );
        let status = ready();
        status
            .transition(LifecycleState::Draining)
            .expect("draining");
        let mut gate = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            status,
            Arc::new(Semaphore::new(1)),
            state,
            16 * 1024,
        );

        let invalid = gate
            .call(request_without_authorization(PanicOnPollBody))
            .await
            .expect("infallible service");
        drop(invalid);
        assert!(
            unauthenticated.clone().try_acquire_owned().is_err(),
            "invalid authentication must retain the connection permit"
        );

        let valid = gate
            .call(request_with_authorization(PanicOnPollBody))
            .await
            .expect("infallible service");
        assert_public_error(
            valid,
            ErrorCode::Unavailable,
            api::PublicErrorReason::Draining,
        )
        .await;
        assert!(
            unauthenticated.try_acquire_owned().is_ok(),
            "valid authentication must release the connection permit before lifecycle admission"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn authenticated_idle_connection_returns_total_capacity() {
        // Break caught: authenticated idle connections retain every total slot.
        let total = Arc::new(Semaphore::new(1));
        let permit = total.clone().try_acquire_owned().unwrap();
        let state = ConnectionAuthState::detached();
        state.mark_authenticated();
        let driver = tokio::spawn(drive_connection(
            async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            },
            state,
            tokio::time::Instant::now() + Duration::from_secs(5),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(
            driver.is_finished(),
            "authenticated idle connection never expired"
        );
        driver.await.unwrap();
        assert_eq!(total.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn active_connection_expires_after_maximum_age_and_returns_capacity() {
        // Break caught: recurring requests can otherwise retain a total slot forever.
        let total = Arc::new(Semaphore::new(1));
        let permit = total.clone().try_acquire_owned().unwrap();
        let state = ConnectionAuthState::detached();
        state.mark_authenticated();
        let gate = PreBodyGate::new(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            Arc::new(Semaphore::new(1)),
            state.clone(),
            16 * 1024,
        );
        let driver = tokio::spawn(drive_connection(
            async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            },
            state,
            tokio::time::Instant::now() + Duration::from_secs(5),
        ));
        for _ in 0..36 {
            let response = gate
                .clone()
                .oneshot(
                    Request::post("/aster.application.v1alpha1.AsterApplicationService/GetStatus")
                        .header(CONTENT_TYPE, "application/proto")
                        .header(
                            http::header::AUTHORIZATION,
                            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                        )
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            response.into_body().collect().await.unwrap();
            tokio::time::advance(Duration::from_secs(50)).await;
            tokio::task::yield_now().await;
            assert!(
                !driver.is_finished(),
                "active connection closed before its age bound"
            );
        }
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert!(
            driver.is_finished(),
            "connection survived maximum age plus grace"
        );
        driver.await.unwrap();
        assert_eq!(total.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn first_authentication_deadline_is_anchored_at_connection_admission() {
        let admitted_at = tokio::time::Instant::now();
        let deadline = first_authentication_deadline(admitted_at, Duration::from_secs(5));

        tokio::time::advance(Duration::from_secs(4)).await;
        let connection_task_started_at = tokio::time::Instant::now();
        assert_eq!(
            deadline.saturating_duration_since(connection_task_started_at),
            Duration::from_secs(1),
            "task scheduling must consume the connection's authentication budget"
        );

        let connection = tokio::spawn(drive_connection(
            std::future::pending::<()>(),
            ConnectionAuthState::detached(),
            deadline,
        ));
        tokio::task::yield_now().await;
        assert!(!connection.is_finished());
        tokio::time::advance(Duration::from_millis(999)).await;
        tokio::task::yield_now().await;
        assert!(!connection.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            connection.is_finished(),
            "the production driver must close at the admission-derived deadline"
        );
        connection.await.expect("connection driver joins");
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn every_event_procedure_preserves_structured_authentication_across_protocols() {
        for (protocol, expected_type_url) in [
            (Protocol::Connect, api::PublicErrorDetail::FULL_NAME),
            (Protocol::GrpcWeb, api::PublicErrorDetail::TYPE_URL),
            (Protocol::Grpc, api::PublicErrorDetail::TYPE_URL),
        ] {
            assert_every_procedure_rejected(&unauthenticated_client(protocol), expected_type_url)
                .await;
        }
    }

    #[tokio::test]
    async fn ninth_unauthenticated_connection_is_refused() {
        let server = BoundAgent::bind("127.0.0.1:0".parse().expect("loopback address"))
            .await
            .expect("bind application listener");
        let address = server.local_addr().expect("application address");
        let (stop_send, stop_receive) = watch::channel(ServerStop::Run);
        let task = tokio::spawn(server.serve(
            ConnectRpcService::new(Router::new()),
            token(),
            ready(),
            AgentLimits::default(),
            stop_receive,
        ));

        let mut first_eight = Vec::new();
        for _ in 0..8 {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("open admitted idle connection");
            stream
                .write_all(b"G")
                .await
                .expect("start incomplete request");
            first_eight.push(stream);
        }

        let mut ninth = TcpStream::connect(address)
            .await
            .expect("kernel accepts connection before application admission");
        ninth.write_all(b"G").await.expect("write admission probe");
        let mut byte = [0_u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), ninth.read(&mut byte))
            .await
            .expect("ninth connection is refused promptly")
        {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(read) => panic!("refused connection received {read} response bytes"),
            Err(error) => panic!("unexpected refusal error: {error}"),
        }

        drop(first_eight);
        stop_send.send(ServerStop::Force).expect("force stop");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("server stop deadline")
            .expect("server task joins")
            .expect("server stops cleanly");
    }
}
