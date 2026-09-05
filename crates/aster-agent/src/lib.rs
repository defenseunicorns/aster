//! Process-local ConnectRPC application boundary for a running Aster node.
//!
//! The service is intentionally narrower than the durable data model. Only
//! operations backed by the live selected-Event handle are exposed. In
//! particular, this crate never opens the node's store and never exposes
//! transport, reconciliation, cryptographic, sealed, or provisioning details.

#![forbid(unsafe_code)]

pub mod config;
pub mod credentials;

pub use credentials::ClientToken;

use std::{collections::VecDeque, sync::Arc, time::Duration};

use aster_node::application::{
    ApplicationError, ApplicationErrorKind, AuthenticatedPeerStatus,
    ContactSyncStatus as NodeContactSyncStatus, EventAcknowledgement,
    EventDelivery as NodeEventDelivery, EventGap as NodeEventGap, EventGapQuery, EventId,
    EventItem, EventPollRequest, EventPublishRequest, EventPublishResult, EventQuery,
    EventSubscriptionId, EventSubscriptionRequest, EventSyncStatus as NodeEventSyncStatus,
    EventUnsubscribe, PeerAuthorization as NodePeerAuthorization, Priority as NodePriority, Scope,
    SelectedEventHandle, SelectedEventStatus, Topic,
};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};

/// Generated, repository-owned application protocol.
pub mod proto {
    connectrpc::include_generated!();
}

use api::AsterApplicationServiceExt as _;
use proto::aster::application::v1alpha1 as api;

/// Maximum accepted request body and decoded protobuf message size.
pub const MAX_AGENT_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum protobuf element-memory budget for one decode.
pub const MAX_AGENT_ELEMENT_MEMORY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded protobuf response before protocol-specific framing.
pub const MAX_AGENT_RESPONSE_PROTO_BYTES: u32 = 2 * 1024 * 1024;
/// Minimum accepted delay following any delivered or caught-up streaming poll.
pub const MIN_STREAM_BACKOFF_MS: u32 = 100;
/// Maximum accepted delay following any delivered or caught-up streaming poll.
pub const MAX_STREAM_BACKOFF_MS: u32 = 60_000;

#[derive(Clone)]
struct BearerAuth {
    token: ClientToken,
}

impl BearerAuth {
    fn authorize(&self, ctx: &RequestContext) -> Result<(), ConnectError> {
        if self
            .token
            .authorizes(ctx.header("authorization").map(|value| value.as_bytes()))
        {
            Ok(())
        } else {
            Err(ConnectError::unauthenticated(
                "valid local client authentication is required",
            ))
        }
    }
}

#[connectrpc::async_trait]
impl connectrpc::Interceptor for BearerAuth {
    async fn intercept_unary(
        &self,
        request: connectrpc::interceptor::UnaryRequest,
        next: connectrpc::Next<'_>,
    ) -> Result<connectrpc::interceptor::UnaryResponse, ConnectError> {
        self.authorize(&request.ctx)?;
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        request: connectrpc::interceptor::StreamRequest,
        inbound: connectrpc::PayloadStream,
        next: connectrpc::NextStream<'_>,
    ) -> Result<connectrpc::interceptor::StreamResponse, ConnectError> {
        self.authorize(&request.ctx)?;
        next.run(request, inbound).await
    }
}

/// High-level ConnectRPC service backed by the running node's sole authority.
#[derive(Clone)]
struct AsterConnectService {
    events: SelectedEventHandle,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl AsterConnectService {
    /// Creates a service over one live Event handle.
    fn new(events: SelectedEventHandle, shutdown: tokio::sync::watch::Receiver<bool>) -> Self {
        Self { events, shutdown }
    }

    /// Builds the protocol router without exposing node internals.
    fn router(self) -> connectrpc::Router {
        Arc::new(self).register(connectrpc::Router::new())
    }
}

#[allow(refining_impl_trait)]
impl api::AsterApplicationService for AsterConnectService {
    async fn get_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, api::GetStatusRequest>,
    ) -> ServiceResult<api::GetStatusResponse> {
        let status = self
            .events
            .status()
            .await
            .map_err(connect_application_error)?;
        bounded_response(status_response(
            self.events.identity(),
            self.events.mission_authority(),
            status,
        ))
    }

    async fn publish_event(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::PublishEventRequest>,
    ) -> ServiceResult<api::PublishEventResponse> {
        let request = request.to_owned_message();
        let result = self
            .events
            .publish(publish_request(request)?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(publish_response(result))
    }

    async fn query_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::QueryEventsRequest>,
    ) -> ServiceResult<api::QueryEventsResponse> {
        let page = self
            .events
            .query(query_request(request.to_owned_message())?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::QueryEventsResponse {
            events: page.items.into_iter().map(event_message).collect(),
            scanned_through: page.scanned_through,
            has_more: page.has_more,
            ..Default::default()
        })
    }

    async fn create_event_subscription(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::CreateEventSubscriptionRequest>,
    ) -> ServiceResult<api::CreateEventSubscriptionResponse> {
        let request = request.to_owned_message();
        let subscription = self
            .events
            .subscribe(EventSubscriptionRequest {
                operation_key: request.operation_key,
                topic: parse_topic(request.topic)?,
                scope: parse_scope(request.scope)?,
                include_descendant_scopes: request.include_descendant_scopes,
            })
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::CreateEventSubscriptionResponse {
            subscription_id: subscription.id.as_bytes().to_vec(),
            inserted: subscription.inserted,
            ..Default::default()
        })
    }

    async fn poll_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::PollEventsRequest>,
    ) -> ServiceResult<api::PollEventsResponse> {
        let request = request.to_owned_message();
        let page = self
            .events
            .poll(poll_request(
                request.subscription_id,
                request.delivery_limit,
                request.scan_limit,
            )?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::PollEventsResponse {
            deliveries: page.deliveries.into_iter().map(delivery_message).collect(),
            has_more: page.has_more,
            ..Default::default()
        })
    }

    async fn stream_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::StreamEventsRequest>,
    ) -> ServiceResult<ServiceStream<api::StreamEventsResponse>> {
        let request = request.to_owned_message();
        if !(MIN_STREAM_BACKOFF_MS..=MAX_STREAM_BACKOFF_MS).contains(&request.poll_backoff_ms) {
            return Err(ConnectError::invalid_argument(
                "poll_backoff_ms is outside the supported range",
            ));
        }
        let poll = poll_request(
            request.subscription_id,
            request.delivery_limit,
            request.scan_limit,
        )?;
        let state = EventStreamState {
            events: self.events.clone(),
            subscription: poll.subscription,
            delivery_limit: poll.delivery_limit,
            scan_limit: poll.scan_limit,
            backoff: Duration::from_millis(u64::from(request.poll_backoff_ms)),
            pending: VecDeque::new(),
            backoff_before_poll: false,
            shutdown: self.shutdown.clone(),
            stopped: false,
        };
        Response::stream_ok(futures::stream::unfold(state, next_stream_delivery))
    }

    async fn acknowledge_event(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::AcknowledgeEventRequest>,
    ) -> ServiceResult<api::AcknowledgeEventResponse> {
        let request = request.to_owned_message();
        let result = self
            .events
            .acknowledge(
                parse_subscription_id(&request.subscription_id)?,
                parse_event_id(&request.event_id)?,
            )
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::AcknowledgeEventResponse {
            already_acknowledged: matches!(result, EventAcknowledgement::AlreadyAcknowledged),
            ..Default::default()
        })
    }

    async fn delete_event_subscription(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::DeleteEventSubscriptionRequest>,
    ) -> ServiceResult<api::DeleteEventSubscriptionResponse> {
        let request = request.to_owned_message();
        let result = self
            .events
            .unsubscribe(parse_subscription_id(&request.subscription_id)?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::DeleteEventSubscriptionResponse {
            already_absent: matches!(result, EventUnsubscribe::AlreadyAbsent),
            ..Default::default()
        })
    }

    async fn query_event_gaps(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::QueryEventGapsRequest>,
    ) -> ServiceResult<api::QueryEventGapsResponse> {
        let request = request.to_owned_message();
        let page = self
            .events
            .gaps(EventGapQuery {
                publisher: parse_node_id(&request.publisher, "publisher")?,
                topic: parse_topic(request.topic)?,
                scope: parse_scope(request.scope)?,
                after_sequence: request.after_sequence,
                scan_limit: parse_limit(request.scan_limit, "scan_limit")?,
            })
            .await
            .map_err(connect_application_error)?;
        bounded_response(api::QueryEventGapsResponse {
            gaps: page.gaps.into_iter().map(gap_message).collect(),
            scanned_through_sequence: page.scanned_through_sequence,
            has_more: page.has_more,
            ..Default::default()
        })
    }
}

struct EventStreamState {
    events: SelectedEventHandle,
    subscription: EventSubscriptionId,
    delivery_limit: usize,
    scan_limit: usize,
    backoff: Duration,
    pending: VecDeque<NodeEventDelivery>,
    backoff_before_poll: bool,
    shutdown: tokio::sync::watch::Receiver<bool>,
    stopped: bool,
}

async fn next_stream_delivery(
    mut state: EventStreamState,
) -> Option<(
    Result<api::StreamEventsResponse, ConnectError>,
    EventStreamState,
)> {
    loop {
        if state.stopped || *state.shutdown.borrow() {
            return None;
        }
        if let Some(delivery) = state.pending.pop_front() {
            return Some((bounded_message(stream_delivery_message(delivery)), state));
        }
        if state.backoff_before_poll {
            tokio::select! {
                () = tokio::time::sleep(state.backoff) => {
                    state.backoff_before_poll = false;
                }
                changed = state.shutdown.changed() => {
                    if changed.is_err() || *state.shutdown.borrow() {
                        return None;
                    }
                    continue;
                }
            }
        }

        let poll = state.events.poll(EventPollRequest {
            subscription: state.subscription,
            delivery_limit: state.delivery_limit,
            scan_limit: state.scan_limit,
        });
        let page = tokio::select! {
            result = poll => result,
            changed = state.shutdown.changed() => {
                if changed.is_err() || *state.shutdown.borrow() {
                    return None;
                }
                continue;
            }
        };
        match page {
            Ok(page) if !page.deliveries.is_empty() => {
                state.pending = page.deliveries.into();
                state.backoff_before_poll = true;
            }
            Ok(page) if page.has_more => tokio::task::yield_now().await,
            Ok(_) => state.backoff_before_poll = true,
            Err(error) => {
                state.stopped = true;
                return Some((Err(connect_application_error(error)), state));
            }
        }
    }
}

fn publish_request(request: api::PublishEventRequest) -> Result<EventPublishRequest, ConnectError> {
    Ok(EventPublishRequest {
        operation_key: request.operation_key,
        predecessor: request
            .predecessor_id
            .as_deref()
            .map(parse_event_id)
            .transpose()?,
        topic: parse_topic(request.topic)?,
        scope: parse_scope(request.scope)?,
        priority: parse_priority(request.priority)?,
        logical_key: request.logical_key,
        payload: request.payload,
        tombstone: request.tombstone,
    })
}

fn query_request(request: api::QueryEventsRequest) -> Result<EventQuery, ConnectError> {
    Ok(EventQuery {
        publisher: request
            .publisher
            .as_deref()
            .map(|value| parse_node_id(value, "publisher"))
            .transpose()?,
        topic: request.topic.map(parse_topic).transpose()?,
        scope: request.scope.map(parse_scope).transpose()?,
        include_descendant_scopes: request.include_descendant_scopes,
        logical_key: request.logical_key,
        after_acceptance_marker: request.after_acceptance_marker,
        limit: parse_limit(request.limit, "limit")?,
    })
}

fn poll_request(
    subscription_id: Vec<u8>,
    delivery_limit: u32,
    scan_limit: u32,
) -> Result<EventPollRequest, ConnectError> {
    Ok(EventPollRequest {
        subscription: parse_subscription_id(&subscription_id)?,
        delivery_limit: parse_limit(delivery_limit, "delivery_limit")?,
        scan_limit: parse_limit(scan_limit, "scan_limit")?,
    })
}

fn publish_response(result: EventPublishResult) -> api::PublishEventResponse {
    api::PublishEventResponse {
        id: result.id.as_bytes().to_vec(),
        publisher: result.publisher.to_vec(),
        publisher_counter: result.publisher_counter,
        event_sequence: result.event_sequence,
        priority: priority_message(result.priority).into(),
        acceptance_marker: result.acceptance_marker,
        inserted: result.inserted,
        ..Default::default()
    }
}

fn event_message(event: EventItem) -> api::Event {
    api::Event {
        id: event.id.as_bytes().to_vec(),
        publisher: event.publisher.to_vec(),
        publisher_counter: event.publisher_counter,
        event_sequence: event.event_sequence,
        topic: event.topic.as_str().to_owned(),
        scope: event.scope.as_str().to_owned(),
        priority: priority_message(event.priority).into(),
        logical_key: event.logical_key,
        payload: event.payload,
        tombstone: event.tombstone,
        acceptance_marker: event.acceptance_marker,
        ..Default::default()
    }
}

fn delivery_message(delivery: NodeEventDelivery) -> api::EventDelivery {
    api::EventDelivery {
        event: event_message(delivery.event).into(),
        attempt: delivery.attempt,
        ..Default::default()
    }
}

fn stream_delivery_message(delivery: NodeEventDelivery) -> api::StreamEventsResponse {
    api::StreamEventsResponse {
        event: event_message(delivery.event).into(),
        attempt: delivery.attempt,
        ..Default::default()
    }
}

fn gap_message(gap: NodeEventGap) -> api::EventGap {
    api::EventGap {
        publisher: gap.publisher.to_vec(),
        topic: gap.topic.as_str().to_owned(),
        scope: gap.scope.as_str().to_owned(),
        start_sequence: gap.start_sequence,
        end_sequence: gap.end_sequence,
        ..Default::default()
    }
}

fn status_response(
    identity: [u8; 32],
    mission_authority: [u8; 32],
    status: SelectedEventStatus,
) -> api::GetStatusResponse {
    api::GetStatusResponse {
        identity: identity.to_vec(),
        mission_authority: mission_authority.to_vec(),
        sync: sync_status_message(status.sync).into(),
        authenticated_contacts: status.authenticated_contacts,
        failed_contact_attempts: status.failed_contact_attempts,
        peers: status.peers.into_iter().map(peer_status_message).collect(),
        ..Default::default()
    }
}

fn peer_status_message(status: AuthenticatedPeerStatus) -> api::PeerStatus {
    let authorization = match status.authorization {
        NodePeerAuthorization::Active => api::PeerAuthorization::Active,
        NodePeerAuthorization::Revoked => api::PeerAuthorization::Revoked,
    };
    let last_contact = match status.last_contact {
        NodeContactSyncStatus::CompleteForLastNegotiatedContact => {
            api::ContactStatus::CompleteForLastNegotiatedContact
        }
        NodeContactSyncStatus::WorkRemained => api::ContactStatus::WorkRemained,
        NodeContactSyncStatus::PolicyChangedSinceContact => {
            api::ContactStatus::PolicyChangedSinceContact
        }
    };
    api::PeerStatus {
        peer: status.peer.to_vec(),
        authorization: authorization.into(),
        authenticated_contacts: status.contacts,
        last_contact: last_contact.into(),
        ..Default::default()
    }
}

fn sync_status_message(status: NodeEventSyncStatus) -> api::SyncStatus {
    match status {
        NodeEventSyncStatus::Offline => api::SyncStatus::Offline,
        NodeEventSyncStatus::NoActiveConfiguredPeers => api::SyncStatus::NoActiveConfiguredPeers,
        NodeEventSyncStatus::AwaitingAuthenticatedContact => {
            api::SyncStatus::AwaitingAuthenticatedContact
        }
        NodeEventSyncStatus::LastContactComplete => api::SyncStatus::LastContactComplete,
        NodeEventSyncStatus::WorkRemained => api::SyncStatus::WorkRemained,
        NodeEventSyncStatus::PolicyChangedSinceContact => {
            api::SyncStatus::PolicyChangedSinceContact
        }
    }
}

fn parse_priority(value: buffa::EnumValue<api::Priority>) -> Result<NodePriority, ConnectError> {
    match value.as_known() {
        Some(api::Priority::Routine) => Ok(NodePriority::Routine),
        Some(api::Priority::Priority) => Ok(NodePriority::Priority),
        Some(api::Priority::Immediate) => Ok(NodePriority::Immediate),
        Some(api::Priority::Flash) => Ok(NodePriority::Flash),
        Some(api::Priority::Unspecified) | None => {
            Err(ConnectError::invalid_argument("priority must be specified"))
        }
    }
}

fn priority_message(priority: NodePriority) -> api::Priority {
    match priority {
        NodePriority::Routine => api::Priority::Routine,
        NodePriority::Priority => api::Priority::Priority,
        NodePriority::Immediate => api::Priority::Immediate,
        NodePriority::Flash => api::Priority::Flash,
    }
}

fn parse_topic(value: String) -> Result<Topic, ConnectError> {
    Topic::new(value).map_err(|_| ConnectError::invalid_argument("topic is not canonical"))
}

fn parse_scope(value: String) -> Result<Scope, ConnectError> {
    Scope::new(value).map_err(|_| ConnectError::invalid_argument("scope is not canonical"))
}

fn parse_limit(value: u32, field: &'static str) -> Result<usize, ConnectError> {
    usize::try_from(value)
        .map_err(|_| ConnectError::invalid_argument(format!("{field} is not representable")))
}

fn parse_node_id(value: &[u8], field: &'static str) -> Result<[u8; 32], ConnectError> {
    value
        .try_into()
        .map_err(|_| ConnectError::invalid_argument(format!("{field} must contain 32 bytes")))
}

fn parse_event_id(value: &[u8]) -> Result<EventId, ConnectError> {
    parse_node_id(value, "event_id").map(EventId::from_bytes)
}

fn parse_subscription_id(value: &[u8]) -> Result<EventSubscriptionId, ConnectError> {
    parse_node_id(value, "subscription_id").map(EventSubscriptionId::from_bytes)
}

fn connect_application_error(error: ApplicationError) -> ConnectError {
    let code = match error.kind() {
        ApplicationErrorKind::InvalidRequest => ErrorCode::InvalidArgument,
        ApplicationErrorKind::RequestRejected | ApplicationErrorKind::UnauthorizedOrRevoked => {
            ErrorCode::PermissionDenied
        }
        ApplicationErrorKind::PolicyUnsettled | ApplicationErrorKind::StateUnavailable => {
            ErrorCode::Unavailable
        }
        ApplicationErrorKind::Conflict => ErrorCode::Aborted,
        ApplicationErrorKind::ResourceLimit => ErrorCode::ResourceExhausted,
        ApplicationErrorKind::Integrity => ErrorCode::DataLoss,
        ApplicationErrorKind::Provisioning => ErrorCode::FailedPrecondition,
        _ => ErrorCode::Internal,
    };
    ConnectError::new(code, error.to_string())
}

fn bounded_response<M: buffa::Message>(message: M) -> ServiceResult<M> {
    Response::ok(bounded_message(message)?)
}

fn bounded_message<M: buffa::Message>(message: M) -> Result<M, ConnectError> {
    let encoded = message.try_encoded_len().map_err(|_| {
        ConnectError::resource_exhausted("response exceeds the protobuf encoding limit")
    })?;
    if encoded > MAX_AGENT_RESPONSE_PROTO_BYTES {
        return Err(ConnectError::resource_exhausted(
            "response is too large; request a smaller page",
        ));
    }
    Ok(message)
}

/// A loopback-bound ConnectRPC listener that has not begun serving.
#[cfg(feature = "server")]
pub struct BoundAgent {
    server: connectrpc::BoundServer,
}

#[cfg(feature = "server")]
impl BoundAgent {
    /// Binds a plaintext listener. Non-loopback addresses fail closed.
    pub async fn bind(
        address: std::net::SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !address.ip().is_loopback() {
            return Err("the plaintext Aster agent may bind only to a loopback address".into());
        }
        Ok(Self {
            server: connectrpc::Server::bind(address).await?,
        })
    }

    /// Returns the exact address selected by the operating system.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.server.local_addr()
    }

    /// Serves until shutdown, closing active streams before transport drain.
    pub async fn serve(
        self,
        events: SelectedEventHandle,
        token: ClientToken,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = AsterConnectService::new(events, shutdown.clone()).router();
        let limits = connectrpc::Limits::default()
            .with_max_request_body_size(MAX_AGENT_MESSAGE_BYTES)
            .with_max_message_size(MAX_AGENT_MESSAGE_BYTES)
            .with_element_memory_limit(MAX_AGENT_ELEMENT_MEMORY_BYTES);
        let deadline = connectrpc::DeadlinePolicy::new()
            .with_min(Duration::from_millis(10))
            .with_max(Duration::from_secs(30))
            .with_default_timeout(Duration::from_secs(10));
        let service = connectrpc::ConnectRpcService::new(router)
            .with_limits(limits)
            .with_deadline_policy(deadline)
            .with_interceptor(BearerAuth { token });
        self.server
            .with_max_concurrent_streams(32)
            .with_max_connection_idle(Duration::from_secs(60))
            .with_max_connection_age(Duration::from_secs(30 * 60))
            .with_max_connection_age_grace(Duration::from_secs(5))
            .with_http2_keepalive_interval(Duration::from_secs(30))
            .with_http2_keepalive_timeout(Duration::from_secs(10))
            .serve_with_service_and_shutdown(service, shutdown_requested(shutdown))
            .await
    }
}

async fn shutdown_requested(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_and_unspecified_priority() {
        assert!(parse_priority(api::Priority::Unspecified.into()).is_err());
        assert!(parse_priority(buffa::EnumValue::Unknown(99)).is_err());
        assert_eq!(
            parse_priority(api::Priority::Flash.into()).expect("known priority"),
            NodePriority::Flash
        );
    }

    #[test]
    fn exact_identifiers_are_required() {
        assert!(parse_event_id(&[0; 31]).is_err());
        assert!(parse_event_id(&[0; 33]).is_err());
        assert_eq!(
            parse_event_id(&[0x5a; 32])
                .expect("exact identifier")
                .as_bytes(),
            &[0x5a; 32]
        );
    }

    #[test]
    fn plaintext_listener_rejects_non_loopback_before_binding() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let error = runtime
            .block_on(BoundAgent::bind("0.0.0.0:0".parse().expect("address")))
            .err()
            .expect("non-loopback must fail");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn client_token_is_exact_and_url_safe() {
        let token = ClientToken::from_bytes(b"0123456789abcdef-._~ABCDEFGHIJKL".to_vec())
            .expect("valid token");
        assert!(token.authorizes(Some(b"Bearer 0123456789abcdef-._~ABCDEFGHIJKL")));
        assert!(!token.authorizes(Some(b"Bearer 0123456789abcdef-._~ABCDEFGHIJKM")));
        assert!(!token.authorizes(Some(b"0123456789abcdef-._~ABCDEFGHIJKL")));
        assert!(ClientToken::from_bytes(vec![b'a'; 31]).is_err());
        assert!(ClientToken::from_bytes(vec![b'a'; 257]).is_err());
        assert!(ClientToken::from_bytes(vec![b' '; 32]).is_err());
    }

    #[test]
    fn oversized_responses_fail_before_protocol_encoding() {
        let error = bounded_message(api::QueryEventsResponse {
            events: vec![api::Event {
                payload: vec![0; MAX_AGENT_RESPONSE_PROTO_BYTES as usize],
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect_err("response budget must include protobuf framing");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }

    #[cfg(unix)]
    #[test]
    fn client_token_file_must_be_owner_only_and_not_a_symlink() {
        use std::os::unix::{fs::PermissionsExt as _, fs::symlink};

        let root = std::env::temp_dir().join(format!(
            "aster-agent-token-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&root).expect("create token test root");
        let path = root.join("token");
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef\n").expect("write token fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set broad fixture mode");
        assert!(ClientToken::load(&path).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("set owner-only fixture mode");
        assert!(ClientToken::load(&path).is_ok());
        let link = root.join("token-link");
        symlink(&path, &link).expect("create token symlink");
        assert!(ClientToken::load(&link).is_err());

        std::fs::remove_dir_all(root).expect("remove token test root");
    }
}
