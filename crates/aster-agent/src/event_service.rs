use std::{collections::VecDeque, sync::Arc, time::Duration};

use aster_node::EventEmissionPolicy;
use aster_node::application::{
    AuthenticatedPeerStatus, ContactSyncStatus as NodeContactSyncStatus, EventAcknowledgement,
    EventDelivery as NodeEventDelivery, EventGap as NodeEventGap, EventGapQuery, EventId,
    EventItem, EventPollRequest, EventPublishRequest, EventPublishResult, EventQuery,
    EventSubscriptionId, EventSubscriptionRequest, EventSyncStatus as NodeEventSyncStatus,
    EventUnsubscribe, PeerAuthorization as NodePeerAuthorization, Priority as NodePriority, Scope,
    SelectedEventHandle, SelectedEventStatus, Topic,
};
use aster_redb_store::{
    MAX_EVENT_OPERATION_BYTES, MAX_EVENT_OPERATIONS, MAX_EVENT_PENDING_DELIVERIES,
};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};

use crate::{
    MAX_AGENT_RESPONSE_PROTO_BYTES, MAX_STREAM_BACKOFF_MS, MIN_STREAM_BACKOFF_MS, api,
    error::{PublicOperation, connect_application_error, public_error},
};

use api::AsterApplicationServiceExt as _;

const APPLICATION_SERVICE_NAME: &str = api::ASTER_APPLICATION_SERVICE_SERVICE_NAME;
const PROFILE_EVENT_OPERATION_WARNING: u64 = 512;
const PROFILE_EVENT_OPERATION_BOUNDARY: u64 = 1_024;
const PROFILE_EVENT_PENDING_DELIVERY_BOUNDARY: u64 = 256;

/// High-level ConnectRPC service backed by the running node's sole authority.
#[derive(Clone)]
pub(crate) struct AsterConnectService {
    events: SelectedEventHandle,
    configured_emission_policy: EventEmissionPolicy,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl AsterConnectService {
    /// Creates a service over one live Event handle.
    pub(crate) fn new(
        events: SelectedEventHandle,
        configured_emission_policy: EventEmissionPolicy,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self {
            events,
            configured_emission_policy,
            shutdown,
        }
    }

    /// Builds the protocol router without exposing node internals.
    pub(crate) fn router(self) -> connectrpc::Router {
        Arc::new(self).register(connectrpc::Router::new())
    }
}

pub(crate) fn application_service(
    events: SelectedEventHandle,
    configured_emission_policy: EventEmissionPolicy,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> connectrpc::ConnectRpcService<connectrpc::Router> {
    configured_service(
        AsterConnectService::new(events, configured_emission_policy, shutdown).router(),
    )
}

pub(crate) fn configured_service(
    router: connectrpc::Router,
) -> connectrpc::ConnectRpcService<connectrpc::Router> {
    let limits = connectrpc::Limits::default()
        .with_max_request_body_size(crate::MAX_AGENT_MESSAGE_BYTES)
        .with_max_message_size(crate::MAX_AGENT_MESSAGE_BYTES)
        .with_element_memory_limit(crate::MAX_AGENT_ELEMENT_MEMORY_BYTES);
    let deadline = connectrpc::DeadlinePolicy::new()
        .with_min(Duration::from_millis(10))
        .with_max(Duration::from_secs(30))
        .with_default_timeout(Duration::from_secs(10))
        .with_enforce_on_streams(true);
    connectrpc::ConnectRpcService::new(router)
        .with_limits(limits)
        .with_deadline_policy(deadline)
}

fn rejection_handler<Req, Res>() -> impl connectrpc::BidiStreamingHandler<Req, Res, Item = Res>
where
    Req: buffa::Message + connectrpc::codec::JsonDeserialize + Send + 'static,
    Res: buffa::Message + connectrpc::codec::JsonSerialize + Send + 'static,
{
    connectrpc::bidi_streaming_handler_fn(|_ctx, _requests: connectrpc::ServiceStream<Req>| async {
        Err::<connectrpc::Response<connectrpc::ServiceStream<Res>>, _>(ConnectError::internal(
            "request rejected",
        ))
    })
}

/// Builds shape-compatible rejection routes. Every route is deliberately
/// registered as bidirectional streaming so gRPC and gRPC-Web can reach the
/// first interceptor with an empty replacement body; that interceptor always
/// rejects before this fallback handler can run.
pub(crate) fn rejection_router() -> connectrpc::Router {
    connectrpc::Router::new()
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "GetStatus",
            rejection_handler::<api::GetStatusRequest, api::GetStatusResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "PublishEvent",
            rejection_handler::<api::PublishEventRequest, api::PublishEventResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "QueryEvents",
            rejection_handler::<api::QueryEventsRequest, api::QueryEventsResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "CreateEventSubscription",
            rejection_handler::<
                api::CreateEventSubscriptionRequest,
                api::CreateEventSubscriptionResponse,
            >(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "PollEvents",
            rejection_handler::<api::PollEventsRequest, api::PollEventsResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "StreamEvents",
            rejection_handler::<api::StreamEventsRequest, api::StreamEventsResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "AcknowledgeEvent",
            rejection_handler::<api::AcknowledgeEventRequest, api::AcknowledgeEventResponse>(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "DeleteEventSubscription",
            rejection_handler::<
                api::DeleteEventSubscriptionRequest,
                api::DeleteEventSubscriptionResponse,
            >(),
        )
        .route_bidi_stream(
            APPLICATION_SERVICE_NAME,
            "QueryEventGaps",
            rejection_handler::<api::QueryEventGapsRequest, api::QueryEventGapsResponse>(),
        )
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
        bounded_response(
            status_response(
                self.events.identity(),
                self.events.mission_authority(),
                self.configured_emission_policy,
                status,
            ),
            PublicOperation::GetStatus,
        )
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
        bounded_response(publish_response(result), PublicOperation::PublishEvent)
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
        bounded_response(
            api::QueryEventsResponse {
                events: page.items.into_iter().map(event_message).collect(),
                scanned_through: page.scanned_through,
                has_more: page.has_more,
                ..Default::default()
            },
            PublicOperation::QueryEvents,
        )
    }

    async fn create_event_subscription(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::CreateEventSubscriptionRequest>,
    ) -> ServiceResult<api::CreateEventSubscriptionResponse> {
        let request = request.to_owned_message();
        let operation = PublicOperation::CreateEventSubscription;
        let subscription = self
            .events
            .subscribe(EventSubscriptionRequest {
                operation_key: request.operation_key,
                topic: parse_topic(request.topic, operation)?,
                scope: parse_scope(request.scope, operation)?,
                include_descendant_scopes: request.include_descendant_scopes,
            })
            .await
            .map_err(connect_application_error)?;
        bounded_response(
            api::CreateEventSubscriptionResponse {
                subscription_id: subscription.id.as_bytes().to_vec(),
                inserted: subscription.inserted,
                ..Default::default()
            },
            operation,
        )
    }

    async fn poll_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::PollEventsRequest>,
    ) -> ServiceResult<api::PollEventsResponse> {
        let request = request.to_owned_message();
        let operation = PublicOperation::PollEvents;
        let page = self
            .events
            .poll(poll_request(
                request.subscription_id,
                request.delivery_limit,
                request.scan_limit,
                operation,
            )?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(
            api::PollEventsResponse {
                deliveries: page.deliveries.into_iter().map(delivery_message).collect(),
                has_more: page.has_more,
                ..Default::default()
            },
            operation,
        )
    }

    async fn stream_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::StreamEventsRequest>,
    ) -> ServiceResult<ServiceStream<api::StreamEventsResponse>> {
        let request = request.to_owned_message();
        let operation = PublicOperation::StreamEvents;
        if !(MIN_STREAM_BACKOFF_MS..=MAX_STREAM_BACKOFF_MS).contains(&request.poll_backoff_ms) {
            return Err(public_error(
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::UnsupportedValue,
                operation,
                false,
                None,
            ));
        }
        let poll = poll_request(
            request.subscription_id,
            request.delivery_limit,
            request.scan_limit,
            operation,
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
        let operation = PublicOperation::AcknowledgeEvent;
        let result = self
            .events
            .acknowledge(
                parse_subscription_id(&request.subscription_id, operation)?,
                parse_event_id(&request.event_id, operation)?,
            )
            .await
            .map_err(connect_application_error)?;
        bounded_response(
            api::AcknowledgeEventResponse {
                already_acknowledged: matches!(result, EventAcknowledgement::AlreadyAcknowledged),
                ..Default::default()
            },
            operation,
        )
    }

    async fn delete_event_subscription(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::DeleteEventSubscriptionRequest>,
    ) -> ServiceResult<api::DeleteEventSubscriptionResponse> {
        let request = request.to_owned_message();
        let operation = PublicOperation::DeleteEventSubscription;
        let result = self
            .events
            .unsubscribe(parse_subscription_id(&request.subscription_id, operation)?)
            .await
            .map_err(connect_application_error)?;
        bounded_response(
            api::DeleteEventSubscriptionResponse {
                already_absent: matches!(result, EventUnsubscribe::AlreadyAbsent),
                ..Default::default()
            },
            operation,
        )
    }

    async fn query_event_gaps(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, api::QueryEventGapsRequest>,
    ) -> ServiceResult<api::QueryEventGapsResponse> {
        let request = request.to_owned_message();
        let operation = PublicOperation::QueryEventGaps;
        let page = self
            .events
            .gaps(EventGapQuery {
                publisher: parse_node_id(&request.publisher, operation)?,
                topic: parse_topic(request.topic, operation)?,
                scope: parse_scope(request.scope, operation)?,
                after_sequence: request.after_sequence,
                scan_limit: parse_limit(request.scan_limit, operation)?,
            })
            .await
            .map_err(connect_application_error)?;
        bounded_response(
            api::QueryEventGapsResponse {
                gaps: page.gaps.into_iter().map(gap_message).collect(),
                scanned_through_sequence: page.scanned_through_sequence,
                has_more: page.has_more,
                ..Default::default()
            },
            operation,
        )
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
            return Some((
                bounded_message(
                    stream_delivery_message(delivery),
                    PublicOperation::StreamEvents,
                ),
                state,
            ));
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
    let operation = PublicOperation::PublishEvent;
    Ok(EventPublishRequest {
        operation_key: request.operation_key,
        predecessor: request
            .predecessor_id
            .as_deref()
            .map(|value| parse_event_id(value, operation))
            .transpose()?,
        topic: parse_topic(request.topic, operation)?,
        scope: parse_scope(request.scope, operation)?,
        priority: parse_priority(request.priority, operation)?,
        logical_key: request.logical_key,
        payload: request.payload,
        tombstone: request.tombstone,
    })
}

fn query_request(request: api::QueryEventsRequest) -> Result<EventQuery, ConnectError> {
    let operation = PublicOperation::QueryEvents;
    Ok(EventQuery {
        publisher: request
            .publisher
            .as_deref()
            .map(|value| parse_node_id(value, operation))
            .transpose()?,
        topic: request
            .topic
            .map(|value| parse_topic(value, operation))
            .transpose()?,
        scope: request
            .scope
            .map(|value| parse_scope(value, operation))
            .transpose()?,
        include_descendant_scopes: request.include_descendant_scopes,
        logical_key: request.logical_key,
        after_acceptance_marker: request.after_acceptance_marker,
        limit: parse_limit(request.limit, operation)?,
    })
}

fn poll_request(
    subscription_id: Vec<u8>,
    delivery_limit: u32,
    scan_limit: u32,
    operation: PublicOperation,
) -> Result<EventPollRequest, ConnectError> {
    Ok(EventPollRequest {
        subscription: parse_subscription_id(&subscription_id, operation)?,
        delivery_limit: parse_limit(delivery_limit, operation)?,
        scan_limit: parse_limit(scan_limit, operation)?,
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
    configured_emission_policy: EventEmissionPolicy,
    status: SelectedEventStatus,
) -> api::GetStatusResponse {
    let profile_remaining =
        PROFILE_EVENT_OPERATION_BOUNDARY.saturating_sub(status.event_operations);
    api::GetStatusResponse {
        identity: identity.to_vec(),
        mission_authority: mission_authority.to_vec(),
        sync: sync_status_message(status.sync).into(),
        authenticated_contacts: status.authenticated_contacts,
        failed_contact_attempts: status.failed_contact_attempts,
        peers: status.peers.into_iter().map(peer_status_message).collect(),
        configured_emission_mode: emission_mode_message(configured_emission_policy).into(),
        effective_emission_mode: emission_mode_message(status.emission_policy).into(),
        store_capacity: api::StoreCapacityStatus {
            items: status.store_usage.items,
            item_limit: status.store_limits.max_items(),
            payload_bytes: status.store_usage.payload_bytes,
            payload_byte_limit: status.store_limits.max_total_payload_bytes(),
            ..Default::default()
        }
        .into(),
        publish_operation_capacity: api::PublishOperationCapacityStatus {
            rows: status.event_operations,
            bytes: status.event_operation_bytes,
            row_hard_limit: MAX_EVENT_OPERATIONS,
            byte_hard_limit: MAX_EVENT_OPERATION_BYTES,
            profile_boundary: PROFILE_EVENT_OPERATION_BOUNDARY,
            profile_remaining,
            profile_warning: status.event_operations >= PROFILE_EVENT_OPERATION_WARNING,
            profile_exhausted: status.event_operations >= PROFILE_EVENT_OPERATION_BOUNDARY,
            ..Default::default()
        }
        .into(),
        delivery_capacity: api::DeliveryCapacityStatus {
            pending: status.pending_deliveries,
            profile_boundary: PROFILE_EVENT_PENDING_DELIVERY_BOUNDARY,
            profile_saturated: status.pending_deliveries >= PROFILE_EVENT_PENDING_DELIVERY_BOUNDARY,
            hard_limit: MAX_EVENT_PENDING_DELIVERIES,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

fn emission_mode_message(policy: EventEmissionPolicy) -> api::EmissionMode {
    match policy {
        EventEmissionPolicy::Normal => api::EmissionMode::Normal,
        EventEmissionPolicy::ReceiveOnly => api::EmissionMode::ReceiveOnly,
        EventEmissionPolicy::AtLeast(_) => api::EmissionMode::Unspecified,
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

fn parse_priority(
    value: buffa::EnumValue<api::Priority>,
    operation: PublicOperation,
) -> Result<NodePriority, ConnectError> {
    match value.as_known() {
        Some(api::Priority::Routine) => Ok(NodePriority::Routine),
        Some(api::Priority::Priority) => Ok(NodePriority::Priority),
        Some(api::Priority::Immediate) => Ok(NodePriority::Immediate),
        Some(api::Priority::Flash) => Ok(NodePriority::Flash),
        Some(api::Priority::Unspecified) | None => Err(public_error(
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::UnsupportedValue,
            operation,
            false,
            None,
        )),
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

fn malformed_input(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::MalformedInput,
        operation,
        false,
        None,
    )
}

fn parse_topic(value: String, operation: PublicOperation) -> Result<Topic, ConnectError> {
    Topic::new(value).map_err(|_| malformed_input(operation))
}

fn parse_scope(value: String, operation: PublicOperation) -> Result<Scope, ConnectError> {
    Scope::new(value).map_err(|_| malformed_input(operation))
}

fn parse_limit(value: u32, operation: PublicOperation) -> Result<usize, ConnectError> {
    usize::try_from(value).map_err(|_| malformed_input(operation))
}

fn parse_node_id(value: &[u8], operation: PublicOperation) -> Result<[u8; 32], ConnectError> {
    value.try_into().map_err(|_| malformed_input(operation))
}

fn parse_event_id(value: &[u8], operation: PublicOperation) -> Result<EventId, ConnectError> {
    parse_node_id(value, operation).map(EventId::from_bytes)
}

fn parse_subscription_id(
    value: &[u8],
    operation: PublicOperation,
) -> Result<EventSubscriptionId, ConnectError> {
    parse_node_id(value, operation).map(EventSubscriptionId::from_bytes)
}

fn bounded_response<M: buffa::Message>(message: M, operation: PublicOperation) -> ServiceResult<M> {
    Response::ok(bounded_message(message, operation)?)
}

fn bounded_message<M: buffa::Message>(
    message: M,
    operation: PublicOperation,
) -> Result<M, ConnectError> {
    let encoded = message.try_encoded_len().map_err(|_| {
        public_error(
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            operation,
            true,
            None,
        )
    })?;
    if encoded > MAX_AGENT_RESPONSE_PROTO_BYTES {
        return Err(public_error(
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            operation,
            true,
            None,
        ));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "client", feature = "server", unix))]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(all(feature = "client", feature = "server"))]
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use buffa::Message as _;
    use connectrpc::{ConnectError, ErrorCode};
    #[cfg(all(feature = "client", feature = "server"))]
    use connectrpc::{
        Protocol,
        client::{ClientConfig, Http2Connection, HttpClient},
    };

    #[cfg(all(feature = "client", feature = "server"))]
    use aster_node::mission::UnprotectedReferenceMission;
    #[cfg(all(feature = "client", feature = "server"))]
    use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
    use aster_redb_store::{AggregateStoreUsage, StoreLimits};

    use super::*;
    #[cfg(all(feature = "client", feature = "server"))]
    use crate::{BoundAgent, ClientToken};
    use crate::{api, error::PublicOperation};

    #[cfg(all(feature = "client", feature = "server"))]
    const TEST_TOKEN: &[u8] = b"public-error-protocol-test-token";
    #[cfg(all(feature = "client", feature = "server"))]
    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    #[cfg(all(feature = "client", feature = "server"))]
    struct TestState(PathBuf);

    #[cfg(all(feature = "client", feature = "server"))]
    impl TestState {
        fn new() -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-agent-public-errors-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated state root");
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect isolated state root");
            Self(path)
        }
    }

    #[cfg(all(feature = "client", feature = "server"))]
    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
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

    fn assert_public_detail(
        error: &ConnectError,
        expected_type_url: &str,
        code: ErrorCode,
        reason: api::PublicErrorReason,
        operation: &str,
        retryable: bool,
    ) {
        assert_eq!(error.code, code);
        assert_eq!(error.details.len(), 1);
        let detail = &error.details[0];
        assert_eq!(detail.type_url, expected_type_url);
        assert!(detail.debug.is_none());
        let wire = decode_base64(detail.value.as_deref().expect("encoded detail"));
        let decoded =
            api::PublicErrorDetail::decode_from_slice(&wire).expect("valid public detail");
        assert_eq!(decoded.reason, reason);
        assert_eq!(decoded.operation, operation);
        assert_eq!(decoded.retryable, retryable);
        assert_eq!(decoded.retry_delay_ms, None);
    }

    #[test]
    fn parser_failures_use_closed_operations_and_never_echo_rejected_values() {
        let invalid_topic = "customer secret topic";
        let topic_error = parse_topic(invalid_topic.to_owned(), PublicOperation::PublishEvent)
            .expect_err("non-canonical topic");
        assert_public_detail(
            &topic_error,
            "aster.application.v1alpha1.PublicErrorDetail",
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::MalformedInput,
            "publish_event",
            false,
        );
        assert!(!format!("{topic_error:?}").contains(invalid_topic));

        let priority_error =
            parse_priority(buffa::EnumValue::Unknown(71), PublicOperation::PublishEvent)
                .expect_err("unsupported priority");
        assert_public_detail(
            &priority_error,
            "aster.application.v1alpha1.PublicErrorDetail",
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::UnsupportedValue,
            "publish_event",
            false,
        );

        let identifier_error = parse_event_id(&[0x5a; 31], PublicOperation::AcknowledgeEvent)
            .expect_err("short identifier");
        assert_public_detail(
            &identifier_error,
            "aster.application.v1alpha1.PublicErrorDetail",
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::MalformedInput,
            "acknowledge_event",
            false,
        );
    }

    #[test]
    fn response_limit_uses_the_resource_exhaustion_contract() {
        let error = bounded_message(
            api::QueryEventsResponse {
                events: vec![api::Event {
                    payload: vec![0; crate::MAX_AGENT_RESPONSE_PROTO_BYTES as usize],
                    ..Default::default()
                }],
                ..Default::default()
            },
            PublicOperation::QueryEvents,
        )
        .expect_err("response budget must include protobuf framing");
        assert_public_detail(
            &error,
            "aster.application.v1alpha1.PublicErrorDetail",
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "query_events",
            true,
        );
    }

    #[test]
    fn status_reports_configured_effective_mode_and_capacity_headroom() {
        let response = status_response(
            [0x11; 32],
            [0x22; 32],
            EventEmissionPolicy::Normal,
            SelectedEventStatus {
                event_operation_audit: Default::default(),
                sync: NodeEventSyncStatus::Offline,
                authenticated_contacts: 0,
                failed_contact_attempts: 0,
                peers: Vec::new(),
                emission_policy: EventEmissionPolicy::ReceiveOnly,
                store_usage: AggregateStoreUsage::default(),
                store_limits: StoreLimits::new(10_000, 64 * 1024 * 1024).expect("limits"),
                event_operations: 0,
                event_operation_bytes: 0,
                pending_deliveries: 0,
            },
        );

        assert_eq!(response.configured_emission_mode, api::EmissionMode::Normal);
        assert_eq!(
            response.effective_emission_mode,
            api::EmissionMode::ReceiveOnly
        );
        assert_eq!(
            response.store_capacity.as_option(),
            Some(&api::StoreCapacityStatus {
                items: 0,
                item_limit: 10_000,
                payload_bytes: 0,
                payload_byte_limit: 64 * 1024 * 1024,
                ..Default::default()
            })
        );
        assert_eq!(
            response.publish_operation_capacity.as_option(),
            Some(&api::PublishOperationCapacityStatus {
                rows: 0,
                bytes: 0,
                row_hard_limit: 4_096,
                byte_hard_limit: 524_288,
                profile_boundary: 1_024,
                profile_remaining: 1_024,
                profile_warning: false,
                profile_exhausted: false,
                ..Default::default()
            })
        );
        assert_eq!(
            response.delivery_capacity.as_option(),
            Some(&api::DeliveryCapacityStatus {
                pending: 0,
                profile_boundary: 256,
                profile_saturated: false,
                hard_limit: 262_144,
                ..Default::default()
            })
        );
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[test]
    fn public_detail_decodes_after_connect_grpc_and_grpc_web_transport() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let state = TestState::new();
            let mission = UnprotectedReferenceMission::from_bytes(
                include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                    .to_vec(),
            )
            .expect("load disposable public test mission");
            let node = start_node(NodeConfig {
                state: state.0.clone(),
                bind: "127.0.0.1:0".parse().expect("mesh bind"),
                mission,
                peers: Vec::new(),
                mutable_interests: MutableSourceInterests::default(),
                sync_interval: Duration::from_millis(50),
                run_for: None,
                application: NodeApplication::Relay,
            })
            .await
            .expect("start real selected node");

            let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
                .await
                .expect("bind agent");
            let address = agent.local_addr().expect("agent address");
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let token = ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid test token");
            let server = tokio::spawn(agent.serve(node.selected_events(), token, shutdown_rx));
            let base_uri = format!("http://{address}");

            for (protocol, expected_type_url) in [
                (
                    Protocol::Connect,
                    <api::PublicErrorDetail as buffa::MessageName>::FULL_NAME,
                ),
                (Protocol::GrpcWeb, api::PublicErrorDetail::TYPE_URL),
            ] {
                let client = api::AsterApplicationServiceClient::new(
                    HttpClient::plaintext(),
                    ClientConfig::new(base_uri.parse().expect("client URI"))
                        .with_protocol(protocol)
                        .with_default_header(
                            "authorization",
                            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                        ),
                );
                let error = client
                    .publish_event(api::PublishEventRequest {
                        topic: "transport canary topic".to_owned(),
                        scope: "mission/team/alpha".to_owned(),
                        priority: api::Priority::Routine.into(),
                        ..Default::default()
                    })
                    .await
                    .expect_err("malformed topic must fail");
                assert_public_detail(
                    &error,
                    expected_type_url,
                    ErrorCode::InvalidArgument,
                    api::PublicErrorReason::MalformedInput,
                    "publish_event",
                    false,
                );
                assert!(!format!("{error:?}").contains("transport canary topic"));
            }

            let grpc =
                Http2Connection::connect_plaintext(base_uri.parse().expect("gRPC transport URI"))
                    .await
                    .expect("connect gRPC HTTP/2 transport")
                    .shared(8);
            let grpc_client = api::AsterApplicationServiceClient::new(
                grpc,
                ClientConfig::new(base_uri.parse().expect("gRPC client URI"))
                    .with_protocol(Protocol::Grpc)
                    .with_default_header(
                        "authorization",
                        format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                    ),
            );
            let error = grpc_client
                .publish_event(api::PublishEventRequest {
                    topic: "transport canary topic".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    ..Default::default()
                })
                .await
                .expect_err("malformed topic must fail");
            assert_public_detail(
                &error,
                api::PublicErrorDetail::TYPE_URL,
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                "publish_event",
                false,
            );
            assert!(!format!("{error:?}").contains("transport canary topic"));

            shutdown_tx.send(true).expect("request agent shutdown");
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("agent shutdown timeout")
                .expect("agent task")
                .expect("agent serve");
            node.shutdown().await.expect("node shutdown");
        });
    }
}
