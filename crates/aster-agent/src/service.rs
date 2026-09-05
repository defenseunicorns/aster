use std::{collections::VecDeque, sync::Arc, time::Duration};

use aster_node::application::{
    AuthenticatedPeerStatus, ContactSyncStatus as NodeContactSyncStatus, EventAcknowledgement,
    EventDelivery as NodeEventDelivery, EventGap as NodeEventGap, EventGapQuery, EventId,
    EventItem, EventPollRequest, EventPublishRequest, EventPublishResult, EventQuery,
    EventSubscriptionId, EventSubscriptionRequest, EventSyncStatus as NodeEventSyncStatus,
    EventUnsubscribe, PeerAuthorization as NodePeerAuthorization, Priority as NodePriority, Scope,
    SelectedEventHandle, SelectedEventStatus, Topic,
};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};

use crate::{
    MAX_AGENT_RESPONSE_PROTO_BYTES, MAX_STREAM_BACKOFF_MS, MIN_STREAM_BACKOFF_MS, api,
    error::{PublicOperation, connect_application_error, public_error},
};

use api::AsterApplicationServiceExt as _;

/// High-level ConnectRPC service backed by the running node's sole authority.
#[derive(Clone)]
pub(crate) struct AsterConnectService {
    events: SelectedEventHandle,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl AsterConnectService {
    /// Creates a service over one live Event handle.
    pub(crate) fn new(
        events: SelectedEventHandle,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self { events, shutdown }
    }

    /// Builds the protocol router without exposing node internals.
    pub(crate) fn router(self) -> connectrpc::Router {
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
        bounded_response(
            status_response(
                self.events.identity(),
                self.events.mission_authority(),
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

    use super::*;
    use crate::{BoundAgent, ClientToken, api, error::PublicOperation};

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
        code: ErrorCode,
        reason: api::PublicErrorReason,
        operation: &str,
        retryable: bool,
    ) {
        assert_eq!(error.code, code);
        assert_eq!(error.details.len(), 1);
        let detail = &error.details[0];
        assert_eq!(
            detail.type_url,
            "aster.application.v1alpha1.PublicErrorDetail"
        );
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
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::UnsupportedValue,
            "publish_event",
            false,
        );

        let identifier_error = parse_event_id(&[0x5a; 31], PublicOperation::AcknowledgeEvent)
            .expect_err("short identifier");
        assert_public_detail(
            &identifier_error,
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
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "query_events",
            true,
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

            for protocol in [Protocol::Connect, Protocol::GrpcWeb] {
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
