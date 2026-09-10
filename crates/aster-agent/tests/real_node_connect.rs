#![cfg(feature = "client")]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use aster_agent::{BoundAgent, ClientToken, proto::aster::application::v1alpha1 as api};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
use buffa::{Message as _, MessageName as _};
use connectrpc::{
    ConnectError, ErrorCode, Protocol,
    client::{ClientConfig, Http2Connection, HttpClient},
};

const TEST_TOKEN: &[u8] = b"real-node-connect-test-token-0001";

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestState(PathBuf);

impl TestState {
    fn new() -> Self {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-agent-real-node-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated state root");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect isolated state root");
        Self(path)
    }
}

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

fn assert_authentication_error(error: &ConnectError, expected_type_url: &str) {
    assert_eq!(error.code, ErrorCode::Unauthenticated);
    assert_eq!(error.message.as_deref(), Some("authentication failed"));
    assert_eq!(error.details.len(), 1);
    let wire_detail = &error.details[0];
    assert_eq!(wire_detail.type_url, expected_type_url);
    assert!(wire_detail.debug.is_none());
    let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(
        wire_detail.value.as_deref().expect("encoded public detail"),
    ))
    .expect("decodable public authentication detail");
    assert_eq!(detail.reason, api::PublicErrorReason::AuthenticationFailed);
    assert_eq!(detail.operation, "unspecified");
    assert!(!detail.retryable);
    assert_eq!(detail.retry_delay_ms, None);
}

#[test]
fn connect_client_uses_the_real_live_event_authority() {
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

        let unauthenticated_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().expect("agent base URI")),
        );
        let error = unauthenticated_client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::FULL_NAME);
        let mut unauthenticated_stream = unauthenticated_client
            .stream_events(api::StreamEventsRequest {
                subscription_id: vec![0; 32],
                delivery_limit: 1,
                scan_limit: 1,
                poll_backoff_ms: 250,
                ..Default::default()
            })
            .await
            .expect("stream response carries protocol error");
        let stream_error = unauthenticated_stream
            .message()
            .await
            .expect_err("missing streaming credentials must fail");
        assert_authentication_error(&stream_error, api::PublicErrorDetail::FULL_NAME);

        let base_uri = format!("http://{address}");
        let unauthenticated_grpc_web = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(base_uri.parse().expect("gRPC-Web client URI"))
                .with_protocol(Protocol::GrpcWeb),
        );
        let error = unauthenticated_grpc_web
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing gRPC-Web credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::TYPE_URL);

        let grpc =
            Http2Connection::connect_plaintext(base_uri.parse().expect("gRPC transport URI"))
                .await
                .expect("connect gRPC HTTP/2 transport")
                .shared(32);
        let unauthenticated_grpc = api::AsterApplicationServiceClient::new(
            grpc.clone(),
            ClientConfig::new(base_uri.parse().expect("unauthenticated gRPC client URI"))
                .with_protocol(Protocol::Grpc),
        );
        let error = unauthenticated_grpc
            .get_status(api::GetStatusRequest::default())
            .await
            .expect_err("missing gRPC credentials must fail");
        assert_authentication_error(&error, api::PublicErrorDetail::TYPE_URL);

        let client = api::AsterApplicationServiceClient::new(
            grpc,
            ClientConfig::new(base_uri.parse().expect("gRPC client URI"))
                .with_protocol(Protocol::Grpc)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let status = client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("read real status")
            .into_owned();
        assert_eq!(status.identity.len(), 32);
        assert_eq!(status.mission_authority.len(), 32);

        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                operation_key: b"connect-real-subscription".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                include_descendant_scopes: false,
                ..Default::default()
            })
            .await
            .expect("create durable subscription")
            .into_owned();
        assert!(subscription.inserted);

        let published = client
            .publish_event(api::PublishEventRequest {
                operation_key: b"connect-real-publication".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Immediate.into(),
                logical_key: b"message-1".to_vec(),
                payload: b"offline-first through ConnectRPC".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish through ConnectRPC")
            .into_owned();
        assert!(published.inserted);
        assert_eq!(published.id.len(), 32);

        let page = client
            .poll_events(api::PollEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                ..Default::default()
            })
            .await
            .expect("poll through ConnectRPC")
            .into_owned();
        assert_eq!(page.deliveries.len(), 1);
        let event = page.deliveries[0]
            .event
            .as_option()
            .expect("delivery event");
        assert_eq!(event.id, published.id);
        assert_eq!(event.payload, b"offline-first through ConnectRPC");
        assert_eq!(page.deliveries[0].attempt, 1);

        let acknowledgement = client
            .acknowledge_event(api::AcknowledgeEventRequest {
                subscription_id: subscription.subscription_id.clone(),
                event_id: published.id,
                ..Default::default()
            })
            .await
            .expect("acknowledge through ConnectRPC")
            .into_owned();
        assert!(!acknowledgement.already_acknowledged);

        let mut stream = client
            .stream_events(api::StreamEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                poll_backoff_ms: 250,
                ..Default::default()
            })
            .await
            .expect("start durable delivery stream");
        let streamed_publication = client
            .publish_event(api::PublishEventRequest {
                operation_key: b"connect-stream-publication".to_vec(),
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Routine.into(),
                logical_key: b"message-2".to_vec(),
                payload: b"streamed without implicit acknowledgement".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish for stream")
            .into_owned();
        let streamed = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("stream delivery timeout")
            .expect("stream protocol")
            .expect("stream delivery")
            .to_owned_message();
        assert_eq!(streamed.attempt, 1);
        assert_eq!(
            streamed.event.as_option().expect("streamed event").id,
            streamed_publication.id
        );
        drop(stream);

        let redelivery = client
            .poll_events(api::PollEventsRequest {
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                ..Default::default()
            })
            .await
            .expect("poll unacknowledged streamed delivery")
            .into_owned();
        assert_eq!(redelivery.deliveries.len(), 1);
        assert_eq!(redelivery.deliveries[0].attempt, 2);
        assert_eq!(
            redelivery.deliveries[0]
                .event
                .as_option()
                .expect("redelivered event")
                .id,
            streamed_publication.id
        );
        client
            .acknowledge_event(api::AcknowledgeEventRequest {
                subscription_id: subscription.subscription_id,
                event_id: streamed_publication.id,
                ..Default::default()
            })
            .await
            .expect("acknowledge redelivery");

        shutdown_tx.send(true).expect("request agent shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("agent shutdown timeout")
            .expect("agent task")
            .expect("agent serve");
        node.shutdown().await.expect("node shutdown");
    });
}
