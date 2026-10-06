#![cfg(feature = "client")]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use aster_agent::{
    BoundAgent, ClientToken,
    proto::aster::application::v1alpha1 as api,
    sdk::{NumberedEventSdk, PublicationJournal, RecoveredState},
};
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

        // Exercise the generated Connect client with authentication as well as
        // the gRPC client above. Borrow actual Aster fields before consuming
        // the response into an independently owned message.
        let connect_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(base_uri.parse().expect("Connect client URI"))
                .with_protocol(Protocol::Connect)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        let response = connect_client
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("read status over authenticated Connect");
        {
            let view = response.view();
            let identity: &[u8] = view.identity;
            let authority: &[u8] = view.mission_authority;
            assert_eq!(identity, status.identity);
            assert_eq!(authority, status.mission_authority);
        }
        let owned: api::GetStatusResponse = response.into_owned();
        drop(connect_client);
        assert_eq!(owned.identity, status.identity);
        assert_eq!(owned.mission_authority, status.mission_authority);

        // Tracer exercises the real route independently of generated types.
        {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect");
            let request = format!("POST /aster.application.v1alpha1.AsterApplicationService/ListEventSubscriptions HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nConnect-Protocol-Version: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}", String::from_utf8_lossy(TEST_TOKEN));
            stream.write_all(request.as_bytes()).await.expect("write request");
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.expect("read response");
            let response = String::from_utf8(bytes).expect("HTTP JSON");
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }

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
        let listed = client.list_event_subscriptions(api::ListEventSubscriptionsRequest::default()).await.expect("list subscriptions").into_owned();
        assert_eq!(listed.subscriptions.len(), 1);
        let row = &listed.subscriptions[0];
        assert_eq!(row.subscription_id, subscription.subscription_id);
        assert_eq!(row.operation_key, b"connect-real-subscription");
        assert_eq!(row.topic, "chat.events");
        assert_eq!(row.scope, "mission/team/alpha");
        assert!(!row.include_descendant_scopes);

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

#[tokio::test]
async fn query_filters_preserve_scan_cursors_across_empty_rpc_pages() {
    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .unwrap();
    let node = start_node(NodeConfig {
        state: state.0.clone(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(50),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .unwrap();
    let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = agent.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
        shutdown_rx,
    ));
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        ),
    );
    let publisher = client
        .get_status(api::GetStatusRequest::default())
        .await
        .unwrap()
        .into_owned()
        .identity;
    let empty = client
        .query_events(api::QueryEventsRequest {
            limit: 2,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert!(empty.events.is_empty());
    assert_eq!(empty.scanned_through, 0);
    assert!(!empty.has_more);
    let mut published = Vec::new();
    for index in 1..=7 {
        published.push(
            client
                .publish_event(api::PublishEventRequest {
                    operation_key: format!("query/{index}").into_bytes(),
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    logical_key: if index == 3 || index == 6 {
                        b"target".to_vec()
                    } else {
                        b"other".to_vec()
                    },
                    payload: format!("payload {index}").into_bytes(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned()
                .id,
        );
    }
    // Decode field 8 directly to pin its wire number and exercise forwarding
    // through the client's protobuf encoder and the real HTTP service.
    let mut bounded = api::QueryEventsRequest::decode_from_slice(&[0x40, 4]).unwrap();
    bounded.limit = 8;
    let page = client.query_events(bounded).await.unwrap().into_owned();
    assert_eq!(
        page.events
            .iter()
            .map(|event| event.acceptance_marker)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(page.scanned_through, 3);
    assert!(!page.has_more);

    for (after, before) in [(0, 0), (0, 1), (3, 3), (4, 2), (u64::MAX, u64::MAX)] {
        let page = client
            .query_events(api::QueryEventsRequest {
                after_acceptance_marker: after,
                before_acceptance_marker: Some(before),
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(page.events.is_empty(), "after={after}, before={before}");
        assert_eq!(page.scanned_through, after);
        assert!(!page.has_more);
    }

    // Combined exclusive bounds, a full final page, and filters that return
    // empty pages must all stop at the upper bound, not the store high-water.
    for (after, before, key, expected, scanned, more) in [
        (1, 4, None, vec![2, 3], 3, false),
        (1, 5, None, vec![2, 3], 3, true),
        (3, 5, None, vec![4], 4, false),
        (1, 5, Some(b"absent".to_vec()), vec![], 3, true),
        (3, 5, Some(b"absent".to_vec()), vec![], 4, false),
        (1, 4, Some(b"target".to_vec()), vec![3], 3, false),
        (6, 8, None, vec![7], 7, false),
        (6, u64::MAX, None, vec![7], 7, false),
        (u64::MAX, u64::MAX, None, vec![], u64::MAX, false),
    ] {
        let page = client
            .query_events(api::QueryEventsRequest {
                publisher: Some(publisher.clone()),
                topic: Some("chat.events".to_owned()),
                scope: Some("mission/team".to_owned()),
                include_descendant_scopes: true,
                logical_key: key,
                after_acceptance_marker: after,
                before_acceptance_marker: Some(before),
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.acceptance_marker)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(page.scanned_through, scanned);
        assert_eq!(page.has_more, more);
    }

    for (key, expected_pages) in [
        (None, vec![vec![1, 2], vec![3, 4], vec![5, 6], vec![7]]),
        (
            Some(b"absent".to_vec()),
            vec![vec![], vec![], vec![], vec![]],
        ),
        (
            Some(b"target".to_vec()),
            vec![vec![], vec![3], vec![6], vec![]],
        ),
    ] {
        let mut cursor = 0;
        for (page_index, expected) in expected_pages.into_iter().enumerate() {
            let page = client
                .query_events(api::QueryEventsRequest {
                    // Test the completely unfiltered path too. On selective paths,
                    // combine every RPC field and an ancestor scope.
                    publisher: key.as_ref().map(|_| publisher.clone()),
                    topic: key.as_ref().map(|_| "chat.events".to_owned()),
                    scope: key.as_ref().map(|_| "mission/team".to_owned()),
                    include_descendant_scopes: key.is_some(),
                    logical_key: key.clone(),
                    after_acceptance_marker: cursor,
                    limit: 2,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned();
            assert_eq!(
                page.events
                    .iter()
                    .map(|event| event.acceptance_marker)
                    .collect::<Vec<_>>(),
                expected
            );
            for event in &page.events {
                assert_eq!(event.id, published[event.acceptance_marker as usize - 1]);
                assert_eq!(
                    event.payload,
                    format!("payload {}", event.acceptance_marker).as_bytes()
                );
            }
            assert_eq!(page.scanned_through, [2, 4, 6, 7][page_index]);
            assert_eq!(page.has_more, page_index < 3);
            cursor = page.scanned_through;
        }
        let terminal = client
            .query_events(api::QueryEventsRequest {
                logical_key: key,
                after_acceptance_marker: cursor,
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(terminal.events.is_empty());
        assert_eq!(terminal.scanned_through, 7);
        assert!(!terminal.has_more);
    }
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn subscription_listing_survives_restart_with_binary_keys_and_distinct_selectors() {
    let state = TestState::new();
    let mut expected = Vec::new();
    for generation in 0..2 {
        let mission = UnprotectedReferenceMission::from_bytes(
            include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle")
                .to_vec(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = agent.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(agent.serve(
            node.selected_events(),
            ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
            shutdown_rx,
        ));
        let client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let unauthenticated = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap()),
        );
        let error = unauthenticated
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .unwrap_err();
        assert_authentication_error(&error, api::PublicErrorDetail::FULL_NAME);
        let before = client
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(before.subscriptions, expected);
        if generation == 0 {
            for key in [
                vec![0xff, 0, 0x80],
                vec![0xfe; aster_redb_store::MAX_EVENT_SUBSCRIPTION_KEY_BYTES],
                vec![0xfd, 0],
            ] {
                let request = api::CreateEventSubscriptionRequest {
                    operation_key: key.clone(),
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    include_descendant_scopes: true,
                    ..Default::default()
                };
                let created = client
                    .create_event_subscription(request.clone())
                    .await
                    .unwrap()
                    .into_owned();
                let replay = client
                    .create_event_subscription(request)
                    .await
                    .unwrap()
                    .into_owned();
                assert!(!replay.inserted);
                assert_eq!(replay.subscription_id, created.subscription_id);
                expected.push(api::EventSubscription {
                    subscription_id: created.subscription_id,
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    include_descendant_scopes: true,
                    operation_key: key,
                    ..Default::default()
                });
            }
            expected.sort_by(|a, b| a.subscription_id.cmp(&b.subscription_id));
        } else {
            let removed = expected.remove(1);
            client
                .delete_event_subscription(api::DeleteEventSubscriptionRequest {
                    subscription_id: removed.subscription_id,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for _ in 0..2 {
            assert_eq!(
                client
                    .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
                    .await
                    .unwrap()
                    .into_owned()
                    .subscriptions,
                expected
            );
        }
        let json_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
                .with_protocol(Protocol::Connect)
                .with_codec_format(connectrpc::CodecFormat::Json)
                .with_default_header(
                    "authorization",
                    format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
                ),
        );
        assert_eq!(
            json_client
                .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
                .await
                .unwrap()
                .into_owned()
                .subscriptions,
            expected,
            "populated JSON response must preserve arbitrary binary operation keys"
        );
        let handle = node.selected_events();
        node.shutdown().await.unwrap();
        let error = json_client
            .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
            .await
            .expect_err("closed actor must reject this RPC, not return an empty list");
        assert_eq!(error.code, ErrorCode::Unavailable);
        shutdown_tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert!(
            handle.list_subscriptions().await.is_err(),
            "closed actor must not return an empty success"
        );
    }
}

#[tokio::test]
async fn optional_event_ttl_is_enforced_by_the_live_agent() {
    const TEST_TTL_MS: u64 = 10_000;

    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .unwrap();
    let node = start_node(NodeConfig {
        state: state.0.clone(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mission,
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(50),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await
    .unwrap();
    let agent = BoundAgent::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = agent.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap(),
        shutdown_rx,
    ));
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        ),
    );
    let mut request = api::PublishEventRequest {
        operation_key: b"ttl-publication".to_vec(),
        topic: "chat.events".to_owned(),
        scope: "mission/team/alpha".to_owned(),
        priority: api::Priority::Routine.into(),
        logical_key: b"finite".to_vec(),
        payload: b"short-lived".to_vec(),
        ttl_ms: Some(0),
        ..Default::default()
    };
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.ttl_ms = Some(TEST_TTL_MS);
    request.tombstone = true;
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.tombstone = false;
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        client
            .publish_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    #[cfg(target_os = "linux")]
    {
        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                operation_key: b"ttl-subscription".to_vec(),
                topic: request.topic.clone(),
                scope: request.scope.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let published = client
            .publish_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(published.ttl_ms, request.ttl_ms);
        let retry = client
            .publish_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(retry.id, published.id);
        assert!(!retry.inserted);
        let mut changed = request.clone();
        changed.ttl_ms = Some(TEST_TTL_MS + 1_000);
        assert_eq!(
            client.publish_event(changed).await.unwrap_err().code,
            ErrorCode::Aborted
        );
        let query = api::QueryEventsRequest {
            logical_key: Some(b"finite".to_vec()),
            limit: 16,
            ..Default::default()
        };
        let page = client
            .query_events(query.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].ttl_ms, request.ttl_ms);
        let poll = api::PollEventsRequest {
            subscription_id: subscription.subscription_id,
            delivery_limit: 16,
            scan_limit: 16,
            ..Default::default()
        };
        let deliveries = client.poll_events(poll.clone()).await.unwrap().into_owned();
        assert_eq!(deliveries.deliveries.len(), 1);
        assert_eq!(
            deliveries.deliveries[0].event.as_option().unwrap().ttl_ms,
            request.ttl_ms
        );
        let full = client
            .get_status(api::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned();
        // Keep a generous pre-expiry window for loaded CI runners while still
        // crossing the real live-agent wall-clock boundary in this test.
        tokio::time::sleep(Duration::from_millis(TEST_TTL_MS + 50)).await;
        assert!(
            client
                .query_events(query)
                .await
                .unwrap()
                .into_owned()
                .events
                .is_empty()
        );
        assert!(
            client
                .poll_events(poll)
                .await
                .unwrap()
                .into_owned()
                .deliveries
                .is_empty()
        );
        assert_eq!(
            client
                .publish_event(request.clone())
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        let empty = client
            .get_status(api::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert!(
            empty.store_capacity.as_option().unwrap().items
                < full.store_capacity.as_option().unwrap().items
        );
        assert!(
            empty.store_capacity.as_option().unwrap().payload_bytes
                < full.store_capacity.as_option().unwrap().payload_bytes
        );
        assert_eq!(
            empty
                .publish_operation_capacity
                .as_option()
                .unwrap()
                .retired_rows,
            1
        );
    }
    request.operation_key = b"durable-publication".to_vec();
    request.ttl_ms = None;
    let durable = client.publish_event(request).await.unwrap().into_owned();
    assert!(durable.inserted);
    assert_eq!(durable.ttl_ms, None);
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn numbered_sdk_recovers_its_committed_result_across_restart() {
    let state = TestState::new();
    let mission = UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .expect("mission");
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
    .expect("node");
    let agent = BoundAgent::bind("127.0.0.1:0".parse().expect("agent bind"))
        .await
        .expect("agent");
    let address = agent.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(agent.serve(
        node.selected_events(),
        ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("token"),
        shutdown_rx,
    ));
    let config = || {
        ClientConfig::new(format!("http://{address}").parse().expect("URI")).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        )
    };
    let journal_path = state.0.join("publication-journal.redb");
    let client_id = b"real-numbered-sdk";
    PublicationJournal::initialize(&journal_path, client_id).expect("initialize journal");

    let sequence;
    let committed;
    let occupied_bytes;
    {
        let sdk = NumberedEventSdk::open(
            api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config()),
            &journal_path,
            client_id,
        )
        .expect("open journal");
        let report = sdk.recover().await.expect("initial recovery");
        assert!(report.operations.is_empty());
        (sequence, committed) = sdk
            .publish(api::PublishNumberedEventRequest {
                topic: "chat.events".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                priority: api::Priority::Immediate.into(),
                logical_key: b"numbered-message".to_vec(),
                payload: b"survives SDK restart".to_vec(),
                ..Default::default()
            })
            .await
            .expect("publish");
        assert_eq!(sequence, 1);
        assert_eq!(committed.operation_sequence, 1);

        let status = api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config())
            .get_status(api::GetStatusRequest::default())
            .await
            .expect("numbered status")
            .into_owned();
        let operations = status
            .publish_operation_capacity
            .as_option()
            .expect("publication capacity");
        assert_eq!(operations.rows, 2, "one client and one outstanding result");
        assert!(operations.bytes > 0);
        occupied_bytes = operations.bytes;
        assert_eq!(operations.ordinary_remaining, 683_925);
        assert!(operations.emergency_remaining > 0);
        assert_eq!(operations.profile_remaining, 1_022);
        assert_eq!(
            operations.ledger_mode,
            api::PublishOperationLedgerMode::Numbered
        );
        assert_eq!(operations.numbered_clients, 1);
        assert_eq!(operations.numbered_outstanding_results, 1);
        assert_eq!(operations.numbered_reverse_rows, 1);
        assert!(operations.rolling_accept_rate > 0.0);
    }

    let restarted = NumberedEventSdk::open(
        api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config()),
        &journal_path,
        client_id,
    )
    .expect("reopen journal");
    let report = restarted.recover().await.expect("restart recovery");
    assert_eq!(report.operations.len(), 1);
    assert_eq!(report.operations[0].sequence, sequence);
    assert!(matches!(&report.operations[0].state,
        RecoveredState::Committed(result) if result == &committed));
    assert!(restarted.session().expect("session") > 1);
    assert_eq!(
        restarted
            .publish_journaled(sequence)
            .await
            .expect("recovered committed result"),
        committed
    );
    restarted
        .acknowledge(sequence)
        .await
        .expect("acknowledge recovered result");

    let status = api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config())
        .get_status(api::GetStatusRequest::default())
        .await
        .expect("compacted numbered status")
        .into_owned();
    let operations = status
        .publish_operation_capacity
        .as_option()
        .expect("publication capacity");
    assert_eq!(
        operations.rows, 1,
        "the durable client remains after result acknowledgement"
    );
    assert!(
        operations.bytes < occupied_bytes,
        "acknowledgement must reclaim the result and reverse-edge bytes"
    );
    assert_eq!(operations.ordinary_remaining, 683_926);
    assert!(operations.emergency_remaining > 0);
    assert_eq!(operations.profile_remaining, 1_023);
    assert_eq!(
        operations.ledger_mode,
        api::PublishOperationLedgerMode::Numbered
    );
    assert_eq!(operations.numbered_clients, 1);
    assert_eq!(operations.numbered_outstanding_results, 0);
    assert_eq!(operations.numbered_reverse_rows, 0);

    shutdown_tx.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("agent shutdown timeout")
        .expect("agent task")
        .expect("agent serve");
    node.shutdown().await.expect("node shutdown");
}
