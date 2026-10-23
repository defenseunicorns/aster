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
#[cfg(target_os = "linux")]
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner, Scope, Topic};
#[cfg(target_os = "linux")]
use aster_node::application::MAX_SELECTED_LIVE_BLOB_BYTES;
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
use buffa::{Message as _, MessageName as _};
use connectrpc::{
    ConnectError, ErrorCode, Protocol,
    client::{ClientConfig, Http2Connection, HttpClient},
};
#[cfg(target_os = "linux")]
use std::{sync::Arc, task::Poll};

const TEST_TOKEN: &[u8] = b"real-node-connect-test-token-0001";

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestState(PathBuf);

impl TestState {
    fn new() -> Self {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
            .join(format!(
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

#[cfg(target_os = "linux")]
fn assert_public_reason(
    error: &ConnectError,
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: &str,
) {
    assert_public_reason_with_retryability(error, code, reason, operation, false);
}

#[cfg(target_os = "linux")]
fn assert_public_reason_with_retryability(
    error: &ConnectError,
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: &str,
    retryable: bool,
) {
    assert_eq!(error.code, code);
    assert_eq!(error.details.len(), 1);
    let wire_detail = &error.details[0];
    assert!(wire_detail.debug.is_none());
    let detail = api::PublicErrorDetail::decode_from_slice(&decode_base64(
        wire_detail.value.as_deref().expect("encoded public detail"),
    ))
    .expect("decodable public detail");
    assert_eq!(detail.reason, reason);
    assert_eq!(detail.operation, operation);
    assert_eq!(detail.retryable, retryable);
    assert_eq!(detail.retry_delay_ms, None);
}

#[cfg(target_os = "linux")]
fn blob_mission() -> UnprotectedReferenceMission {
    let access = ProvisioningAccess::member(
        Scope::new("mission/team/alpha").expect("Blob scope"),
        vec![1],
        vec![Topic::new("imagery.maps").expect("Blob topic")],
    )
    .expect("Blob access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xb7; 32]).expect("reference provisioner");
    UnprotectedReferenceMission::from_bytes(
        provisioner
            .issue_node(1, &[access])
            .expect("issue Blob mission")
            .to_bytes()
            .expect("encode Blob mission"),
    )
    .expect("load disposable Blob test mission")
}

#[cfg(target_os = "linux")]
#[test]
fn real_node_blob_publish_read_preserves_ttl_and_status_distinctions() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let state = TestState::new();
        let node = start_node(NodeConfig {
            state: state.0.clone(),
            bind: "127.0.0.1:0".parse().expect("mesh bind"),
            mission: blob_mission(),
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
        let server = tokio::spawn(
            agent
                .serve_with_blobs(
                    node.selected_events(),
                    node.selected_blobs(),
                    node.state_root().to_path_buf(),
                    ClientToken::from_bytes(TEST_TOKEN.to_vec()).expect("valid token"),
                    shutdown_rx,
                )
                .expect("construct combined Event/Blob service"),
        );
        let grpc = Http2Connection::connect_plaintext(
            format!("http://{address}")
                .parse()
                .expect("gRPC transport URI"),
        )
        .await
        .expect("connect gRPC HTTP/2 transport")
        .shared(8);
        let client = api::AsterApplicationServiceClient::new(
            grpc.clone(),
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("gRPC client URI"),
            )
            .with_protocol(Protocol::Grpc)
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );

        let pending_upload = |key: &'static [u8], polled: Arc<tokio::sync::Notify>| {
            let mut metadata = Some(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                    api::PublishBlobMetadata {
                        operation_key: key.to_vec(),
                        topic: "imagery.maps".to_owned(),
                        scope: "mission/team/alpha".to_owned(),
                        priority: api::Priority::Routine.into(),
                        total_len: 1,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            });
            futures::stream::poll_fn(move |_| {
                if let Some(metadata) = metadata.take() {
                    Poll::Ready(Some(metadata))
                } else {
                    polled.notify_one();
                    Poll::Pending
                }
            })
        };
        let one_byte_upload = |key: &[u8], declared_len: u64| {
            vec![
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                        api::PublishBlobMetadata {
                            operation_key: key.to_vec(),
                            topic: "imagery.maps".to_owned(),
                            scope: "mission/team/alpha".to_owned(),
                            priority: api::Priority::Routine.into(),
                            total_len: declared_len,
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Chunk(vec![0x31])),
                    ..Default::default()
                },
            ]
        };
        let stalled_keys = [
            b"real-node-blob-cancelled-left".as_slice(),
            b"real-node-blob-cancelled-right".as_slice(),
        ];
        let mut uploads = tokio::task::JoinSet::new();
        for (index, key) in stalled_keys.into_iter().enumerate() {
            let client = client.clone();
            let stream = pending_upload(key, Arc::new(tokio::sync::Notify::new()));
            uploads.spawn(async move { (index, client.publish_blob(stream).await) });
        }

        // Both uploads remain pending after metadata, so whichever acquires
        // the singleton permit holds it until cancellation. The first result
        // must be the other upload's rejection, regardless of arrival order.
        // JoinSet also aborts outstanding requests if an assertion fails.
        let (rejected_index, rejection) =
            tokio::time::timeout(Duration::from_secs(2), uploads.join_next())
                .await
                .expect("one competing upload is rejected while the other holds capacity")
                .expect("two competing upload tasks")
                .expect("rejected upload task");
        assert_eq!(
            rejection
                .expect_err("one stalled upload must own the singleton permit")
                .code,
            ErrorCode::ResourceExhausted
        );
        let cancelled_key = stalled_keys[1 - rejected_index];
        uploads.abort_all();
        assert!(
            uploads
                .join_next()
                .await
                .expect("permit-owning upload remains pending")
                .unwrap_err()
                .is_cancelled()
        );
        assert!(uploads.is_empty());
        let recovered_cancelled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client
                    .publish_blob(connectrpc::stream_iter(one_byte_upload(cancelled_key, 1)))
                    .await
                {
                    Ok(response) => break response.into_owned(),
                    Err(error) if error.code == ErrorCode::ResourceExhausted => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("cancel recovery failed: {error:?}"),
                }
            }
        })
        .await
        .expect("cancellation releases staging and capacity after cleanup");
        assert!(recovered_cancelled.inserted);

        let deadline_client = api::AsterApplicationServiceClient::new(
            grpc,
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("deadline client URI"),
            )
            .with_protocol(Protocol::Grpc)
            .with_default_timeout(Duration::from_millis(10))
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let deadline_polled = Arc::new(tokio::sync::Notify::new());
        let deadline_stream =
            pending_upload(b"real-node-blob-deadline", Arc::clone(&deadline_polled));
        let deadline_task =
            tokio::spawn(async move { deadline_client.publish_blob(deadline_stream).await });
        deadline_polled.notified().await;
        let deadline = deadline_task
            .await
            .expect("deadline request task")
            .expect_err("an incomplete upload must obey the client deadline");
        assert_eq!(deadline.code, ErrorCode::DeadlineExceeded);

        // The client deadline can finish before server-side staging cleanup.
        // Recover the exact key through the ordinary client before testing
        // gRPC-Web rejection, so cleanup cannot occupy that case's permit.
        let recovered_deadline = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client
                    .publish_blob(connectrpc::stream_iter(one_byte_upload(
                        b"real-node-blob-deadline",
                        1,
                    )))
                    .await
                {
                    Ok(response) => break response.into_owned(),
                    Err(error) if error.code == ErrorCode::ResourceExhausted => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("deadline recovery failed: {error:?}"),
                }
            }
        })
        .await
        .expect("deadline releases staging and capacity after cleanup");
        assert!(recovered_deadline.inserted);

        let grpc_web_client = api::AsterApplicationServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(
                format!("http://{address}")
                    .parse()
                    .expect("gRPC-Web client URI"),
            )
            .with_protocol(Protocol::GrpcWeb)
            .with_default_header(
                "authorization",
                format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
            ),
        );
        let grpc_web_frames = vec![
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                    api::PublishBlobMetadata {
                        operation_key: b"grpc-web-rejected-blob".to_vec(),
                        topic: "imagery.maps".to_owned(),
                        scope: "mission/team/alpha".to_owned(),
                        priority: api::Priority::Routine.into(),
                        total_len: 1,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            },
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Chunk(vec![0x44])),
                ..Default::default()
            },
        ];
        let grpc_web_error = grpc_web_client
            .publish_blob(connectrpc::stream_iter(grpc_web_frames.clone()))
            .await
            .expect_err("gRPC-Web request streaming must be rejected");
        assert_public_reason(
            &grpc_web_error,
            ErrorCode::Unimplemented,
            api::PublicErrorReason::UnsupportedValue,
            "publish_blob",
        );
        let after_grpc_web = client
            .publish_blob(connectrpc::stream_iter(grpc_web_frames))
            .await
            .expect("gRPC-Web rejection must not mutate Blob state")
            .into_owned();
        assert!(after_grpc_web.inserted);

        let payload = vec![0x5a; 65_536 + 3];
        let metadata = api::PublishBlobMetadata {
            operation_key: b"real-node-blob-durable".to_vec(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("application/octet-stream".to_owned()),
            schema_id: b"schema/blob-v1".to_vec(),
            total_len: payload.len() as u64,
            ttl_ms: None,
            ..Default::default()
        };
        let frames = vec![
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                    metadata.clone(),
                ))),
                ..Default::default()
            },
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Chunk(
                    payload[..65_536].to_vec(),
                )),
                ..Default::default()
            },
            api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Chunk(
                    payload[65_536..].to_vec(),
                )),
                ..Default::default()
            },
        ];
        let published = client
            .publish_blob(connectrpc::stream_iter(frames.clone()))
            .await
            .expect("publish durable Blob")
            .into_owned();
        assert!(published.inserted);
        assert_eq!(published.ttl_ms, None);
        assert_eq!(published.total_len, payload.len() as u64);
        let retried = client
            .publish_blob(connectrpc::stream_iter(frames))
            .await
            .expect("retry durable Blob")
            .into_owned();
        assert!(!retried.inserted);
        assert_eq!(retried.id, published.id);
        assert_eq!(retried.ttl_ms, None);

        let mut pages = client
            .read_blob(api::ReadBlobRequest {
                id: published.id.clone(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start multi-page Blob read");
        let mut observed = Vec::new();
        let mut offsets = Vec::new();
        while let Some(page) = pages.message().await.expect("read Blob page") {
            let page = page.to_owned_message();
            assert_eq!(page.id, published.id);
            assert_eq!(page.publisher, published.publisher);
            assert_eq!(page.publisher_counter, published.publisher_counter);
            assert_eq!(page.topic, "imagery.maps");
            assert_eq!(page.scope, "mission/team/alpha");
            assert_eq!(page.priority, api::Priority::Immediate);
            assert_eq!(page.ttl_ms, None);
            assert_eq!(page.total_len, payload.len() as u64);
            assert_eq!(page.media_type.as_deref(), Some("application/octet-stream"));
            assert_eq!(page.schema_id, b"schema/blob-v1");
            assert_eq!(page.acceptance_marker, published.acceptance_marker);
            offsets.push(page.offset);
            observed.extend_from_slice(&page.chunk);
            if page.complete {
                break;
            }
        }
        assert_eq!(offsets, [0, 65_536]);
        assert_eq!(observed, payload);

        let metadata_frame = |key: &[u8], total_len| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                api::PublishBlobMetadata {
                    operation_key: key.to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    total_len,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let chunk_frame = |bytes| api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Chunk(bytes)),
            ..Default::default()
        };
        let malformed_cases = vec![
            (
                "missing-frame",
                vec![api::PublishBlobRequest::default()],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                None,
            ),
            (
                "over-policy",
                vec![metadata_frame(
                    b"real-node-blob-over-policy",
                    MAX_SELECTED_LIVE_BLOB_BYTES + 1,
                )],
                ErrorCode::ResourceExhausted,
                api::PublicErrorReason::ResourceExhaustion,
                Some(b"real-node-blob-over-policy".as_slice()),
            ),
            (
                "short",
                vec![
                    metadata_frame(b"real-node-blob-short", 2),
                    chunk_frame(vec![1]),
                ],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                Some(b"real-node-blob-short".as_slice()),
            ),
            (
                "long",
                vec![
                    metadata_frame(b"real-node-blob-long", 1),
                    chunk_frame(vec![1, 2]),
                ],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                Some(b"real-node-blob-long".as_slice()),
            ),
            (
                "reordered",
                vec![chunk_frame(vec![1])],
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                None,
            ),
        ];
        for (label, frames, code, reason, rejected_key) in malformed_cases {
            let error = client
                .publish_blob(connectrpc::stream_iter(frames))
                .await
                .expect_err(label);
            assert_public_reason_with_retryability(
                &error,
                code,
                reason,
                "publish_blob",
                reason == api::PublicErrorReason::ResourceExhaustion,
            );

            let recovery_key = rejected_key
                .map(<[u8]>::to_vec)
                .unwrap_or_else(|| format!("real-node-recovery-{label}").into_bytes());
            let recovered = client
                .publish_blob(connectrpc::stream_iter(vec![
                    metadata_frame(&recovery_key, 1),
                    chunk_frame(vec![0x41]),
                ]))
                .await
                .expect("every rejected stream must release staging and its upload permit")
                .into_owned();
            assert!(recovered.inserted);
            let retry = client
                .publish_blob(connectrpc::stream_iter(vec![
                    metadata_frame(&recovery_key, 1),
                    chunk_frame(vec![0x41]),
                ]))
                .await
                .expect("exact-key recovery must remain idempotent")
                .into_owned();
            assert!(!retry.inserted);
            assert_eq!(retry.id, recovered.id);
        }
        assert!(
            fs::read_dir(&state.0)
                .expect("inspect state root")
                .all(|entry| !entry
                    .expect("state entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aster-agent-blob-upload-")),
            "Blob staging names must be unlinked before payload custody"
        );

        let finite_payload = b"finite-blob".to_vec();
        let finite = client
            .publish_blob(connectrpc::stream_iter(vec![
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                        api::PublishBlobMetadata {
                            operation_key: b"real-node-blob-finite".to_vec(),
                            topic: "imagery.maps".to_owned(),
                            scope: "mission/team/alpha".to_owned(),
                            priority: api::Priority::Priority.into(),
                            media_type: Some("application/octet-stream".to_owned()),
                            schema_id: b"schema/blob-v1".to_vec(),
                            total_len: finite_payload.len() as u64,
                            ttl_ms: Some(1_000),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                },
                api::PublishBlobRequest {
                    frame: Some(api::publish_blob_request::Frame::Chunk(finite_payload)),
                    ..Default::default()
                },
            ]))
            .await
            .expect("publish finite Blob")
            .into_owned();
        assert_eq!(finite.ttl_ms, Some(1_000));
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let mut expired = client
            .read_blob(api::ReadBlobRequest {
                id: finite.id,
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start expired read stream");
        let expired = expired
            .message()
            .await
            .expect_err("recently expired Blob must fail");
        assert_public_reason(
            &expired,
            ErrorCode::NotFound,
            api::PublicErrorReason::ExpiredOrRetired,
            "read_blob",
        );

        let mut missing = client
            .read_blob(api::ReadBlobRequest {
                id: vec![0xee; 32],
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .expect("start never-observed read stream");
        let missing = missing
            .message()
            .await
            .expect_err("never-observed Blob must fail");
        assert_public_reason(
            &missing,
            ErrorCode::NotFound,
            api::PublicErrorReason::MissingDurableObject,
            "read_blob",
        );

        shutdown_tx.send(true).expect("request shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("agent shutdown timeout")
            .expect("agent task")
            .expect("agent serve");
        node.shutdown().await.expect("node shutdown");
    });
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
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
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
        assert!(status.credential_generation.is_empty());

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
            assert!(view.credential_generation.is_empty());
        }
        let owned: api::GetStatusResponse = response.into_owned();
        drop(connect_client);
        assert_eq!(owned.identity, status.identity);
        assert_eq!(owned.mission_authority, status.mission_authority);
        assert!(owned.credential_generation.is_empty());

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

        claim_rpc_fixture(&client).await;
        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
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
            .publish_numbered_event(api::PublishNumberedEventRequest {
                client_id: b"rpc-fixture".to_vec(), session: 1, operation_sequence: 1,
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
        assert_eq!(published.result.as_option().unwrap().receipt.as_option().unwrap().event_id.len(), 32);

        let page = client
            .poll_events(api::PollEventsRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
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
        assert_eq!(event.id, published.result.as_option().unwrap().receipt.as_option().unwrap().event_id);
        assert_eq!(event.payload, b"offline-first through ConnectRPC");
        assert_eq!(page.deliveries[0].attempt, 1);

        let acknowledgement = client
            .acknowledge_event(api::AcknowledgeEventRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
                subscription_id: subscription.subscription_id.clone(),
                event_id: published.result.as_option().unwrap().receipt.as_option().unwrap().event_id.clone(),
                ..Default::default()
            })
            .await
            .expect("acknowledge through ConnectRPC")
            .into_owned();
        assert!(!acknowledgement.already_acknowledged);

        let mut stream = client
            .stream_events(api::StreamEventsRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
                subscription_id: subscription.subscription_id.clone(),
                delivery_limit: 8,
                scan_limit: 32,
                poll_backoff_ms: 250,
                ..Default::default()
            })
            .await
            .expect("start durable delivery stream");
        let streamed_publication = client
            .publish_numbered_event(api::PublishNumberedEventRequest {
                client_id: b"rpc-fixture".to_vec(), session: 1, operation_sequence: 2,
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
            streamed_publication.result.as_option().unwrap().receipt.as_option().unwrap().event_id
        );
        drop(stream);

        let redelivery = client
            .poll_events(api::PollEventsRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
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
            streamed_publication.result.as_option().unwrap().receipt.as_option().unwrap().event_id
        );
        client
            .acknowledge_event(api::AcknowledgeEventRequest {
                    client: api::EventClientContext { client_id: b"rpc-fixture".to_vec(), session: 1, ..Default::default() }.into(),
                subscription_id: subscription.subscription_id,
                event_id: streamed_publication.result.as_option().unwrap().receipt.as_option().unwrap().event_id.clone(),
                ..Default::default()
            })
            .await
            .expect("acknowledge redelivery");

        let path = state.0.join("delivery-pipeline.redb");
        PublicationJournal::initialize(&path, b"delivery-pipeline-fixture").unwrap();
        let sdk = NumberedEventSdk::open(client.clone(), &path, b"delivery-pipeline-fixture").unwrap();
        sdk.recover().await.unwrap();
        let sequences = (0_u8..2).map(|suffix| sdk.journal_publication(api::PublishNumberedEventRequest {
            topic: "chat.events".to_owned(), scope: "mission/team/alpha".to_owned(), priority: api::Priority::Routine.into(),
            logical_key: vec![suffix], payload: vec![suffix], ..Default::default()
        }).unwrap()).collect::<Vec<_>>();
        let pipelined = sdk.publish_journaled_pipeline(&sequences, 1).await.unwrap();
        assert_eq!(pipelined.len(), 2);

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
    claim_rpc_fixture(&client).await;
    let mut published = Vec::new();
    for index in 1..=7 {
        published.push(
            client
                .publish_numbered_event(api::PublishNumberedEventRequest {
                    client_id: b"rpc-fixture".to_vec(),
                    session: 1,
                    operation_sequence: index,
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
                .result
                .as_option()
                .unwrap()
                .receipt
                .as_option()
                .unwrap()
                .event_id
                .clone(),
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
            claim_rpc_fixture(&client).await;
            for key in [
                vec![0xff, 0, 0x80],
                vec![0xfe; aster_redb_store::MAX_EVENT_SUBSCRIPTION_KEY_BYTES],
                vec![0xfd, 0],
            ] {
                let request = api::CreateEventSubscriptionRequest {
                    client: api::EventClientContext {
                        client_id: b"rpc-fixture".to_vec(),
                        session: 1,
                        ..Default::default()
                    }
                    .into(),
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
                    owner_client_id: b"rpc-fixture".to_vec(),
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
                    client: api::EventClientContext {
                        client_id: b"rpc-fixture".to_vec(),
                        session: 1,
                        ..Default::default()
                    }
                    .into(),
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
async fn platform_compat_optional_event_ttl_is_enforced_by_the_live_agent() {
    const TEST_TTL_MS: u64 = 3_000;

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
    claim_rpc_fixture(&client).await;
    let mut request = api::PublishNumberedEventRequest {
        client_id: b"rpc-fixture".to_vec(),
        session: 1,
        operation_sequence: 1,
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
            .publish_numbered_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.ttl_ms = Some(TEST_TTL_MS);
    request.tombstone = true;
    assert_eq!(
        client
            .publish_numbered_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    request.tombstone = false;
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        client
            .publish_numbered_event(request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    #[cfg(target_os = "linux")]
    {
        let subscription = client
            .create_event_subscription(api::CreateEventSubscriptionRequest {
                client: api::EventClientContext {
                    client_id: b"rpc-fixture".to_vec(),
                    session: 1,
                    ..Default::default()
                }
                .into(),
                operation_key: b"ttl-subscription".to_vec(),
                topic: request.topic.clone(),
                scope: request.scope.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        let published = client
            .publish_numbered_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(request.ttl_ms, Some(TEST_TTL_MS));
        let retry = client
            .publish_numbered_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            retry
                .result
                .as_option()
                .unwrap()
                .receipt
                .as_option()
                .unwrap()
                .event_id,
            published
                .result
                .as_option()
                .unwrap()
                .receipt
                .as_option()
                .unwrap()
                .event_id
        );
        assert!(!retry.inserted);
        let mut changed = request.clone();
        changed.ttl_ms = Some(TEST_TTL_MS + 1_000);
        assert_eq!(
            client
                .publish_numbered_event(changed)
                .await
                .unwrap_err()
                .code,
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
            client: api::EventClientContext {
                client_id: b"rpc-fixture".to_vec(),
                session: 1,
                ..Default::default()
            }
            .into(),
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
        // Expiry retires content, but the unacknowledged numbered result
        // must still replay the original receipt without publishing again.
        let retired_retry = client
            .publish_numbered_event(request.clone())
            .await
            .unwrap()
            .into_owned();
        assert!(!retired_retry.inserted);
        let retired_result = retired_retry.result.as_option().unwrap();
        assert_eq!(
            retired_result.receipt.as_option().unwrap(),
            published
                .result
                .as_option()
                .unwrap()
                .receipt
                .as_option()
                .unwrap()
        );
        assert_eq!(
            retired_result.operation_sequence,
            request.operation_sequence
        );
        assert_eq!(retired_result.content, api::CommittedContentStatus::Retired);
        assert_eq!(
            retired_result.retirement_reason,
            Some(api::RetirementReason::Expired.into())
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
        let operations = empty.publish_operation_capacity.as_option().unwrap();
        assert_eq!(
            operations.ledger_mode,
            api::PublishOperationLedgerMode::Numbered
        );
        assert_eq!(operations.retired_rows, 0);
        assert_eq!(operations.numbered_outstanding_results, 1);
        // The reverse row belongs to the retained result, not live content;
        // it is removed only when the client acknowledges that result.
        assert_eq!(operations.numbered_reverse_rows, 1);
    }
    request.operation_sequence = if cfg!(target_os = "linux") { 2 } else { 1 };
    request.ttl_ms = None;
    let durable = client
        .publish_numbered_event(request)
        .await
        .unwrap()
        .into_owned();
    assert!(durable.inserted);
    assert!(durable.result.as_option().is_some());
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

    // Exercise the journal-backed numbered pipeline over real native HTTP/2,
    // with eight retained entries. The explicit test-support feature lowers
    // only the network window to four and observes refill within one stream.
    for (index, protocol) in [Protocol::Connect, Protocol::Grpc].into_iter().enumerate() {
        let client_id = format!("numbered-pipeline-{index}");
        let path = state.0.join(format!("pipeline-{index}.redb"));
        PublicationJournal::initialize(&path, client_id.as_bytes()).unwrap();
        let transport =
            Http2Connection::connect_plaintext(format!("http://{address}").parse().unwrap())
                .await
                .unwrap()
                .shared(8);
        let sdk = NumberedEventSdk::open(
            api::AsterApplicationServiceClient::new(transport, config().with_protocol(protocol)),
            &path,
            client_id.as_bytes(),
        )
        .unwrap();
        sdk.recover().await.unwrap();
        let sequences: Vec<_> = (0_u8..8)
            .map(|suffix| {
                sdk.journal_publication(api::PublishNumberedEventRequest {
                    topic: "chat.events".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    priority: api::Priority::Routine.into(),
                    logical_key: vec![suffix],
                    payload: vec![suffix],
                    ..Default::default()
                })
                .unwrap()
            })
            .collect();
        assert_eq!(aster_agent::sdk::MAX_PUBLICATION_JOURNAL_ENTRIES, 8);
        assert!(
            sdk.journal_publication(api::PublishNumberedEventRequest::default())
                .is_err(),
            "all eight journal slots remain occupied"
        );
        #[cfg(feature = "sdk-test-support")]
        let results = {
            let (results, stats) = tokio::time::timeout(
                Duration::from_secs(30),
                sdk.publish_journaled_pipeline_with_window_for_test(&sequences, 1, 4),
            )
            .await
            .expect("one invocation must refill the four-request window")
            .expect("numbered native pipeline");
            assert_eq!(stats.stream_sessions, 1, "refill must use the same stream");
            assert_eq!(stats.requests_sent, 8, "all eight requests use that stream");
            assert_eq!(stats.max_in_flight, 4, "the actual network window is four");
            assert!(
                stats.send_batches > 1,
                "the stream must refill after results"
            );
            results
        };
        #[cfg(not(feature = "sdk-test-support"))]
        let results = sdk
            .publish_journaled_pipeline(&sequences, 1)
            .await
            .expect("numbered native pipeline with production window");
        assert_eq!(
            results
                .iter()
                .map(|result| result.operation_sequence)
                .collect::<Vec<_>>(),
            sequences
        );
        assert_eq!(sequences, (1..=8).collect::<Vec<u64>>());
        for sequence in sequences {
            sdk.acknowledge(sequence).await.unwrap();
        }
        drop(sdk);
        let reopened = NumberedEventSdk::open(
            api::AsterApplicationServiceClient::new(HttpClient::plaintext(), config()),
            &path,
            client_id.as_bytes(),
        )
        .unwrap();
        assert!(reopened.recover().await.unwrap().operations.is_empty());
    }

    shutdown_tx.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("agent shutdown timeout")
        .expect("agent task")
        .expect("agent serve");
    node.shutdown().await.expect("node shutdown");
}

async fn claim_rpc_fixture<T>(client: &api::AsterApplicationServiceClient<T>)
where
    T: connectrpc::client::ClientTransport,
    T::ResponseBody: Unpin,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: std::fmt::Display,
{
    let mut claim = [0; 32];
    getrandom::fill(&mut claim).unwrap();
    let snapshot = client
        .begin_event_publication_session(api::BeginEventPublicationSessionRequest {
            client_id: b"rpc-fixture".to_vec(),
            claim_nonce: claim.to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(snapshot.session, 1);
    client
        .complete_event_publication_recovery(api::CompleteEventPublicationRecoveryRequest {
            client_id: b"rpc-fixture".to_vec(),
            session: snapshot.session,
            snapshot_revision: snapshot.snapshot_revision,
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn sdk_subscription_context_is_fenced_without_implicit_takeover() {
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
    let token = ClientToken::from_bytes(TEST_TOKEN.to_vec()).unwrap();
    let server = tokio::spawn(agent.serve(node.selected_events(), token, shutdown_rx));
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse().unwrap()).with_default_header(
            "authorization",
            format!("Bearer {}", String::from_utf8_lossy(TEST_TOKEN)),
        ),
    );
    let path = state.0.join("owned-sdk.redb");
    PublicationJournal::initialize(&path, b"owned-sdk").unwrap();
    let sdk = NumberedEventSdk::open(client.clone(), &path, b"owned-sdk").unwrap();
    assert!(sdk.client_context().is_err());
    let initial_capacity = client
        .get_status(api::GetStatusRequest::default())
        .await
        .unwrap()
        .into_owned()
        .publish_operation_capacity;
    for _ in 0..2 {
        let initial = sdk.client_status().await.unwrap();
        assert_eq!(
            initial.disposition,
            api::EventClientDisposition::Unregistered
        );
        assert_eq!(initial.current_session, None);
        assert_eq!(
            (
                initial.subscriptions,
                initial.pending_deliveries,
                initial.acknowledged_deliveries,
                initial.ownership_metadata_bytes
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(sdk.session().unwrap(), 0);
        assert!(sdk.client_context().is_err());
    }
    assert_eq!(
        client
            .get_status(api::GetStatusRequest::default())
            .await
            .unwrap()
            .into_owned()
            .publish_operation_capacity,
        initial_capacity
    );
    for invalid in [
        api::GetEventClientStatusRequest {
            client_id: b"owned-sdk".to_vec(),
            observed_session: Some(0),
            ..Default::default()
        },
        api::GetEventClientStatusRequest::default(),
        api::GetEventClientStatusRequest {
            client_id: vec![1; 65],
            ..Default::default()
        },
    ] {
        assert_eq!(
            client
                .get_event_client_status(invalid)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    sdk.recover().await.unwrap();
    let old = sdk.client_context().unwrap();
    assert_eq!(
        old.session, 1,
        "status did not register or claim the client"
    );
    assert_eq!(
        sdk.client_status().await.unwrap().disposition,
        api::EventClientDisposition::Current
    );
    let unobserved = client
        .get_event_client_status(api::GetEventClientStatusRequest {
            client_id: old.client_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(unobserved.current_session, Some(old.session));
    assert_eq!(
        unobserved.disposition,
        api::EventClientDisposition::RecoveryRequired
    );
    let request = api::CreateEventSubscriptionRequest {
        operation_key: b"reader".to_vec(),
        topic: "chat.events".into(),
        scope: "mission/team/alpha".into(),
        ..Default::default()
    };
    // The public wire requires context; the SDK fills it from recovered state.
    for invalid in [
        request.clone(),
        api::CreateEventSubscriptionRequest {
            client: api::EventClientContext {
                client_id: old.client_id.clone(),
                session: 0,
                ..Default::default()
            }
            .into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            client
                .create_event_subscription(invalid)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let subscription = sdk.create_subscription(request.clone()).await.unwrap();
    assert!(subscription.inserted);
    assert_eq!(sdk.client_status().await.unwrap().subscriptions, 1);
    let mut nonce = vec![0; 32];
    getrandom::fill(&mut nonce).unwrap();
    let takeover = client
        .begin_event_publication_session(api::BeginEventPublicationSessionRequest {
            client_id: old.client_id.clone(),
            expected_session: old.session,
            claim_nonce: nonce,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    let current = api::EventClientContext {
        client_id: old.client_id.clone(),
        session: takeover.session,
        ..Default::default()
    };
    let status = sdk.client_status().await.unwrap();
    assert_eq!(status.disposition, api::EventClientDisposition::Fenced);
    assert_eq!(status.current_session, Some(takeover.session));
    for error in [
        sdk.create_subscription(request.clone()).await.unwrap_err(),
        sdk.poll_events(api::PollEventsRequest {
            subscription_id: subscription.subscription_id.clone(),
            delivery_limit: 8,
            scan_limit: 8,
            ..Default::default()
        })
        .await
        .unwrap_err(),
        sdk.acknowledge_delivery(api::AcknowledgeEventRequest {
            subscription_id: subscription.subscription_id.clone(),
            event_id: vec![0; 32],
            ..Default::default()
        })
        .await
        .unwrap_err(),
        sdk.delete_subscription(api::DeleteEventSubscriptionRequest {
            subscription_id: subscription.subscription_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err(),
    ] {
        assert!(
            matches!(error, aster_agent::sdk::NumberedEventSdkError::Transport(error) if error.code == ErrorCode::Aborted)
        );
    }
    let recovering = client
        .get_event_client_status(api::GetEventClientStatusRequest {
            client_id: old.client_id.clone(),
            observed_session: Some(takeover.session),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(
        recovering.disposition,
        api::EventClientDisposition::RecoveryRequired
    );
    let blocked = client
        .poll_events(api::PollEventsRequest {
            client: current.clone().into(),
            subscription_id: subscription.subscription_id.clone(),
            delivery_limit: 8,
            scan_limit: 8,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(blocked.code, ErrorCode::FailedPrecondition);
    let listed = client
        .list_event_subscriptions(api::ListEventSubscriptionsRequest::default())
        .await
        .unwrap()
        .into_owned();
    assert_eq!(listed.subscriptions.len(), 1);
    assert_eq!(listed.subscriptions[0].owner_client_id, old.client_id);
    assert!(
        client
            .query_events(api::QueryEventsRequest {
                limit: 8,
                ..Default::default()
            })
            .await
            .is_ok()
    );
    assert_eq!(sdk.client_status().await.unwrap(), status);
    client
        .complete_event_publication_recovery(api::CompleteEventPublicationRecoveryRequest {
            client_id: old.client_id.clone(),
            session: takeover.session,
            snapshot_revision: takeover.snapshot_revision,
            ..Default::default()
        })
        .await
        .unwrap();
    let replay = client
        .create_event_subscription(api::CreateEventSubscriptionRequest {
            client: current.clone().into(),
            ..request
        })
        .await
        .unwrap()
        .into_owned();
    assert!(!replay.inserted);
    assert_eq!(replay.subscription_id, subscription.subscription_id);
    client
        .delete_event_subscription(api::DeleteEventSubscriptionRequest {
            client: current.into(),
            subscription_id: subscription.subscription_id,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        sdk.client_status().await.unwrap().ownership_metadata_bytes,
        0
    );
    // No SDK mutation above silently advanced or repaired this fenced journal.
    assert_eq!(sdk.client_context().unwrap(), old);
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
}
