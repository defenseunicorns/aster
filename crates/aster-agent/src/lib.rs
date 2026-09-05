//! Process-local ConnectRPC application boundary for a running Aster node.
//!
//! The service is intentionally narrower than the durable data model. Only
//! operations backed by the live selected-Event handle are exposed. In
//! particular, this crate never opens the node's store and never exposes
//! transport, reconciliation, cryptographic, sealed, or provisioning details.

#![forbid(unsafe_code)]

pub mod config;
pub mod credentials;
pub mod error;
pub mod health;
pub mod lifecycle;
mod service;

pub use credentials::ClientToken;
pub use error::{PublicOperation, connect_application_error, public_error};

use std::time::Duration;

use aster_node::application::SelectedEventHandle;
use connectrpc::{ConnectError, ErrorCode, RequestContext};

use service::AsterConnectService;

/// Generated, repository-owned application protocol.
pub mod proto {
    connectrpc::include_generated!();
}

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
            Err(public_error(
                ErrorCode::Unauthenticated,
                api::PublicErrorReason::AuthenticationFailed,
                PublicOperation::Unspecified,
                false,
                None,
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
    use buffa::{Message as _, MessageName as _};
    use connectrpc::ErrorCode;

    use super::*;

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

    fn assert_authentication_failure(error: &ConnectError) {
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(error.message.as_deref(), Some("authentication failed"));
        assert_eq!(error.details.len(), 1);
        let detail = &error.details[0];
        assert_eq!(detail.type_url, api::PublicErrorDetail::FULL_NAME);
        assert!(detail.debug.is_none());
        let wire = decode_base64(detail.value.as_deref().expect("encoded detail"));
        let detail = api::PublicErrorDetail::decode_from_slice(&wire)
            .expect("decodable public authentication detail");
        assert_eq!(detail.reason, api::PublicErrorReason::AuthenticationFailed);
        assert_eq!(detail.operation, "unspecified");
        assert!(!detail.retryable);
        assert_eq!(detail.retry_delay_ms, None);
    }

    #[test]
    fn missing_and_invalid_bearer_credentials_are_indistinguishable_and_sanitized() {
        const INVALID_CREDENTIAL_CANARY: &str = "Bearer invalid-credential-canary-0123456789abcdef";
        let auth = BearerAuth {
            token: ClientToken::from_bytes(b"0123456789abcdef-._~ABCDEFGHIJKL".to_vec())
                .expect("valid token"),
        };

        let missing = auth
            .authorize(&RequestContext::new(Default::default()))
            .expect_err("missing bearer credential must fail");
        let mut invalid_context = RequestContext::new(Default::default());
        invalid_context.headers_mut().insert(
            "authorization",
            INVALID_CREDENTIAL_CANARY
                .parse()
                .expect("valid authorization header fixture"),
        );
        let invalid = auth
            .authorize(&invalid_context)
            .expect_err("invalid bearer credential must fail");

        assert_authentication_failure(&missing);
        assert_authentication_failure(&invalid);
        assert_eq!(
            serde_json::to_value(&missing).expect("serializable missing-credential error"),
            serde_json::to_value(&invalid).expect("serializable invalid-credential error")
        );
        assert!(!format!("{invalid:?}").contains(INVALID_CREDENTIAL_CANARY));
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
