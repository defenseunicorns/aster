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
#[cfg(feature = "server")]
pub mod runtime;
#[cfg(feature = "server")]
pub mod server;
mod service;

pub use credentials::ClientToken;
pub use error::{PublicOperation, connect_application_error, public_error};

use aster_node::application::SelectedEventHandle;

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

/// Compatibility entry point for the existing development CLI. Its serving
/// path delegates to the bounded pre-body server; Task 6 replaces this adapter
/// with the customer runtime supervisor.
#[cfg(feature = "server")]
pub struct BoundAgent {
    server: server::BoundAgent,
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
            server: server::BoundAgent::bind(address).await?,
        })
    }

    /// Returns the exact address selected by the operating system.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.server.local_addr().map_err(std::io::Error::other)
    }

    /// Serves until shutdown, closing active streams before transport drain.
    pub async fn serve(
        self,
        events: SelectedEventHandle,
        token: ClientToken,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = service::application_service(events, shutdown.clone());
        let status = lifecycle::ServiceStatus::starting();
        status.transition(lifecycle::LifecycleState::Ready)?;
        let reloadable = credentials::ReloadableClientToken::new(token);
        let (stop_send, stop_receive) = tokio::sync::watch::channel(server::ServerStop::Run);
        let stop_status = status.clone();
        let stop_task = tokio::spawn(async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
            let _ = stop_status.transition(lifecycle::LifecycleState::Draining);
            let _ = stop_send.send(server::ServerStop::Drain);
        });
        let result = self
            .server
            .serve(
                service,
                reloadable,
                status,
                config::AgentLimits::default(),
                stop_receive,
            )
            .await;
        stop_task.abort();
        result.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
