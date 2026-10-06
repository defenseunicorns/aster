use crate::{api, auth::Token, operation_key::Key};
use connectrpc::{
    Protocol,
    client::{ClientConfig, HttpClient},
};
use std::{net::SocketAddr, time::Duration};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

fn rpc_hint(code: connectrpc::ErrorCode) -> &'static str {
    use connectrpc::ErrorCode::*;
    match code {
        Unavailable => {
            "\nCheck that aster-agent is running and that --host and --port are correct."
        }
        Unauthenticated => {
            "\nCheck that the supplied token matches the agent's configured client token."
        }
        PermissionDenied => {
            "\nCheck the permissions for this operation and the requested topic and scope."
        }
        DeadlineExceeded => {
            "\nCheck agent responsiveness; increase --timeout if needed (agent-side limits still apply)."
        }
        _ => "",
    }
}

pub fn describe_rpc_error(method: &str, code: connectrpc::ErrorCode) -> String {
    format!("{method} failed: {}{}", code.as_str(), rpc_hint(code))
}

pub struct MutationError {
    reason: &'static str,
    unknown: bool,
    hint: &'static str,
}

impl MutationError {
    fn rpc(code: connectrpc::ErrorCode) -> Self {
        use connectrpc::ErrorCode::*;
        // These codes reject the request. Other errors may follow a commit,
        // including transport failures, timeouts, and response decoding errors.
        // ResourceExhausted also covers local response-size/decode limits, so
        // its code alone cannot confirm a server rejection.
        let rejected = matches!(
            code,
            InvalidArgument
                | NotFound
                | AlreadyExists
                | PermissionDenied
                | FailedPrecondition
                | Aborted
                | OutOfRange
                | Unimplemented
                | Unauthenticated
        );
        Self {
            reason: code.as_str(),
            unknown: !rejected,
            hint: rpc_hint(code),
        }
    }

    fn unknown(reason: &'static str) -> Self {
        Self {
            reason,
            unknown: true,
            hint: "",
        }
    }

    pub fn describe_unsubscribe(&self) -> String {
        if self.unknown {
            format!(
                "DeleteEventSubscription outcome unknown: {}\nretry unsubscribe with the same subscription ID",
                self.reason
            )
        } else {
            format!(
                "DeleteEventSubscription failed: {}{}",
                self.reason, self.hint
            )
        }
    }

    pub fn describe(&self, method: &str, key: &Key) -> String {
        if self.unknown {
            format!(
                "{method} outcome unknown: {}{}\n{}",
                self.reason,
                self.hint,
                key.retry_instruction()
            )
        } else {
            format!("{method} failed: {}{}", self.reason, self.hint)
        }
    }
}

pub fn query_client(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> api::AsterApplicationServiceClient<HttpClient> {
    api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    )
}

pub async fn query(
    client: &api::AsterApplicationServiceClient<HttpClient>,
    request: &api::QueryEventsRequest,
    timeout: Duration,
) -> Result<api::QueryEventsResponse, connectrpc::ErrorCode> {
    let response = tokio::time::timeout(timeout, client.query_events(request.clone()))
        .await
        .map_err(|_| connectrpc::ErrorCode::DeadlineExceeded)?
        .map_err(|error| error.code)?;
    Ok(response.into_owned())
}

fn config(address: SocketAddr, token: &Token, timeout: Duration) -> ClientConfig {
    ClientConfig::new(
        format!("http://{address}")
            .parse()
            .expect("socket address URI"),
    )
    .with_protocol(Protocol::Connect)
    .with_default_header(http::header::AUTHORIZATION, token.header())
    .with_default_timeout(timeout)
    .with_default_max_message_size(4 * 1024 * 1024)
    .with_default_element_memory_limit(4 * 1024 * 1024)
}

pub async fn status(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> Result<api::GetStatusResponse, String> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response =
        tokio::time::timeout(timeout, client.get_status(api::GetStatusRequest::default()))
            .await
            .map_err(|_| describe_rpc_error("GetStatus", connectrpc::ErrorCode::DeadlineExceeded))?
            // A remote server can put arbitrary text, including credentials, into
            // error messages. Report only the protocol's fixed error code.
            .map_err(|error| describe_rpc_error("GetStatus", error.code))?;
    Ok(response.into_owned())
}

pub async fn publish(
    address: SocketAddr,
    token: &Token,
    request: api::PublishEventRequest,
    timeout: Duration,
) -> Result<api::PublishEventResponse, MutationError> {
    let ttl_ms = request.ttl_ms;
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response = tokio::time::timeout(timeout, client.publish_event(request))
        .await
        .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
        .map_err(|error| MutationError::rpc(error.code))?;
    let response = response.into_owned();
    if response.id.len() != 32 || response.publisher.len() != 32 {
        return Err(MutationError::unknown("invalid publication receipt"));
    }
    if ttl_ms.is_some() && response.ttl_ms != ttl_ms {
        return Err(MutationError::unknown(
            "agent did not confirm the requested TTL",
        ));
    }
    Ok(response)
}

pub async fn unsubscribe(
    address: SocketAddr,
    token: &Token,
    subscription_id: Vec<u8>,
    timeout: Duration,
) -> Result<api::DeleteEventSubscriptionResponse, MutationError> {
    let client = query_client(address, token, timeout);
    let response = tokio::time::timeout(
        timeout,
        client.delete_event_subscription(api::DeleteEventSubscriptionRequest {
            subscription_id,
            ..Default::default()
        }),
    )
    .await
    .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
    .map_err(|e| MutationError::rpc(e.code))?;
    Ok(response.into_owned())
}

pub async fn subscriptions(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> Result<api::ListEventSubscriptionsResponse, String> {
    let client = query_client(address, token, timeout);
    let response = tokio::time::timeout(
        timeout,
        client.list_event_subscriptions(api::ListEventSubscriptionsRequest::default()),
    )
    .await
    .map_err(|_| {
        describe_rpc_error(
            "ListEventSubscriptions",
            connectrpc::ErrorCode::DeadlineExceeded,
        )
    })?
    .map_err(|error| describe_rpc_error("ListEventSubscriptions", error.code))?;
    let response = response.into_owned();
    if response
        .subscriptions
        .iter()
        .any(|row| row.subscription_id.len() != 32)
    {
        return Err("ListEventSubscriptions failed: invalid subscription ID".to_owned());
    }
    Ok(response)
}

pub async fn subscribe(
    address: SocketAddr,
    token: &Token,
    request: api::CreateEventSubscriptionRequest,
    timeout: Duration,
) -> Result<api::CreateEventSubscriptionResponse, MutationError> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response = tokio::time::timeout(timeout, client.create_event_subscription(request))
        .await
        .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
        .map_err(|error| MutationError::rpc(error.code))?;
    let response = response.into_owned();
    if response.subscription_id.len() != 32 {
        return Err(MutationError::unknown("invalid subscription ID"));
    }
    Ok(response)
}
