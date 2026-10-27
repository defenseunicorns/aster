#[cfg(test)]
use crate::progress::NoProgress;
use crate::{
    api,
    auth::Token,
    blob_publish, blob_read,
    operation_key::Key,
    progress::{ProgressEvent, ProgressSink, ProgressSnapshot},
};
use buffa::Message as _;
use connectrpc::{
    Protocol,
    client::{ClientConfig, Http2Connection, HttpClient, SharedHttp2Connection},
};
use std::{
    cell::RefCell,
    fs::File,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct PublishProgress {
    sent: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    durable: Arc<AtomicU64>,
    total: u64,
}

impl PublishProgress {
    fn new(offset: u64, total: u64) -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(offset)),
            accepted: Arc::new(AtomicU64::new(offset)),
            durable: Arc::new(AtomicU64::new(offset)),
            total,
        }
    }

    fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            sent: self.sent.load(Ordering::Acquire),
            accepted: self.accepted.load(Ordering::Acquire),
            durable: self.durable.load(Ordering::Acquire),
            written: 0,
            total: self.total,
        }
    }

    fn report<P: ProgressSink>(
        &self,
        sink: &RefCell<P>,
        event: ProgressEvent,
    ) -> Result<(), MutationError> {
        sink.borrow_mut()
            .report(event, self.snapshot())
            .map_err(|_| MutationError::unknown("cannot write Blob progress; transfer cancelled"))
    }
}

pub struct BlobPublishFailure {
    error: MutationError,
    pub progress: ProgressSnapshot,
}

impl BlobPublishFailure {
    pub fn describe(&self, key: &Key) -> String {
        let description = self.error.describe("PublishBlob", key);
        let progress = format!(
            "progress before failure: sent={} accepted={} durable={} total={}",
            self.progress.sent, self.progress.accepted, self.progress.durable, self.progress.total,
        );
        if let Some((reason, retry)) = description.rsplit_once("\nretry the identical request") {
            return format!("{reason}\n{progress}\nretry the identical request{retry}");
        }
        format!("{description}\n{progress}")
    }
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub const BLOB_TRANSFER_DEFAULT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

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
    retryable_rejection: bool,
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
            retryable_rejection: false,
        }
    }

    fn rpc_error(error: &connectrpc::ConnectError, expected_operation: &str) -> Self {
        let mut classified = Self::rpc(error.code);
        let Some(detail) = public_error_detail(error, expected_operation) else {
            return classified;
        };
        if is_definite_publish_rejection(error.code, detail.reason.as_known()) {
            classified.unknown = false;
            classified.retryable_rejection = detail.retryable;
        }
        classified
    }

    fn unknown(reason: &'static str) -> Self {
        Self {
            reason,
            unknown: true,
            hint: "",
            retryable_rejection: false,
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
            let retry = if self.retryable_rejection {
                format!("\n{}", key.retry_instruction())
            } else {
                String::new()
            };
            format!("{method} failed: {}{}{}", self.reason, self.hint, retry)
        }
    }
}

fn is_definite_publish_rejection(
    code: connectrpc::ErrorCode,
    reason: Option<api::PublicErrorReason>,
) -> bool {
    use api::PublicErrorReason as Reason;
    use connectrpc::ErrorCode as Code;

    matches!(
        (code, reason),
        (
            Code::InvalidArgument,
            Some(Reason::MalformedInput | Reason::UnsupportedValue)
        ) | (Code::Unimplemented, Some(Reason::UnsupportedValue))
            | (Code::Aborted, Some(Reason::OperationKeyConflict))
            | (
                Code::NotFound,
                Some(Reason::MissingDurableObject | Reason::ExpiredOrRetired)
            )
            | (Code::PermissionDenied, Some(Reason::FailedPrecondition))
            | (Code::FailedPrecondition, Some(Reason::FailedPrecondition))
            | (
                Code::ResourceExhausted,
                Some(Reason::ResourceExhaustion | Reason::OperationCapacityExhausted)
            )
    )
}

fn public_error_detail(
    error: &connectrpc::ConnectError,
    expected_operation: &str,
) -> Option<api::PublicErrorDetail> {
    let [detail] = error.details.as_slice() else {
        return None;
    };
    if detail.debug.is_some()
        || !matches!(
            detail.type_url.as_str(),
            api::PublicErrorDetail::TYPE_URL
                | <api::PublicErrorDetail as buffa::MessageName>::FULL_NAME
        )
    {
        return None;
    }
    let value = decode_base64(detail.value.as_deref()?)?;
    let decoded = api::PublicErrorDetail::decode_from_slice(&value).ok()?;
    let reason = decoded.reason.as_known()?;
    if decoded.operation != expected_operation
        || reason == api::PublicErrorReason::Unspecified
        || !valid_public_error_pair(error.code, expected_operation, reason)
    {
        return None;
    }
    Some(decoded)
}

fn valid_public_error_pair(
    code: connectrpc::ErrorCode,
    operation: &str,
    reason: api::PublicErrorReason,
) -> bool {
    use api::PublicErrorReason as Reason;
    use connectrpc::ErrorCode as Code;

    let common = matches!(
        (code, reason),
        (
            Code::InvalidArgument,
            Reason::MalformedInput | Reason::UnsupportedValue
        ) | (Code::Unimplemented, Reason::UnsupportedValue)
            | (Code::PermissionDenied, Reason::FailedPrecondition)
            | (
                Code::Unavailable,
                Reason::FailedPrecondition | Reason::StateUnavailable
            )
            | (Code::DataLoss | Code::Internal, Reason::Internal)
            | (
                Code::ResourceExhausted,
                Reason::ResourceExhaustion | Reason::OperationCapacityExhausted
            )
    );
    common
        || match operation {
            "publish_blob" => matches!(
                (code, reason),
                (Code::Aborted, Reason::OperationKeyConflict)
                    | (Code::FailedPrecondition, Reason::FailedPrecondition)
                    | (
                        Code::NotFound,
                        Reason::MissingDurableObject | Reason::ExpiredOrRetired
                    )
            ),
            "read_blob" => matches!(
                (code, reason),
                (
                    Code::NotFound,
                    Reason::MissingDurableObject | Reason::ExpiredOrRetired
                )
            ),
            _ => false,
        }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    if value.is_empty() {
        return None;
    }
    let padding = if value.ends_with("==") {
        2
    } else if value.ends_with('=') {
        1
    } else {
        0
    };
    if (padding != 0 && !value.len().is_multiple_of(4)) || (padding == 0 && value.len() % 4 == 1) {
        return None;
    }
    let unpadded = &value[..value.len() - padding];
    if unpadded.as_bytes().contains(&b'=') {
        return None;
    }
    let bytes = unpadded.as_bytes();
    if bytes.len() % 4 == 1
        || (padding == 2 && bytes.len() % 4 != 2)
        || (padding == 1 && bytes.len() % 4 != 3)
    {
        return None;
    }
    let mut output = Vec::with_capacity((bytes.len() * 3) / 4);
    for chunk in bytes.chunks(4) {
        let a = sextet(chunk[0])?;
        let b = sextet(chunk[1])?;
        if chunk.len() == 2 && b & 0x0f != 0 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        if chunk.len() > 2 {
            let c = sextet(chunk[2])?;
            if chunk.len() == 3 && c & 0x03 != 0 {
                return None;
            }
            output.push((b << 4) | (c >> 2));
            if chunk.len() > 3 {
                output.push((c << 6) | sextet(chunk[3])?);
            }
        }
    }
    Some(output)
}

fn describe_blob_read_error(error: &connectrpc::ConnectError) -> String {
    let reason = public_error_detail(error, "read_blob")
        .and_then(|detail| detail.reason.as_known())
        .map(|reason| match reason {
            api::PublicErrorReason::MissingDurableObject => "missing Blob",
            api::PublicErrorReason::ExpiredOrRetired => "Blob expired or retired",
            _ => error.code.as_str(),
        })
        .unwrap_or_else(|| error.code.as_str());
    format!("ReadBlob failed: {reason}{}", rpc_hint(error.code))
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
    protocol_config(address, token, timeout, Protocol::Connect)
}

fn protocol_config(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
    protocol: Protocol,
) -> ClientConfig {
    ClientConfig::new(
        format!("http://{address}")
            .parse()
            .expect("socket address URI"),
    )
    .with_protocol(protocol)
    .with_default_header(http::header::AUTHORIZATION, token.header())
    .with_default_timeout(timeout)
    .with_default_max_message_size(4 * 1024 * 1024)
    .with_default_element_memory_limit(4 * 1024 * 1024)
}

fn blob_client(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> api::AsterApplicationServiceClient<SharedHttp2Connection> {
    let uri = format!("http://{address}")
        .parse()
        .expect("socket address URI");
    let transport = Http2Connection::lazy_plaintext(uri).shared(1);
    api::AsterApplicationServiceClient::new(
        transport,
        protocol_config(address, token, timeout, Protocol::Grpc),
    )
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

pub async fn inspect_blob_publication(
    client: &api::AsterApplicationServiceClient<HttpClient>,
    request: api::InspectBlobPublicationRequest,
) -> Result<api::InspectBlobPublicationResponse, String> {
    let expected_id = request.publication_id.clone();
    let response = client
        .inspect_blob_publication(request)
        .await
        .map_err(|error| describe_rpc_error("InspectBlobPublication", error.code))?
        .into_owned();
    if !blob_inspection_is_valid(&expected_id, &response) {
        return Err("InspectBlobPublication failed: invalid status response".to_owned());
    }
    Ok(response)
}

fn blob_inspection_is_valid(
    expected_id: &[u8],
    response: &api::InspectBlobPublicationResponse,
) -> bool {
    let Some(phase) = response.phase.as_known() else {
        return false;
    };
    if response.publication_id != expected_id
        || response.publication_id.len() != 32
        || !response.publication_id.iter().any(|byte| *byte != 0)
        || response.durable_plaintext_bytes > response.plaintext_total_bytes
        || response.durable_transfer_bytes > response.transfer_total_bytes
        || response.durable_units > response.total_units
        || response
            .blob_id
            .as_ref()
            .is_some_and(|blob_id| blob_id.len() != 32)
    {
        return false;
    }
    let empty = response.plaintext_total_bytes == 0
        && response.durable_plaintext_bytes == 0
        && response.transfer_total_bytes == 0
        && response.durable_transfer_bytes == 0
        && response.total_units == 0
        && response.durable_units == 0
        && response.blob_id.is_none();
    let totals_consistent = if response.plaintext_total_bytes == 0 {
        response.transfer_total_bytes == 0 && response.total_units == 0
    } else {
        response.transfer_total_bytes != 0 && response.total_units != 0
    };
    let complete = response.durable_plaintext_bytes == response.plaintext_total_bytes
        && response.durable_transfer_bytes == response.transfer_total_bytes
        && response.durable_units == response.total_units;
    match phase {
        api::BlobPublicationPhase::Unspecified => false,
        api::BlobPublicationPhase::Missing | api::BlobPublicationPhase::ExpiredOrRetired => empty,
        api::BlobPublicationPhase::AwaitingData => {
            totals_consistent
                && response.durable_plaintext_bytes == 0
                && response.durable_transfer_bytes == 0
                && response.durable_units == 0
                && response.blob_id.is_none()
        }
        api::BlobPublicationPhase::Receiving => {
            totals_consistent
                && response.plaintext_total_bytes != 0
                && !complete
                && (response.durable_plaintext_bytes != 0
                    || response.durable_transfer_bytes != 0
                    || response.durable_units != 0)
                && response.blob_id.is_none()
        }
        api::BlobPublicationPhase::ReadyToFinalize => {
            totals_consistent && complete && response.blob_id.is_none()
        }
        api::BlobPublicationPhase::Available => {
            totals_consistent && complete && response.blob_id.is_some()
        }
    }
}

pub fn publication_sdk(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
    identity: &crate::journal::Identity,
) -> Result<aster_agent::sdk::NumberedEventSdk<HttpClient>, String> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    aster_agent::sdk::NumberedEventSdk::open(client, &identity.path, &identity.client_id)
        .map_err(crate::journal::describe_error)
}

#[cfg(test)]
pub async fn publish_blob(
    address: SocketAddr,
    token: &Token,
    metadata: api::PublishBlobMetadata,
    file: File,
    timeout: Duration,
) -> Result<api::PublishBlobReceipt, MutationError> {
    let progress = RefCell::new(NoProgress);
    publish_blob_with_progress(address, token, metadata, file, timeout, &progress)
        .await
        .map_err(|failure| failure.error)
}

pub async fn publish_blob_with_progress<P: ProgressSink>(
    address: SocketAddr,
    token: &Token,
    metadata: api::PublishBlobMetadata,
    file: File,
    timeout: Duration,
    progress: &RefCell<P>,
) -> Result<api::PublishBlobReceipt, BlobPublishFailure> {
    publish_blob_with_progress_and_chunk_bytes(
        address,
        token,
        metadata,
        file,
        timeout,
        progress,
        blob_publish::CHUNK_BYTES,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn publish_blob_with_progress_and_chunk_bytes<P: ProgressSink>(
    address: SocketAddr,
    token: &Token,
    metadata: api::PublishBlobMetadata,
    file: File,
    timeout: Duration,
    progress: &RefCell<P>,
    chunk_bytes: usize,
) -> Result<api::PublishBlobReceipt, BlobPublishFailure> {
    assert!(
        chunk_bytes > 0 && chunk_bytes <= blob_publish::CHUNK_BYTES,
        "Blob publish chunk bound must be within the production limit"
    );
    let progress_state = PublishProgress::new(0, metadata.total_len);
    let failure_state = progress_state.clone();
    let transfer = async {
        let requested = metadata.clone();
        let total_len = metadata.total_len;
        let mut rpc = blob_client(address, token, timeout)
            .publish_blob()
            .await
            .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?;
        rpc.send(api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                metadata,
            ))),
            ..Default::default()
        })
        .await
        .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?;
        let accepted = rpc
            .message::<api::PublishBlobResponse>()
            .await
            .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?
            .ok_or_else(|| MutationError::unknown("agent ended Blob upload before acceptance"))?
            .to_owned_message();
        let api::publish_blob_response::Frame::Accepted(accepted) = accepted
            .frame
            .ok_or_else(|| MutationError::unknown("agent omitted Blob acceptance"))?
        else {
            return Err(MutationError::unknown(
                "agent sent Blob progress before acceptance",
            ));
        };
        if accepted.accepted_offset != accepted.durable_offset
            || accepted.canonical_frame_bytes != chunk_bytes as u32
            || accepted.publication_id.len() != 32
            || !accepted.publication_id.iter().any(|byte| *byte != 0)
            || accepted.durable_offset > total_len
            || (accepted.durable_offset != total_len
                && !accepted.durable_offset.is_multiple_of(chunk_bytes as u64))
        {
            return Err(MutationError::unknown(
                "agent returned an invalid Blob resume offset",
            ));
        }
        let publication_id = accepted.publication_id.clone();
        let resume_offset = accepted.durable_offset;
        progress_state.sent.store(resume_offset, Ordering::Release);
        progress_state
            .accepted
            .store(resume_offset, Ordering::Release);
        progress_state
            .durable
            .store(resume_offset, Ordering::Release);
        progress_state.report(progress, ProgressEvent::Initial)?;
        let (mut send, mut receive) = rpc.into_split();
        let (mut frames, reader) =
            blob_publish::stream_file_with_chunk_bytes(file, total_len, resume_offset, chunk_bytes);
        let sender_progress = progress_state.clone();
        let sender = async move {
            while let Some(frame) = frames.next().await {
                let end = match frame.frame.as_ref() {
                    Some(api::publish_blob_request::Frame::Data(data)) => data
                        .offset
                        .checked_add(data.bytes.len() as u64)
                        .ok_or_else(|| MutationError::unknown("Blob request offset overflow"))?,
                    _ => return Err(MutationError::unknown("invalid local Blob data frame")),
                };
                send.send(frame)
                    .await
                    .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?;
                sender_progress.sent.store(end, Ordering::Release);
                sender_progress.report(progress, ProgressEvent::Periodic)?;
            }
            send.send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Finish(Box::default())),
                ..Default::default()
            })
            .await
            .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?;
            send.close_send();
            reader
                .await
                .map_err(|_| {
                    MutationError::unknown("source reader failed while request may have been sent")
                })?
                .map_err(MutationError::unknown)
        };
        let receiver_progress = progress_state.clone();
        let receiver = async move {
            let mut accepted_offset = resume_offset;
            let mut durable_offset = resume_offset;
            let mut receipt = None;
            while let Some(response) = receive
                .message::<api::PublishBlobResponse>()
                .await
                .map_err(|error| MutationError::rpc_error(&error, "publish_blob"))?
            {
                match response.to_owned_message().frame {
                    Some(api::publish_blob_response::Frame::Checkpoint(checkpoint))
                        if receipt.is_none()
                            && blob_publish::checkpoint_is_valid(
                                &checkpoint,
                                accepted_offset,
                                durable_offset,
                                receiver_progress.sent.load(Ordering::Acquire),
                                total_len,
                            ) =>
                    {
                        accepted_offset = checkpoint.accepted_offset;
                        durable_offset = checkpoint.durable_offset;
                        receiver_progress
                            .sent
                            .fetch_max(accepted_offset, Ordering::AcqRel);
                        receiver_progress
                            .accepted
                            .store(accepted_offset, Ordering::Release);
                        receiver_progress
                            .durable
                            .store(durable_offset, Ordering::Release);
                        receiver_progress.report(progress, ProgressEvent::Checkpoint)?;
                    }
                    Some(api::publish_blob_response::Frame::Complete(complete))
                        if receipt.is_none() =>
                    {
                        receipt = Some(*complete);
                    }
                    _ => {
                        return Err(MutationError::unknown(
                            "agent returned an invalid Blob progress sequence",
                        ));
                    }
                }
            }
            receipt.ok_or_else(|| MutationError::unknown("agent omitted Blob completion"))
        };
        let ((), response) = tokio::try_join!(sender, receiver)?;
        if response.publication_id != publication_id
            || !blob_publish::receipt_matches(&requested, &response)
        {
            return Err(MutationError::unknown("invalid publication receipt"));
        }
        progress_state.sent.store(total_len, Ordering::Release);
        progress_state.accepted.store(total_len, Ordering::Release);
        progress_state.durable.store(total_len, Ordering::Release);
        progress_state.report(progress, ProgressEvent::Terminal)?;
        Ok(response)
    };
    let result = tokio::time::timeout(timeout, transfer)
        .await
        .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))
        .and_then(|result| result);
    result.map_err(|error| BlobPublishFailure {
        error,
        progress: failure_state.snapshot(),
    })
}

#[cfg(all(test, target_os = "linux"))]
pub async fn read_blob(
    address: SocketAddr,
    token: &Token,
    request: api::ReadBlobRequest,
    output_path: PathBuf,
    timeout: Duration,
) -> Result<blob_read::Metadata, String> {
    let mut progress = NoProgress;
    read_blob_with_progress(address, token, request, output_path, timeout, &mut progress).await
}

pub async fn read_blob_with_progress<P: ProgressSink>(
    address: SocketAddr,
    token: &Token,
    request: api::ReadBlobRequest,
    output_path: PathBuf,
    timeout: Duration,
    progress: &mut P,
) -> Result<blob_read::Metadata, String> {
    read_blob_with_progress_and_page_bytes(
        address,
        token,
        request,
        output_path,
        timeout,
        progress,
        blob_read::RPC_PAGE_BYTES,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn read_blob_with_progress_and_page_bytes<P: ProgressSink>(
    address: SocketAddr,
    token: &Token,
    request: api::ReadBlobRequest,
    output_path: PathBuf,
    timeout: Duration,
    progress: &mut P,
    page_bytes: usize,
) -> Result<blob_read::Metadata, String> {
    assert!(
        page_bytes > 0 && page_bytes <= blob_read::RPC_PAGE_BYTES,
        "Blob read page bound must be within the production limit"
    );
    let mut output = blob_read::OutputFile::create(output_path).map_err(str::to_owned)?;
    let mut validator = blob_read::Validator::new(request.clone()).with_max_page_bytes(page_bytes);
    let mut written = 0_u64;
    let mut started = false;
    let transfer: Result<blob_read::Metadata, String> = async {
        let mut stream = blob_client(address, token, timeout)
            .read_blob(request)
            .await
            .map_err(|error| describe_blob_read_error(&error))?;
        while let Some(page) = stream
            .message()
            .await
            .map_err(|error| describe_blob_read_error(&error))?
        {
            let page = page.to_owned_message();
            validator.accept(&page).map_err(str::to_owned)?;
            if !started {
                progress
                    .report(
                        ProgressEvent::Initial,
                        ProgressSnapshot {
                            total: page.total_len,
                            ..Default::default()
                        },
                    )
                    .map_err(|_| "cannot write Blob progress; read cancelled".to_owned())?;
                started = true;
            }
            output.write_page(&page.chunk).map_err(str::to_owned)?;
            written = written
                .checked_add(page.chunk.len() as u64)
                .ok_or_else(|| "ReadBlob failed: written byte count overflow".to_owned())?;
            progress
                .report(
                    if page.complete {
                        ProgressEvent::Checkpoint
                    } else {
                        ProgressEvent::Periodic
                    },
                    ProgressSnapshot {
                        written,
                        total: page.total_len,
                        ..Default::default()
                    },
                )
                .map_err(|_| "cannot write Blob progress; read cancelled".to_owned())?;
        }
        let metadata = validator.finish().map_err(str::to_owned)?;
        progress
            .report(
                ProgressEvent::Terminal,
                ProgressSnapshot {
                    written,
                    total: metadata.total_len,
                    ..Default::default()
                },
            )
            .map_err(|_| "cannot write Blob progress; read cancelled".to_owned())?;
        Ok(metadata)
    }
    .await;
    match transfer {
        Ok(metadata) => match output.finish() {
            Ok(()) => Ok(metadata),
            Err(error) => Err(discard_output(output, error.to_owned())),
        },
        Err(error) => Err(discard_output(
            output,
            format!(
                "{error}; discarded {written} authenticated bytes; destination was not published"
            ),
        )),
    }
}

fn discard_output(output: blob_read::OutputFile, error: String) -> String {
    drop(output);
    error
}

pub async fn unsubscribe(
    address: SocketAddr,
    token: &Token,
    subscription_id: Vec<u8>,
    identity: &crate::journal::Identity,
    timeout: Duration,
) -> Result<api::DeleteEventSubscriptionResponse, MutationError> {
    let client = query_client(address, token, timeout);
    let sdk = publication_sdk(address, token, timeout, identity)
        .map_err(|_| MutationError::unknown("client journal unavailable"))?;
    sdk.recover().await.map_err(|error| match error {
        aster_agent::sdk::NumberedEventSdkError::Transport(error) => MutationError::rpc(error.code),
        _ => MutationError::unknown("client recovery failed"),
    })?;
    let context = sdk
        .client_context()
        .map_err(|_| MutationError::unknown("client context unavailable"))?;
    let response = tokio::time::timeout(
        timeout,
        client.delete_event_subscription(api::DeleteEventSubscriptionRequest {
            client: context.into(),
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
    mut request: api::CreateEventSubscriptionRequest,
    identity: &crate::journal::Identity,
    timeout: Duration,
) -> Result<api::CreateEventSubscriptionResponse, MutationError> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let sdk = publication_sdk(address, token, timeout, identity)
        .map_err(|_| MutationError::unknown("client journal unavailable"))?;
    sdk.recover().await.map_err(|error| match error {
        aster_agent::sdk::NumberedEventSdkError::Transport(error) => MutationError::rpc(error.code),
        _ => MutationError::unknown("client recovery failed"),
    })?;
    request.client = sdk
        .client_context()
        .map_err(|_| MutationError::unknown("client context unavailable"))?
        .into();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_status_rejects_contradictory_or_regressed_counters() {
        let publication_id = vec![7; 32];
        let valid = api::InspectBlobPublicationResponse {
            publication_id: publication_id.clone(),
            phase: api::BlobPublicationPhase::Receiving.into(),
            plaintext_total_bytes: 10,
            durable_plaintext_bytes: 5,
            transfer_total_bytes: 12,
            durable_transfer_bytes: 6,
            total_units: 2,
            durable_units: 1,
            ..Default::default()
        };
        assert!(blob_inspection_is_valid(&publication_id, &valid));
        for invalid in [
            api::InspectBlobPublicationResponse {
                durable_plaintext_bytes: 11,
                ..valid.clone()
            },
            api::InspectBlobPublicationResponse {
                phase: api::BlobPublicationPhase::Available.into(),
                durable_plaintext_bytes: 10,
                durable_transfer_bytes: 12,
                durable_units: 2,
                ..valid.clone()
            },
            api::InspectBlobPublicationResponse {
                phase: api::BlobPublicationPhase::Missing.into(),
                ..valid
            },
        ] {
            assert!(!blob_inspection_is_valid(&publication_id, &invalid));
        }
    }

    #[test]
    fn blob_status_accepts_available_empty_publication() {
        let publication_id = vec![7; 32];
        assert!(blob_inspection_is_valid(
            &publication_id,
            &api::InspectBlobPublicationResponse {
                publication_id: publication_id.clone(),
                phase: api::BlobPublicationPhase::Available.into(),
                blob_id: Some(vec![9; 32]),
                ..Default::default()
            }
        ));
    }
    use std::{
        future::poll_fn,
        io,
        sync::{Arc, Mutex},
    };

    struct FailingProgress;

    impl ProgressSink for FailingProgress {
        fn report(&mut self, _event: ProgressEvent, _snapshot: ProgressSnapshot) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"))
        }
    }

    const SERVICE: &str = "aster.application.v1alpha1.AsterApplicationService";

    struct Fixture {
        address: SocketAddr,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn start(router: connectrpc::Router) -> Self {
            let bound = connectrpc::server::Server::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = bound.local_addr().unwrap();
            let (shutdown, stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                bound
                    .serve_with_graceful_shutdown(router, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
            Self {
                address,
                shutdown: Some(shutdown),
                task,
            }
        }

        async fn stop(mut self) {
            let _ = self.shutdown.take().unwrap().send(());
            self.task.await.unwrap();
        }
    }

    fn token() -> Token {
        Token::parse("asterctl-test-token-00000000000000".to_owned()).unwrap()
    }

    fn publish_metadata(total_len: u64) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"native-http2-fixture".to_vec(),
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(60_000),
            total_len,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            ..Default::default()
        }
    }

    fn receipt(metadata: &api::PublishBlobMetadata) -> api::PublishBlobReceipt {
        api::PublishBlobReceipt {
            publication_id: vec![3; 32],
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            priority: metadata.priority,
            ttl_ms: metadata.ttl_ms,
            total_len: metadata.total_len,
            media_type: metadata.media_type.clone(),
            schema_id: metadata.schema_id.clone(),
            acceptance_marker: 4,
            inserted: true,
            ..Default::default()
        }
    }

    fn read_page(
        total_len: u64,
        offset: u64,
        chunk: Vec<u8>,
        complete: bool,
    ) -> api::ReadBlobResponse {
        api::ReadBlobResponse {
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(60_000),
            total_len,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            acceptance_marker: 4,
            offset,
            chunk,
            complete,
            ..Default::default()
        }
    }

    fn test_path(suffix: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "asterctl-native-http2-{}-{}-{suffix}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[cfg(target_os = "linux")]
    fn private_test_directory(suffix: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = test_path(suffix);
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn blob_unknown_outcome_prints_exact_operation_key_retry_guidance() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        assert_eq!(
            MutationError::unknown("invalid publication receipt").describe("PublishBlob", &key),
            "PublishBlob outcome unknown: invalid publication receipt\nretry the identical request with --operation-key=blob-key"
        );
    }

    fn public_error(
        code: connectrpc::ErrorCode,
        reason: api::PublicErrorReason,
        operation: &str,
        retryable: bool,
    ) -> connectrpc::ConnectError {
        connectrpc::ConnectError::new(code, "secret remote diagnostic").with_detail(
            connectrpc::ErrorDetail::from_message(
                api::PublicErrorDetail::TYPE_URL,
                &api::PublicErrorDetail {
                    reason: reason.into(),
                    operation: operation.to_owned(),
                    retryable,
                    ..Default::default()
                },
            ),
        )
    }

    #[test]
    fn typed_blob_rejection_is_not_an_unknown_outcome() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let error = public_error(
            connectrpc::ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "publish_blob",
            false,
        );
        assert_eq!(
            MutationError::rpc_error(&error, "publish_blob").describe("PublishBlob", &key),
            "PublishBlob failed: resource_exhausted"
        );
        let retryable = public_error(
            connectrpc::ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "publish_blob",
            true,
        );
        assert_eq!(
            MutationError::rpc_error(&retryable, "publish_blob").describe("PublishBlob", &key),
            "PublishBlob failed: resource_exhausted\nretry the identical request with --operation-key=blob-key"
        );
        let uncertain = public_error(
            connectrpc::ErrorCode::Unavailable,
            api::PublicErrorReason::StateUnavailable,
            "publish_blob",
            true,
        );
        assert!(
            MutationError::rpc_error(&uncertain, "publish_blob")
                .describe("PublishBlob", &key)
                .starts_with("PublishBlob outcome unknown: unavailable")
        );
    }

    #[test]
    fn typed_blob_read_distinguishes_missing_from_expired_without_remote_text() {
        let missing = public_error(
            connectrpc::ErrorCode::NotFound,
            api::PublicErrorReason::MissingDurableObject,
            "read_blob",
            false,
        );
        assert_eq!(
            describe_blob_read_error(&missing),
            "ReadBlob failed: missing Blob"
        );
        let expired = public_error(
            connectrpc::ErrorCode::NotFound,
            api::PublicErrorReason::ExpiredOrRetired,
            "read_blob",
            false,
        );
        assert_eq!(
            describe_blob_read_error(&expired),
            "ReadBlob failed: Blob expired or retired"
        );
    }

    #[test]
    fn malformed_or_unexpected_public_details_remain_code_only_and_redacted() {
        let error = connectrpc::ConnectError::new(
            connectrpc::ErrorCode::ResourceExhausted,
            "secret remote diagnostic",
        )
        .with_detail(connectrpc::ErrorDetail {
            type_url: "type.googleapis.com/attacker.Error".into(),
            value: Some("not-protobuf".into()),
            debug: Some(serde_json::json!({"operation": "attacker-controlled"})),
        });
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let rendered =
            MutationError::rpc_error(&error, "publish_blob").describe("PublishBlob", &key);
        assert!(rendered.starts_with("PublishBlob outcome unknown: resource_exhausted"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("attacker"));

        let wrong_operation = public_error(
            connectrpc::ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "attacker-operation",
            true,
        );
        assert!(
            MutationError::rpc_error(&wrong_operation, "publish_blob")
                .describe("PublishBlob", &key)
                .starts_with("PublishBlob outcome unknown: resource_exhausted")
        );
        let unknown_reason = connectrpc::ConnectError::new(
            connectrpc::ErrorCode::ResourceExhausted,
            "secret remote diagnostic",
        )
        .with_detail(connectrpc::ErrorDetail::from_message(
            api::PublicErrorDetail::TYPE_URL,
            &api::PublicErrorDetail {
                reason: buffa::EnumValue::Unknown(71),
                operation: "publish_blob".to_owned(),
                retryable: true,
                ..Default::default()
            },
        ));
        assert!(
            MutationError::rpc_error(&unknown_reason, "publish_blob")
                .describe("PublishBlob", &key)
                .starts_with("PublishBlob outcome unknown: resource_exhausted")
        );

        assert!(decode_base64("AA=").is_none());
        assert!(decode_base64("A/==").is_none());
        assert!(decode_base64("AAAA====").is_none());
    }

    #[test]
    fn contradictory_typed_codes_cannot_override_conservative_blob_outcomes() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        for code in [
            connectrpc::ErrorCode::Unavailable,
            connectrpc::ErrorCode::DeadlineExceeded,
            connectrpc::ErrorCode::Internal,
        ] {
            let publish = public_error(
                code,
                api::PublicErrorReason::ResourceExhaustion,
                "publish_blob",
                true,
            );
            let rendered =
                MutationError::rpc_error(&publish, "publish_blob").describe("PublishBlob", &key);
            assert!(
                rendered.starts_with(&format!("PublishBlob outcome unknown: {}", code.as_str()))
            );
            assert!(rendered.contains("retry the identical request"));
            assert!(!rendered.contains("secret remote diagnostic"));

            let read = public_error(
                code,
                api::PublicErrorReason::ExpiredOrRetired,
                "read_blob",
                true,
            );
            let rendered = describe_blob_read_error(&read);
            assert!(rendered.starts_with(&format!("ReadBlob failed: {}", code.as_str())));
            assert!(!rendered.contains("expired"));
            assert!(!rendered.contains("secret remote diagnostic"));
        }
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_covers_multi_page_publish_and_read_clients() {
        const TEST_FRAME_BYTES: usize = 4;
        const TEST_TOTAL_BYTES: usize = TEST_FRAME_BYTES + 1;
        let payload = vec![0x5a; TEST_TOTAL_BYTES];
        let metadata = publish_metadata(payload.len() as u64);
        let expected_receipt = receipt(&metadata);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_by_handler = Arc::clone(&observed);
        let publish_response = expected_receipt.clone();
        let router = connectrpc::Router::new()
            .route_bidi_stream(
                SERVICE,
                "PublishBlob",
                connectrpc::bidi_streaming_handler_fn(
                    move |_ctx, requests: connectrpc::ServiceStream<api::PublishBlobRequest>| {
                        let observed = Arc::clone(&observed_by_handler);
                        let response = publish_response.clone();
                        async move {
                            let responses = futures::stream::try_unfold(
                                (requests, observed, response, 0_u8),
                                |(mut requests, observed, response, phase)| async move {
                                    match phase {
                                        0 => Ok(Some((
                                            api::PublishBlobResponse {
                                                frame: Some(
                                                    api::publish_blob_response::Frame::Accepted(
                                                        Box::new(api::PublishBlobAccepted {
                                                            canonical_frame_bytes: TEST_FRAME_BYTES
                                                                as u32,
                                                            publication_id: vec![3; 32],
                                                            ..Default::default()
                                                        }),
                                                    ),
                                                ),
                                                ..Default::default()
                                            },
                                            (requests, observed, response, 1),
                                        ))),
                                        1 => {
                                            let mut frames = Vec::new();
                                            while let Some(frame) = poll_fn(|context| {
                                                requests.as_mut().poll_next(context)
                                            })
                                            .await
                                            {
                                                frames.push(frame?);
                                            }
                                            *observed.lock().unwrap() = frames;
                                            Ok(Some((
                                                api::PublishBlobResponse {
                                                    frame: Some(
                                                        api::publish_blob_response::Frame::Complete(
                                                            Box::new(response.clone()),
                                                        ),
                                                    ),
                                                    ..Default::default()
                                                },
                                                (requests, observed, response, 2),
                                            )))
                                        }
                                        _ => Ok(None),
                                    }
                                },
                            );
                            connectrpc::Response::stream_ok(responses)
                        }
                    },
                ),
            )
            .route_server_stream(
                SERVICE,
                "ReadBlob",
                connectrpc::streaming_handler_fn(
                    |_ctx, _request: api::ReadBlobRequest| async move {
                        connectrpc::Response::stream_ok(connectrpc::stream_iter([
                            Ok(read_page(
                                TEST_TOTAL_BYTES as u64,
                                0,
                                vec![0x5a; TEST_FRAME_BYTES],
                                false,
                            )),
                            Ok(read_page(
                                TEST_TOTAL_BYTES as u64,
                                TEST_FRAME_BYTES as u64,
                                vec![0x5a],
                                true,
                            )),
                        ]))
                    },
                ),
            );
        let fixture = Fixture::start(router).await;
        let source = test_path("source");
        #[cfg(target_os = "linux")]
        let destination_directory = private_test_directory("destination-directory");
        #[cfg(target_os = "linux")]
        let destination = destination_directory.join("destination");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, &payload).unwrap();

        let progress = RefCell::new(NoProgress);
        let response = match publish_blob_with_progress_and_chunk_bytes(
            fixture.address,
            &token(),
            metadata,
            File::open(&source).unwrap(),
            Duration::from_secs(2),
            &progress,
            TEST_FRAME_BYTES,
        )
        .await
        {
            Ok(response) => response,
            Err(failure) => panic!(
                "{}",
                failure.error.describe(
                    "PublishBlob",
                    &crate::operation_key::Selection::Explicit("native-http2-fixture".to_owned())
                        .resolve()
                        .unwrap()
                )
            ),
        };
        assert_eq!(response, expected_receipt);
        {
            let frames = observed.lock().unwrap();
            assert_eq!(frames.len(), 4);
            assert!(matches!(
                frames[0].frame,
                Some(api::publish_blob_request::Frame::Metadata(_))
            ));
            assert!(matches!(
                frames[1].frame.as_ref(),
                Some(api::publish_blob_request::Frame::Data(chunk))
                    if chunk.offset == 0 && chunk.bytes.len() == TEST_FRAME_BYTES
            ));
            assert!(matches!(
                frames[2].frame.as_ref(),
                Some(api::publish_blob_request::Frame::Data(chunk))
                    if chunk.offset == TEST_FRAME_BYTES as u64 && chunk.bytes.len() == 1
            ));
            assert!(matches!(
                frames[3].frame,
                Some(api::publish_blob_request::Frame::Finish(_))
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let request = api::ReadBlobRequest {
                id: vec![1; 32],
                topic: "imagery.maps".into(),
                scope: "mission/team/alpha".into(),
                ..Default::default()
            };
            let mut progress = NoProgress;
            let read = read_blob_with_progress_and_page_bytes(
                fixture.address,
                &token(),
                request,
                destination.clone(),
                Duration::from_secs(2),
                &mut progress,
                TEST_FRAME_BYTES,
            )
            .await
            .unwrap();
            assert_eq!(read.total_len, payload.len() as u64);
            assert_eq!(std::fs::read(&destination).unwrap(), payload);
        }

        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
        #[cfg(target_os = "linux")]
        std::fs::remove_dir_all(destination_directory).unwrap();
    }

    async fn publish_error(error: connectrpc::ConnectError) -> MutationError {
        let router = connectrpc::Router::new().route_bidi_stream(
            SERVICE,
            "PublishBlob",
            connectrpc::bidi_streaming_handler_fn(
                move |_ctx, _requests: connectrpc::ServiceStream<api::PublishBlobRequest>| {
                    let error = error.clone();
                    async move {
                        connectrpc::Response::stream_ok(connectrpc::stream_iter([Err::<
                            api::PublishBlobResponse,
                            _,
                        >(
                            error
                        )]))
                    }
                },
            ),
        );
        let fixture = Fixture::start(router).await;
        let source = test_path("error-source");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, b"x").unwrap();
        let error = publish_blob(
            fixture.address,
            &token(),
            publish_metadata(1),
            File::open(&source).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
        error
    }

    #[tokio::test]
    async fn concurrent_publish_error_fixtures_keep_their_sources_isolated() {
        let (rejected, unavailable) = tokio::join!(
            publish_error(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::InvalidArgument,
                "fixture rejection",
            )),
            publish_error(connectrpc::ConnectError::unavailable("fixture unavailable")),
        );
        assert_eq!(rejected.reason, "invalid_argument");
        assert!(!rejected.unknown);
        assert_eq!(unavailable.reason, "unavailable");
        assert!(unavailable.unknown);
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_preserves_rpc_error_and_unknown_outcome_classification() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let rejected = publish_error(connectrpc::ConnectError::new(
            connectrpc::ErrorCode::InvalidArgument,
            "secret fixture detail",
        ))
        .await;
        assert_eq!(
            rejected.describe("PublishBlob", &key),
            "PublishBlob failed: invalid_argument"
        );
        let uncertain = publish_error(connectrpc::ConnectError::new(
            connectrpc::ErrorCode::Unavailable,
            "secret fixture detail",
        ))
        .await;
        assert_eq!(
            uncertain.describe("PublishBlob", &key),
            "PublishBlob outcome unknown: unavailable\nCheck that aster-agent is running and that --host and --port are correct.\nretry the identical request with --operation-key=blob-key"
        );
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_uses_only_valid_typed_public_errors() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let rejected = publish_error(public_error(
            connectrpc::ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            "publish_blob",
            true,
        ))
        .await;
        assert_eq!(
            rejected.describe("PublishBlob", &key),
            "PublishBlob failed: resource_exhausted\nretry the identical request with --operation-key=blob-key"
        );

        let malformed = publish_error(
            connectrpc::ConnectError::new(
                connectrpc::ErrorCode::ResourceExhausted,
                "secret fixture detail",
            )
            .with_detail(connectrpc::ErrorDetail {
                type_url: "type.googleapis.com/attacker.Error".into(),
                value: Some("not-protobuf".into()),
                debug: None,
            }),
        )
        .await;
        let rendered = malformed.describe("PublishBlob", &key);
        assert!(rendered.starts_with("PublishBlob outcome unknown: resource_exhausted"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("attacker"));
    }

    #[tokio::test]
    async fn publish_timeout_reports_sent_accepted_durable_total_and_retry() {
        let router = connectrpc::Router::new().route_bidi_stream(
            SERVICE,
            "PublishBlob",
            connectrpc::bidi_streaming_handler_fn(
                |_ctx, _requests: connectrpc::ServiceStream<api::PublishBlobRequest>| async move {
                    let responses = futures::stream::try_unfold(false, |accepted| async move {
                        if !accepted {
                            return Ok(Some((
                                api::PublishBlobResponse {
                                    frame: Some(api::publish_blob_response::Frame::Accepted(
                                        Box::new(api::PublishBlobAccepted {
                                            canonical_frame_bytes: blob_publish::CHUNK_BYTES as u32,
                                            publication_id: vec![3; 32],
                                            ..Default::default()
                                        }),
                                    )),
                                    ..Default::default()
                                },
                                true,
                            )));
                        }
                        std::future::pending::<()>().await;
                        Ok(None)
                    });
                    connectrpc::Response::stream_ok(responses)
                },
            ),
        );
        let fixture = Fixture::start(router).await;
        let source = test_path("deadline-source");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, b"x").unwrap();
        let progress = RefCell::new(NoProgress);
        let error = publish_blob_with_progress(
            fixture.address,
            &token(),
            publish_metadata(1),
            File::open(&source).unwrap(),
            Duration::from_millis(20),
            &progress,
        )
        .await
        .unwrap_err();
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let description = error.describe(&key);
        assert!(description.contains("PublishBlob outcome unknown: deadline_exceeded"));
        assert!(description.contains("--operation-key=blob-key"));
        assert!(
            description.contains("sent=1 accepted=0 durable=0 total=1"),
            "{description}"
        );
        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
    }

    #[tokio::test]
    async fn broken_publish_stderr_prevents_success() {
        let router = connectrpc::Router::new().route_bidi_stream(
            SERVICE,
            "PublishBlob",
            connectrpc::bidi_streaming_handler_fn(
                |_ctx, _requests: connectrpc::ServiceStream<api::PublishBlobRequest>| async move {
                    connectrpc::Response::stream_ok(connectrpc::stream_iter([Ok(
                        api::PublishBlobResponse {
                            frame: Some(api::publish_blob_response::Frame::Accepted(Box::new(
                                api::PublishBlobAccepted {
                                    canonical_frame_bytes: blob_publish::CHUNK_BYTES as u32,
                                    publication_id: vec![3; 32],
                                    ..Default::default()
                                },
                            ))),
                            ..Default::default()
                        },
                    )]))
                },
            ),
        );
        let fixture = Fixture::start(router).await;
        let source = test_path("broken-publish-progress-source");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, b"x").unwrap();
        let progress = RefCell::new(FailingProgress);
        let error = publish_blob_with_progress(
            fixture.address,
            &token(),
            publish_metadata(1),
            File::open(&source).unwrap(),
            Duration::from_secs(2),
            &progress,
        )
        .await
        .unwrap_err();
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let description = error.describe(&key);
        assert!(
            description.contains("cannot write Blob progress"),
            "{description}"
        );
        assert!(description.contains("sent=0 accepted=0 durable=0 total=1"));

        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn read_interruption_reports_discarded_bytes() {
        const TEST_PAGE_BYTES: usize = 4;
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(|_ctx, _request: api::ReadBlobRequest| async move {
                connectrpc::Response::stream_ok(connectrpc::stream_iter([
                    Ok(read_page(
                        (TEST_PAGE_BYTES + 1) as u64,
                        0,
                        vec![0x5a; TEST_PAGE_BYTES],
                        false,
                    )),
                    Err(connectrpc::ConnectError::unavailable(
                        "secret fixture detail",
                    )),
                ]))
            }),
        );
        let fixture = Fixture::start(router).await;
        let directory = private_test_directory("partial-directory");
        let destination = directory.join("destination");
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let mut progress = NoProgress;
        let error = read_blob_with_progress_and_page_bytes(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
            &mut progress,
            TEST_PAGE_BYTES,
        )
        .await
        .unwrap_err();
        assert!(error.contains("ReadBlob failed: unavailable"), "{error}");
        assert!(
            error.contains(&format!(
                "discarded {} authenticated bytes",
                TEST_PAGE_BYTES
            )),
            "{error}"
        );
        assert!(error.contains("destination was not published"), "{error}");
        assert!(!error.contains("secret fixture detail"), "{error}");
        assert!(!destination.exists());
        fixture.stop().await;
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn broken_read_stderr_does_not_publish_destination() {
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(|_ctx, _request: api::ReadBlobRequest| async move {
                connectrpc::Response::stream_ok(connectrpc::stream_iter([Ok(read_page(
                    b"authenticated".len() as u64 + 1,
                    0,
                    b"authenticated".to_vec(),
                    false,
                ))]))
            }),
        );
        let fixture = Fixture::start(router).await;
        let directory = private_test_directory("broken-progress-directory");
        let destination = directory.join("destination");
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let error = read_blob_with_progress(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
            &mut FailingProgress,
        )
        .await
        .unwrap_err();
        assert!(error.contains("progress"), "{error}");
        assert!(error.contains("discarded 0 authenticated bytes"), "{error}");
        assert!(!destination.exists());

        fixture.stop().await;
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn blob_native_http2_read_failure_removes_staged_partial_without_unrelated_damage() {
        let directory = private_test_directory("cleanup-directory");
        let destination = directory.join("destination");
        let unrelated = directory.join("unrelated");
        std::fs::write(&unrelated, b"unrelated contents").unwrap();
        let directory_by_handler = directory.clone();
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(move |_ctx, _request: api::ReadBlobRequest| {
                let directory = directory_by_handler.clone();
                async move {
                    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
                    connectrpc::Response::stream_ok(connectrpc::stream_iter([Err::<
                        api::ReadBlobResponse,
                        _,
                    >(
                        connectrpc::ConnectError::unavailable("fixture failure"),
                    )]))
                }
            }),
        );
        let fixture = Fixture::start(router).await;
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let error = read_blob(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(error.contains("ReadBlob failed: unavailable"), "{error}");
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated contents");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);

        fixture.stop().await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn empty_blob_read_succeeds_with_every_progress_mode() {
        use crate::progress::{ProgressKind, ProgressMode, ProgressReporter, SystemClock};
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(|_ctx, _request: api::ReadBlobRequest| async move {
                connectrpc::Response::stream_ok(connectrpc::stream_iter([Ok(read_page(
                    0,
                    0,
                    vec![],
                    true,
                ))]))
            }),
        );
        let fixture = Fixture::start(router).await;
        let directory = private_test_directory("empty-blob-progress");
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        for mode in [
            ProgressMode::Auto,
            ProgressMode::Never,
            ProgressMode::Always,
        ] {
            let destination = directory.join(format!("{mode:?}"));
            let mut reporter = ProgressReporter::new(
                Vec::new(),
                mode,
                false,
                ProgressKind::Read,
                SystemClock::start(),
            );
            read_blob_with_progress(
                fixture.address,
                &token(),
                request.clone(),
                destination.clone(),
                Duration::from_secs(2),
                &mut reporter,
            )
            .await
            .expect("valid empty Blob is published to the destination");
            assert_eq!(std::fs::read(destination).unwrap(), b"");
        }
        fixture.stop().await;
        std::fs::remove_dir_all(directory).unwrap();
    }
}
