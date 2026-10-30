use std::{path::Path, sync::Arc};

use aster_mesh::{MAX_BLOB_MEDIA_TYPE_BYTES, MAX_BLOB_SCHEMA_ID_BYTES};
use aster_node::application::{
    BlobId, BlobPublicationInspection, BlobPublicationInspectionRequest, BlobPublicationPhase,
    BlobPublishOptions, BlobPublishRequest as NodeBlobPublishRequest, BlobPublishResult,
    BlobPublishStreamRequest, BlobReadPage, BlobReadPageRequest,
    BlobReadRequest as NodeBlobReadRequest, BlobStreamPublicationId,
    MAX_SELECTED_BLOB_STREAM_BYTES, Priority, Scope, SelectedBlobHandle, Topic,
};
use aster_redb_store::MAX_BLOB_OPERATION_KEY_BYTES;
use connectrpc::{ConnectError, ErrorCode, RequestContext, Response, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use zeroize::Zeroizing;

use crate::{
    BLOB_RPC_FRAME_BYTES, api,
    error::{PublicOperation, connect_blob_application_error, public_error},
};

const UPLOAD_PERMITS: usize = 1;

#[derive(Clone)]
pub(crate) struct BlobConnectService {
    blobs: SelectedBlobHandle,
    uploads: Arc<tokio::sync::Semaphore>,
}

impl BlobConnectService {
    pub(crate) fn new(blobs: SelectedBlobHandle, _state_root: &Path) -> std::io::Result<Self> {
        Ok(Self {
            blobs,
            uploads: Arc::new(tokio::sync::Semaphore::new(UPLOAD_PERMITS)),
        })
    }

    pub(crate) async fn publish(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    ) -> ServiceResult<ServiceStream<api::PublishBlobResponse>> {
        let operation = PublicOperation::PublishBlob;
        if ctx.protocol() == Some(connectrpc::Protocol::GrpcWeb) {
            return Err(unsupported_transport(operation));
        }
        let first = requests
            .next()
            .await
            .ok_or_else(|| malformed(operation))?
            .map_err(|_| malformed(operation))?
            .to_owned_message();
        let (parsed, grammar) = UploadGrammar::start(first)?;
        let permit = Arc::clone(&self.uploads)
            .try_acquire_owned()
            .map_err(|_| resource_exhausted(operation))?;
        let stream = self
            .blobs
            .open_publish_stream(BlobPublishStreamRequest {
                publication: parsed.request,
                options: parsed.options,
                total_len: grammar.total_len,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        let durable_offset = stream.durable_offset();
        let publication_id = *stream.publication_id().as_bytes();
        let grammar = grammar.resume(durable_offset)?;
        let state = PublishStreamState {
            requests,
            stream: Some(stream),
            grammar: Some(grammar),
            durable_offset,
            publication_id,
            accepted_pending: true,
            complete: false,
            _permit: permit,
        };
        Response::stream_ok(futures::stream::try_unfold(state, next_publish_response))
    }

    pub(crate) async fn read(
        &self,
        request: api::ReadBlobRequest,
    ) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
        self.read_with_page_bytes(request, BLOB_RPC_FRAME_BYTES)
            .await
    }

    async fn read_with_page_bytes(
        &self,
        request: api::ReadBlobRequest,
        page_bytes: usize,
    ) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
        assert!(
            page_bytes > 0 && page_bytes <= BLOB_RPC_FRAME_BYTES,
            "Blob read page bound must be within the production limit"
        );
        let operation = PublicOperation::ReadBlob;
        let (request, topic, scope) = parse_read_request(request)?;
        let state = ReadStreamState {
            blobs: self.blobs.clone(),
            request,
            topic,
            scope,
            offset: 0,
            metadata: None,
            complete: false,
        };
        let responses = futures::stream::try_unfold(state, move |mut state| async move {
            if state.complete {
                return Ok(None);
            }
            let page = state
                .blobs
                .read_page(BlobReadPageRequest {
                    blob: state.request.clone(),
                    offset: state.offset,
                    max_bytes: page_bytes,
                })
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            let terminal_empty = page.is_empty()
                && page.offset == 0
                && page.next_offset() == 0
                && page.total_len == 0
                && page.complete
                && state.offset == 0
                && state.metadata.is_none();
            if page.offset != state.offset || (page.is_empty() && !terminal_empty) {
                return Err(internal(operation));
            }
            let observed = ReadMetadata::from_page(&page, &state.topic, &state.scope);
            if let Some(expected) = &state.metadata {
                ensure_stable_read_metadata(expected, &observed)?;
            } else {
                state.metadata = Some(observed.clone());
            }
            let next_offset = page.next_offset();
            let complete = page.complete;
            let page_len = u64::try_from(page.len()).map_err(|_| internal(operation))?;
            if page.offset.checked_add(page_len) != Some(next_offset)
                || page.len() > page_bytes
                || complete != (next_offset == observed.total_len)
            {
                return Err(internal(operation));
            }
            let metadata = state.metadata.as_ref().ok_or_else(|| internal(operation))?;
            let response = read_response(metadata, page.offset, page.as_bytes().to_vec(), complete);
            if (!terminal_empty && next_offset <= state.offset) || next_offset > observed.total_len
            {
                return Err(internal(operation));
            }
            state.offset = next_offset;
            state.complete = complete;
            Ok(Some((response, state)))
        });
        Response::stream_ok(responses)
    }

    pub(crate) async fn inspect(
        &self,
        request: api::InspectBlobPublicationRequest,
    ) -> ServiceResult<api::InspectBlobPublicationResponse> {
        let operation = PublicOperation::InspectBlobPublication;
        let publication_id_bytes: [u8; 32] = request
            .publication_id
            .as_slice()
            .try_into()
            .map_err(|_| malformed(operation))?;
        let publication_id = BlobStreamPublicationId::from_bytes(publication_id_bytes)
            .map_err(|_| malformed(operation))?;
        let inspection = self
            .blobs
            .inspect_publication(BlobPublicationInspectionRequest {
                publication_id,
                topic: Topic::new(request.topic).map_err(|_| malformed(operation))?,
                scope: Scope::new(request.scope).map_err(|_| malformed(operation))?,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        Response::ok(publication_status_message(inspection))
    }

    pub(crate) async fn capacity_status(
        &self,
    ) -> Result<
        aster_node::application::BlobCapacityStatus,
        aster_node::application::ApplicationError,
    > {
        self.blobs.capacity_status().await
    }
}

#[derive(Debug)]
struct ParsedPublish {
    request: NodeBlobPublishRequest,
    options: BlobPublishOptions,
}

#[derive(Debug)]
struct UploadGrammar {
    total_len: u64,
    received: u64,
    frames: u64,
    maximum_frames: u64,
    frame_bytes: usize,
}

impl UploadGrammar {
    fn start(first: api::PublishBlobRequest) -> Result<(ParsedPublish, Self), ConnectError> {
        Self::start_with_frame_bytes(first, BLOB_RPC_FRAME_BYTES)
    }

    fn start_with_frame_bytes(
        first: api::PublishBlobRequest,
        frame_bytes: usize,
    ) -> Result<(ParsedPublish, Self), ConnectError> {
        let operation = PublicOperation::PublishBlob;
        if frame_bytes == 0 || frame_bytes > BLOB_RPC_FRAME_BYTES {
            return Err(internal(operation));
        }
        let api::publish_blob_request::Frame::Metadata(metadata) =
            first.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if metadata.total_len == 0 {
            return Err(malformed(operation));
        }
        if metadata.total_len > MAX_SELECTED_BLOB_STREAM_BYTES {
            return Err(resource_exhausted(operation));
        }
        if metadata.operation_key.is_empty()
            || metadata.operation_key.len() > MAX_BLOB_OPERATION_KEY_BYTES
            || metadata
                .media_type
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_BLOB_MEDIA_TYPE_BYTES)
            || metadata.schema_id.len() > MAX_BLOB_SCHEMA_ID_BYTES
        {
            return Err(malformed(operation));
        }
        let priority = parse_priority(metadata.priority, operation)?;
        let topic = Topic::new(metadata.topic).map_err(|_| malformed(operation))?;
        let scope = Scope::new(metadata.scope).map_err(|_| malformed(operation))?;
        let options = match metadata.ttl_ms {
            None => BlobPublishOptions::durable(),
            Some(0) => return Err(malformed(operation)),
            Some(ttl_ms) => {
                BlobPublishOptions::finite_ttl_ms(ttl_ms).map_err(|_| malformed(operation))?
            }
        };
        let maximum_frames = maximum_chunk_frames_for_len(metadata.total_len, frame_bytes)?;
        Ok((
            ParsedPublish {
                request: NodeBlobPublishRequest {
                    operation_key: metadata.operation_key,
                    topic,
                    scope,
                    priority,
                    media_type: metadata.media_type,
                    schema_id: metadata.schema_id,
                },
                options,
            },
            Self {
                total_len: metadata.total_len,
                received: 0,
                frames: 0,
                maximum_frames,
                frame_bytes,
            },
        ))
    }

    #[cfg(test)]
    fn start_with_frame_bytes_for_test(
        first: api::PublishBlobRequest,
        frame_bytes: usize,
    ) -> Result<(ParsedPublish, Self), ConnectError> {
        assert!(
            frame_bytes > 0 && frame_bytes <= BLOB_RPC_FRAME_BYTES,
            "test frame bound must be within the production limit"
        );
        Self::start_with_frame_bytes(first, frame_bytes)
    }

    fn resume(mut self, durable_offset: u64) -> Result<Self, ConnectError> {
        if durable_offset > self.total_len
            || (durable_offset != self.total_len
                && !durable_offset.is_multiple_of(self.frame_bytes as u64))
        {
            return Err(internal(PublicOperation::PublishBlob));
        }
        self.received = durable_offset;
        self.frames = chunk_frames_for_len(durable_offset, self.frame_bytes)?;
        Ok(self)
    }

    fn accept(&mut self, frame: api::PublishBlobRequest) -> Result<Vec<u8>, ConnectError> {
        let operation = PublicOperation::PublishBlob;
        let api::publish_blob_request::Frame::Data(chunk) =
            frame.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if chunk.offset != self.received
            || chunk.bytes.is_empty()
            || chunk.bytes.len() > self.frame_bytes
        {
            return Err(malformed(operation));
        }
        let chunk_len = u64::try_from(chunk.bytes.len()).map_err(|_| malformed(operation))?;
        let remaining = self
            .total_len
            .checked_sub(self.received)
            .ok_or_else(|| malformed(operation))?;
        let canonical_len = remaining.min(self.frame_bytes as u64);
        if chunk_len != canonical_len {
            return Err(malformed(operation));
        }
        self.received = self
            .received
            .checked_add(chunk_len)
            .ok_or_else(|| malformed(operation))?;
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| malformed(operation))?;
        if self.frames > self.maximum_frames {
            return Err(malformed(operation));
        }
        Ok(chunk.bytes)
    }

    fn finish(self) -> Result<(), ConnectError> {
        if self.received == self.total_len && self.frames == self.maximum_frames {
            Ok(())
        } else {
            Err(malformed(PublicOperation::PublishBlob))
        }
    }
}

fn chunk_frames_for_len(len: u64, frame_bytes: usize) -> Result<u64, ConnectError> {
    if len == 0 {
        return Ok(0);
    }
    maximum_chunk_frames_for_len(len, frame_bytes)
}

struct PublishStreamState {
    requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    stream: Option<aster_node::application::SelectedBlobPublishStream>,
    grammar: Option<UploadGrammar>,
    durable_offset: u64,
    publication_id: [u8; 32],
    accepted_pending: bool,
    complete: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

async fn next_publish_response(
    mut state: PublishStreamState,
) -> Result<Option<(api::PublishBlobResponse, PublishStreamState)>, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    if state.complete {
        return Ok(None);
    }
    if state.accepted_pending {
        state.accepted_pending = false;
        return Ok(Some((
            publish_accepted(state.durable_offset, state.publication_id),
            state,
        )));
    }
    loop {
        let Some(frame) = state.requests.next().await else {
            return Err(malformed(operation));
        };
        let frame = frame.map_err(|_| malformed(operation))?.to_owned_message();
        if matches!(
            frame.frame,
            Some(api::publish_blob_request::Frame::Finish(_))
        ) {
            let grammar = state.grammar.take().ok_or_else(|| internal(operation))?;
            grammar.finish()?;
            if state.requests.next().await.is_some() {
                return Err(malformed(operation));
            }
            let stream = state.stream.take().ok_or_else(|| internal(operation))?;
            let result = stream
                .finish()
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            state.complete = true;
            return Ok(Some((publish_complete(result)?, state)));
        }
        let grammar = state.grammar.as_mut().ok_or_else(|| internal(operation))?;
        let offset = grammar.received;
        let chunk = Zeroizing::new(grammar.accept(frame)?);
        let stream = state.stream.as_mut().ok_or_else(|| internal(operation))?;
        let progress = stream
            .write(offset, chunk)
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        if progress.accepted_offset != grammar.received
            || progress.durable_offset < state.durable_offset
            || progress.durable_offset > progress.accepted_offset
        {
            return Err(internal(operation));
        }
        if progress.durable_offset > state.durable_offset {
            state.durable_offset = progress.durable_offset;
            return Ok(Some((publish_checkpoint(progress), state)));
        }
    }
}

fn maximum_chunk_frames_for_len(total_len: u64, frame_bytes: usize) -> Result<u64, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    let chunk_bytes = u64::try_from(frame_bytes).map_err(|_| internal(operation))?;
    if chunk_bytes == 0 {
        return Err(internal(operation));
    }
    total_len
        .checked_sub(1)
        .and_then(|value| value.checked_div(chunk_bytes))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| malformed(operation))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadMetadata {
    id: [u8; 32],
    publisher: [u8; 32],
    publisher_counter: u64,
    topic: String,
    scope: String,
    priority: Priority,
    ttl_ms: Option<u64>,
    total_len: u64,
    media_type: Option<String>,
    schema_id: Vec<u8>,
    acceptance_marker: u64,
}

impl ReadMetadata {
    fn from_page(page: &BlobReadPage, topic: &str, scope: &str) -> Self {
        Self {
            id: *page.id.as_bytes(),
            publisher: page.publisher,
            publisher_counter: page.publisher_counter,
            topic: topic.to_owned(),
            scope: scope.to_owned(),
            priority: page.priority,
            ttl_ms: page.ttl_ms,
            total_len: page.total_len,
            media_type: page.media_type.clone(),
            schema_id: page.schema_id.clone(),
            acceptance_marker: page.acceptance_marker,
        }
    }
}

struct ReadStreamState {
    blobs: SelectedBlobHandle,
    request: NodeBlobReadRequest,
    topic: String,
    scope: String,
    offset: u64,
    metadata: Option<ReadMetadata>,
    complete: bool,
}

fn ensure_stable_read_metadata(
    expected: &ReadMetadata,
    observed: &ReadMetadata,
) -> Result<(), ConnectError> {
    if expected == observed {
        Ok(())
    } else {
        Err(internal(PublicOperation::ReadBlob))
    }
}

fn parse_read_request(
    request: api::ReadBlobRequest,
) -> Result<(NodeBlobReadRequest, String, String), ConnectError> {
    let operation = PublicOperation::ReadBlob;
    let id: [u8; 32] = request
        .id
        .as_slice()
        .try_into()
        .map_err(|_| malformed(operation))?;
    let topic = Topic::new(request.topic).map_err(|_| malformed(operation))?;
    let scope = Scope::new(request.scope).map_err(|_| malformed(operation))?;
    let topic_name = topic.as_str().to_owned();
    let scope_name = scope.as_str().to_owned();
    Ok((
        NodeBlobReadRequest {
            id: BlobId::from_bytes(id),
            topic,
            scope,
        },
        topic_name,
        scope_name,
    ))
}

fn publish_accepted(offset: u64, publication_id: [u8; 32]) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Accepted(Box::new(
            api::PublishBlobAccepted {
                accepted_offset: offset,
                durable_offset: offset,
                canonical_frame_bytes: BLOB_RPC_FRAME_BYTES as u32,
                publication_id: publication_id.to_vec(),
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn publish_checkpoint(
    progress: aster_node::application::BlobPublishProgress,
) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Checkpoint(Box::new(
            api::PublishBlobCheckpoint {
                accepted_offset: progress.accepted_offset,
                durable_offset: progress.durable_offset,
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

fn publish_complete(result: BlobPublishResult) -> Result<api::PublishBlobResponse, ConnectError> {
    Ok(api::PublishBlobResponse {
        frame: Some(api::publish_blob_response::Frame::Complete(Box::new(
            publish_receipt(result)?,
        ))),
        ..Default::default()
    })
}

fn publish_receipt(result: BlobPublishResult) -> Result<api::PublishBlobReceipt, ConnectError> {
    let publication_id = result
        .publication_id
        .ok_or_else(|| internal(PublicOperation::PublishBlob))?;
    Ok(api::PublishBlobReceipt {
        id: result.id.as_bytes().to_vec(),
        publisher: result.publisher.to_vec(),
        publisher_counter: result.publisher_counter,
        priority: priority_message(result.priority).into(),
        ttl_ms: result.ttl_ms,
        total_len: result.total_len,
        media_type: result.media_type,
        schema_id: result.schema_id,
        acceptance_marker: result.acceptance_marker,
        inserted: result.inserted,
        publication_id: publication_id.as_bytes().to_vec(),
        ..Default::default()
    })
}

fn publication_status_message(
    inspection: BlobPublicationInspection,
) -> api::InspectBlobPublicationResponse {
    api::InspectBlobPublicationResponse {
        publication_id: inspection.publication_id.as_bytes().to_vec(),
        phase: match inspection.phase {
            BlobPublicationPhase::Missing => api::BlobPublicationPhase::Missing,
            BlobPublicationPhase::AwaitingData => api::BlobPublicationPhase::AwaitingData,
            BlobPublicationPhase::Receiving => api::BlobPublicationPhase::Receiving,
            BlobPublicationPhase::ReadyToFinalize => api::BlobPublicationPhase::ReadyToFinalize,
            BlobPublicationPhase::Available => api::BlobPublicationPhase::Available,
            BlobPublicationPhase::ExpiredOrRetired => api::BlobPublicationPhase::ExpiredOrRetired,
        }
        .into(),
        plaintext_total_bytes: inspection.plaintext_total_bytes,
        durable_plaintext_bytes: inspection.durable_plaintext_bytes,
        transfer_total_bytes: inspection.transfer_total_bytes,
        durable_transfer_bytes: inspection.durable_transfer_bytes,
        total_units: inspection.total_units,
        durable_units: inspection.durable_units,
        blob_id: inspection.blob_id.map(|id| id.as_bytes().to_vec()),
        ..Default::default()
    }
}

fn read_response(
    metadata: &ReadMetadata,
    offset: u64,
    chunk: Vec<u8>,
    complete: bool,
) -> api::ReadBlobResponse {
    api::ReadBlobResponse {
        id: metadata.id.to_vec(),
        publisher: metadata.publisher.to_vec(),
        publisher_counter: metadata.publisher_counter,
        topic: metadata.topic.clone(),
        scope: metadata.scope.clone(),
        priority: priority_message(metadata.priority).into(),
        ttl_ms: metadata.ttl_ms,
        total_len: metadata.total_len,
        media_type: metadata.media_type.clone(),
        schema_id: metadata.schema_id.clone(),
        acceptance_marker: metadata.acceptance_marker,
        offset,
        chunk,
        complete,
        ..Default::default()
    }
}

fn parse_priority(
    value: buffa::EnumValue<api::Priority>,
    operation: PublicOperation,
) -> Result<Priority, ConnectError> {
    match value.as_known() {
        Some(api::Priority::Routine) => Ok(Priority::Routine),
        Some(api::Priority::Priority) => Ok(Priority::Priority),
        Some(api::Priority::Immediate) => Ok(Priority::Immediate),
        Some(api::Priority::Flash) => Ok(Priority::Flash),
        Some(api::Priority::Unspecified) | None => Err(unsupported_value(operation)),
    }
}

const fn priority_message(priority: Priority) -> api::Priority {
    match priority {
        Priority::Routine => api::Priority::Routine,
        Priority::Priority => api::Priority::Priority,
        Priority::Immediate => api::Priority::Immediate,
        Priority::Flash => api::Priority::Flash,
    }
}

fn malformed(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::MalformedInput,
        operation,
        false,
        None,
    )
}

fn unsupported_value(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn unsupported_transport(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::Unimplemented,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn resource_exhausted(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::ResourceExhausted,
        api::PublicErrorReason::ResourceExhaustion,
        operation,
        true,
        None,
    )
}

fn internal(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::DataLoss,
        api::PublicErrorReason::Internal,
        operation,
        false,
        None,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::api;
    #[cfg(target_os = "linux")]
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use aster_node::application::{
        BlobPublicationInspection, BlobPublicationPhase, BlobStreamPublicationId,
        MAX_SELECTED_BLOB_STREAM_BYTES,
    };
    #[cfg(target_os = "linux")]
    use aster_node::mission::UnprotectedReferenceMission;
    #[cfg(target_os = "linux")]
    use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
    use buffa::Message as _;
    use connectrpc::ErrorCode;

    #[cfg(target_os = "linux")]
    static NEXT_STAGING_TEST: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    struct StagingTestRoot(PathBuf);

    #[cfg(target_os = "linux")]
    impl StagingTestRoot {
        fn new() -> Self {
            let sequence = NEXT_STAGING_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-agent-staging-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for StagingTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn metadata(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"blob-operation".to_vec(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            total_len,
            ttl_ms,
            ..Default::default()
        }
    }

    #[test]
    fn inspect_blob_publication_maps_all_states_without_transport_details() {
        let publication_id = BlobStreamPublicationId::from_bytes([0x31; 32]).unwrap();
        for (phase, expected) in [
            (
                BlobPublicationPhase::Missing,
                api::BlobPublicationPhase::Missing,
            ),
            (
                BlobPublicationPhase::AwaitingData,
                api::BlobPublicationPhase::AwaitingData,
            ),
            (
                BlobPublicationPhase::Receiving,
                api::BlobPublicationPhase::Receiving,
            ),
            (
                BlobPublicationPhase::ReadyToFinalize,
                api::BlobPublicationPhase::ReadyToFinalize,
            ),
            (
                BlobPublicationPhase::Available,
                api::BlobPublicationPhase::Available,
            ),
            (
                BlobPublicationPhase::ExpiredOrRetired,
                api::BlobPublicationPhase::ExpiredOrRetired,
            ),
        ] {
            let available = phase == BlobPublicationPhase::Available;
            let response = publication_status_message(BlobPublicationInspection {
                publication_id,
                phase,
                plaintext_total_bytes: 1_000,
                durable_plaintext_bytes: 500,
                transfer_total_bytes: 1_200,
                durable_transfer_bytes: 600,
                total_units: 10,
                durable_units: 5,
                blob_id: available.then(|| BlobId::from_bytes([0x32; 32])),
            });
            assert_eq!(response.publication_id, [0x31; 32]);
            assert_eq!(response.phase, expected);
            assert_eq!(response.blob_id.is_some(), available);
            assert!(response.encoded_len() < crate::MAX_AGENT_RESPONSE_PROTO_BYTES);
        }
    }

    #[test]
    fn inspect_blob_publication_hides_unauthorized_as_missing() {
        let response = publication_status_message(BlobPublicationInspection {
            publication_id: BlobStreamPublicationId::from_bytes([0x33; 32]).unwrap(),
            phase: BlobPublicationPhase::Missing,
            plaintext_total_bytes: 0,
            durable_plaintext_bytes: 0,
            transfer_total_bytes: 0,
            durable_transfer_bytes: 0,
            total_units: 0,
            durable_units: 0,
            blob_id: None,
        });
        assert_eq!(response.phase, api::BlobPublicationPhase::Missing);
        assert!(response.blob_id.is_none());
    }

    #[test]
    fn publish_receipt_includes_publication_id() {
        let publication_id = BlobStreamPublicationId::from_bytes([0x34; 32]).unwrap();
        let receipt = publish_receipt(BlobPublishResult {
            publication_id: Some(publication_id),
            id: BlobId::from_bytes([0x35; 32]),
            publisher: [0x36; 32],
            publisher_counter: 7,
            priority: Priority::Immediate,
            ttl_ms: None,
            total_len: 8,
            media_type: None,
            schema_id: Vec::new(),
            acceptance_marker: 9,
            inserted: true,
        })
        .unwrap();
        assert_eq!(receipt.publication_id, [0x34; 32]);
    }

    fn metadata_frame(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                metadata(total_len, ttl_ms),
            ))),
            ..Default::default()
        }
    }

    fn chunk(offset: u64, bytes: Vec<u8>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                api::PublishBlobData {
                    offset,
                    bytes,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }
    }

    #[test]
    fn blob_ttl_wire_presence_round_trips_and_zero_is_rejected() {
        let durable = metadata_frame(1, None);
        let durable = api::PublishBlobRequest::decode_from_slice(&durable.encode_to_vec()).unwrap();
        let (durable, _) = UploadGrammar::start(durable).unwrap();
        assert_eq!(durable.options.ttl_ms(), None);

        let finite = metadata_frame(1, Some(u64::MAX));
        let finite = api::PublishBlobRequest::decode_from_slice(&finite.encode_to_vec()).unwrap();
        let (finite, _) = UploadGrammar::start(finite).unwrap();
        assert_eq!(finite.options.ttl_ms(), Some(u64::MAX));

        let error = UploadGrammar::start(metadata_frame(1, Some(0))).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn blob_upload_requires_one_metadata_frame_before_chunks() {
        assert_eq!(
            UploadGrammar::start(api::PublishBlobRequest::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            UploadGrammar::start(chunk(0, vec![1])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let (_, mut grammar) = UploadGrammar::start(metadata_frame(1, None)).unwrap();
        assert_eq!(
            grammar.accept(metadata_frame(1, None)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_rejects_empty_and_over_policy_declared_lengths_without_allocating_them() {
        assert_eq!(
            UploadGrammar::start(metadata_frame(0, None))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            UploadGrammar::start(metadata_frame(MAX_SELECTED_BLOB_STREAM_BYTES + 1, None))
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn blob_upload_rejects_an_empty_chunk() {
        let (_, mut empty_chunk) = UploadGrammar::start(metadata_frame(1, None)).unwrap();
        assert_eq!(
            empty_chunk.accept(chunk(0, Vec::new())).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_rejects_a_chunk_above_the_injected_frame_limit() {
        const TEST_FRAME_BYTES: usize = 4;
        let (_, mut oversized_chunk) = UploadGrammar::start_with_frame_bytes_for_test(
            metadata_frame((TEST_FRAME_BYTES + 1) as u64, None),
            TEST_FRAME_BYTES,
        )
        .unwrap();
        assert_eq!(
            oversized_chunk
                .accept(chunk(0, vec![0; TEST_FRAME_BYTES + 1]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_rejects_a_stream_shorter_than_declared() {
        let (_, short) = UploadGrammar::start(metadata_frame(2, None)).unwrap();
        assert_eq!(short.finish().unwrap_err().code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn blob_upload_rejects_a_chunk_longer_than_the_declared_stream() {
        let (_, mut long) = UploadGrammar::start(metadata_frame(1, None)).unwrap();
        assert_eq!(
            long.accept(chunk(0, vec![1, 2])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_resumes_only_from_canonical_durable_offsets() {
        const TEST_FRAME_BYTES: usize = 4;
        let total = TEST_FRAME_BYTES as u64 * 2 + 1;
        let (_, grammar) = UploadGrammar::start_with_frame_bytes_for_test(
            metadata_frame(total, None),
            TEST_FRAME_BYTES,
        )
        .unwrap();
        let grammar = grammar.resume(TEST_FRAME_BYTES as u64).unwrap();
        assert_eq!(grammar.received, TEST_FRAME_BYTES as u64);
        assert_eq!(grammar.frames, 1);

        let (_, grammar) = UploadGrammar::start_with_frame_bytes_for_test(
            metadata_frame(total, None),
            TEST_FRAME_BYTES,
        )
        .unwrap();
        assert_eq!(grammar.resume(1).unwrap_err().code, ErrorCode::DataLoss);
    }

    #[test]
    fn blob_upload_derives_frame_bound_from_declared_u64_length() {
        const TEST_FRAME_BYTES: usize = 4;
        let declared = TEST_FRAME_BYTES as u64 * 1_025;
        assert_eq!(
            maximum_chunk_frames_for_len(declared, TEST_FRAME_BYTES).unwrap(),
            1_025
        );
    }

    #[test]
    fn read_page_response_carries_complete_stable_publication_metadata() {
        let metadata = ReadMetadata {
            id: [0x11; 32],
            publisher: [0x22; 32],
            publisher_counter: 7,
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: aster_node::application::Priority::Immediate,
            ttl_ms: Some(u64::MAX),
            total_len: 3,
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            acceptance_marker: 9,
        };
        let response = read_response(&metadata, 1, vec![0xbb, 0xcc], true);
        assert_eq!(response.id, vec![0x11; 32]);
        assert_eq!(response.publisher, vec![0x22; 32]);
        assert_eq!(response.publisher_counter, 7);
        assert_eq!(response.topic, "imagery.maps");
        assert_eq!(response.scope, "mission/team/alpha");
        assert_eq!(response.priority, api::Priority::Immediate);
        assert_eq!(response.ttl_ms, Some(u64::MAX));
        assert_eq!(response.total_len, 3);
        assert_eq!(response.media_type.as_deref(), Some("image/octet-stream"));
        assert_eq!(response.schema_id, b"schema-v1");
        assert_eq!(response.acceptance_marker, 9);
        assert_eq!(response.offset, 1);
        assert_eq!(response.chunk, [0xbb, 0xcc]);
        assert!(response.complete);

        let mut changed = metadata.clone();
        changed.acceptance_marker = 10;
        assert_eq!(
            ensure_stable_read_metadata(&metadata, &changed)
                .unwrap_err()
                .code,
            ErrorCode::DataLoss
        );
    }

    #[test]
    fn rpc_blob_frame_size_is_a_stable_agent_contract() {
        assert_eq!(crate::BLOB_RPC_FRAME_BYTES, 512 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_read_reauthenticates_expiry_between_pages() {
        const TEST_PAGE_BYTES: usize = 4;
        let ttl = std::time::Duration::from_secs(2);
        let fixture = StagingTestRoot::new();
        let state_root = fixture.0.join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        let access = ProvisioningAccess::member(
            Scope::new("mission/team/alpha").unwrap(),
            vec![1],
            vec![Topic::new("imagery.maps").unwrap()],
        )
        .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xb8; 32]).unwrap();
        let mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state_root.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: std::time::Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let blobs = node.selected_blobs();
        let source_path = fixture.0.join("source.bin");
        fs::write(&source_path, vec![0x5c; TEST_PAGE_BYTES + 1]).unwrap();
        let publication = blobs
            .publish_with_options(
                NodeBlobPublishRequest {
                    operation_key: b"lazy-expiry".to_vec(),
                    topic: Topic::new("imagery.maps").unwrap(),
                    scope: Scope::new("mission/team/alpha").unwrap(),
                    priority: Priority::Routine,
                    media_type: None,
                    schema_id: Vec::new(),
                },
                BlobPublishOptions::finite_ttl_ms(
                    u64::try_from(ttl.as_millis()).expect("test TTL fits u64"),
                )
                .unwrap(),
                fs::File::open(source_path).unwrap(),
            )
            .await
            .unwrap();
        let service = BlobConnectService::new(blobs, &state_root).unwrap();
        let mut stream = service
            .read_with_page_bytes(
                api::ReadBlobRequest {
                    id: publication.id.as_bytes().to_vec(),
                    topic: "imagery.maps".to_owned(),
                    scope: "mission/team/alpha".to_owned(),
                    ..Default::default()
                },
                TEST_PAGE_BYTES,
            )
            .await
            .unwrap()
            .body;
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.chunk.len(), TEST_PAGE_BYTES);
        assert!(!first.complete);

        tokio::time::sleep(ttl + std::time::Duration::from_millis(100)).await;
        let expired = stream.next().await.unwrap().unwrap_err();
        assert_eq!(expired.code, ErrorCode::NotFound);
        assert_eq!(
            expired.message.as_deref(),
            Some("durable object expired or was retired")
        );

        node.shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_stream_emits_one_empty_terminal_blob_page() {
        let fixture = StagingTestRoot::new();
        let state_root = fixture.0.join("empty-read-state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        let topic = Topic::new("imagery.maps").unwrap();
        let scope = Scope::new("mission/team/alpha").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xb9; 32]).unwrap();
        let mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state_root.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: std::time::Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let blobs = node.selected_blobs();
        let stream = blobs
            .open_publish_stream(BlobPublishStreamRequest {
                publication: NodeBlobPublishRequest {
                    operation_key: b"agent-empty-read".to_vec(),
                    topic: topic.clone(),
                    scope: scope.clone(),
                    priority: Priority::Routine,
                    media_type: None,
                    schema_id: Vec::new(),
                },
                options: BlobPublishOptions::durable(),
                total_len: 0,
            })
            .await
            .unwrap();
        let publication = stream.finish().await.unwrap();
        let service = BlobConnectService::new(blobs, &state_root).unwrap();
        let mut responses = service
            .read(api::ReadBlobRequest {
                id: publication.id.as_bytes().to_vec(),
                topic: topic.as_str().to_owned(),
                scope: scope.as_str().to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .body;
        let page = responses.next().await.unwrap().unwrap();
        assert!(page.chunk.is_empty());
        assert_eq!(page.offset, 0);
        assert_eq!(page.total_len, 0);
        assert!(page.complete);
        assert!(responses.next().await.is_none());
        node.shutdown().await.unwrap();
    }
}
