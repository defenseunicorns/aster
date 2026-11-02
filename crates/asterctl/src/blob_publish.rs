use crate::{api, operation_key, progress::ProgressMode, validation};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] blob-publish
                --file PATH --topic TOPIC --scope SCOPE
                --operation-key KEY|auto [BLOB-OPTIONS]

Publish a nonempty regular file as an immutable Blob through a running Aster agent.

BLOB OPTIONS:
      --file PATH               Source file (required; path remains local)
      --topic TOPIC             Blob topic (required)
      --scope SCOPE             Propagation and authorization scope (required)
      --priority PRIORITY       routine, priority, immediate, or flash (default: routine)
      --media-type TYPE         UTF-8 media type, 1–255 bytes
      --schema-id BASE64        Schema identity, up to 1024 decoded bytes
      --ttl-ms MILLISECONDS     Positive Blob lifetime (default: durable)
      --operation-key KEY|auto  Required UTF-8 key, 1–256 bytes; auto generates a key
      --progress MODE           auto, always, or never (default: auto)
      --help                    Show this help

See asterctl --help for global options.
Generated keys are printed to stderr before sending and included in JSON output.
The path remains local; file contents stream to the local agent.
The source file's contents and length must remain unchanged until the command exits.
";

/// Stable native gRPC Blob payload frame size owned by the CLI protocol layer.
pub(crate) const RPC_FRAME_BYTES: usize = 512 * 1024;
pub(crate) const CHUNK_BYTES: usize = RPC_FRAME_BYTES;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_SCHEMA_ID_BYTES: usize = 1024;

#[derive(Debug, PartialEq)]
pub struct Publication {
    file: Option<PathBuf>,
    topic: String,
    scope: String,
    priority: buffa::EnumValue<api::Priority>,
    media_type: Option<String>,
    schema_id: Vec<u8>,
    ttl_ms: Option<u64>,
    operation_key: Option<operation_key::Selection>,
    pub(crate) progress: ProgressMode,
}

impl Default for Publication {
    fn default() -> Self {
        Self {
            file: None,
            topic: String::new(),
            scope: String::new(),
            priority: api::Priority::Routine.into(),
            media_type: None,
            schema_id: Vec::new(),
            ttl_ms: None,
            operation_key: None,
            progress: ProgressMode::Auto,
        }
    }
}

impl Publication {
    pub fn set_file(&mut self, path: PathBuf) -> Result<(), &'static str> {
        if path.as_os_str().is_empty() {
            return Err("source file path must not be empty");
        }
        self.file = Some(path);
        Ok(())
    }

    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--topic" => {
                validation::topic(&value)?;
                self.topic = value;
            }
            "--scope" => {
                validation::scope(&value)?;
                self.scope = value;
            }
            "--priority" => {
                self.priority = parse_priority(&value)?;
            }
            "--media-type" => {
                if value.is_empty() || value.len() > MAX_MEDIA_TYPE_BYTES {
                    return Err("media type must contain 1–255 UTF-8 bytes");
                }
                self.media_type = Some(value);
            }
            "--schema-id" => {
                self.schema_id = validation::base64(&value)
                    .filter(|bytes| bytes.len() <= MAX_SCHEMA_ID_BYTES)
                    .ok_or("schema ID must be Base64 encoding of at most 1024 bytes")?;
            }
            "--ttl-ms" => self.ttl_ms = Some(parse_ttl(&value)?),
            "--operation-key" => {
                self.operation_key = Some(operation_key::Selection::parse(value)?);
            }
            "--progress" => self.progress = ProgressMode::parse(&value)?,
            _ => unreachable!("Blob publish option"),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.file.is_none() {
            return Err("--file is required; see blob-publish --help");
        }
        if self.topic.is_empty() {
            return Err("--topic is required; see blob-publish --help");
        }
        if self.scope.is_empty() {
            return Err("--scope is required; see blob-publish --help");
        }
        if self.operation_key.is_none() {
            return Err(operation_key::REQUIRED);
        }
        Ok(())
    }

    pub fn prepare(self) -> Result<PreparedUpload, &'static str> {
        self.validate()?;
        let file = open_source(&self.file.expect("validated source path"))?;
        let file_metadata = file.metadata().map_err(|_| "cannot inspect source file")?;
        if !file_metadata.is_file() {
            return Err("source must be a regular file");
        }
        let total_len = file_metadata.len();
        if total_len == 0 {
            return Err("source file must not be empty");
        }
        let key = self
            .operation_key
            .expect("validated operation key")
            .resolve()?;
        Ok(PreparedUpload {
            metadata: api::PublishBlobMetadata {
                operation_key: key.value.as_bytes().to_vec(),
                topic: self.topic,
                scope: self.scope,
                priority: self.priority,
                media_type: self.media_type,
                schema_id: self.schema_id,
                total_len,
                ttl_ms: self.ttl_ms,
                ..Default::default()
            },
            file,
            key,
            progress: self.progress,
        })
    }
}

fn open_source(path: &std::path::Path) -> Result<File, &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // Opening a FIFO for read normally waits for a writer. Preflight must
        // reject it from its descriptor metadata instead of blocking the CLI.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "cannot open source file")?;
    let file_metadata = file.metadata().map_err(|_| "cannot inspect source file")?;
    if !file_metadata.is_file() {
        return Err("source must be a regular file");
    }
    if file_metadata.len() == 0 {
        return Err("source file must not be empty");
    }
    Ok(file)
}

fn parse_priority(value: &str) -> Result<buffa::EnumValue<api::Priority>, &'static str> {
    Ok(match value {
        "routine" => api::Priority::Routine,
        "priority" => api::Priority::Priority,
        "immediate" => api::Priority::Immediate,
        "flash" => api::Priority::Flash,
        _ => return Err("priority must be routine, priority, immediate, or flash"),
    }
    .into())
}

fn parse_ttl(value: &str) -> Result<u64, &'static str> {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|ttl| *ttl > 0)
        .ok_or("TTL must be an integer from 1 to 18446744073709551615 milliseconds")
}

pub struct PreparedUpload {
    pub metadata: api::PublishBlobMetadata,
    pub file: File,
    pub key: operation_key::Key,
    pub progress: ProgressMode,
}

pub(crate) struct FrameStream {
    receiver: tokio::sync::mpsc::Receiver<api::PublishBlobRequest>,
}

impl FrameStream {
    pub(crate) async fn next(&mut self) -> Option<api::PublishBlobRequest> {
        self.receiver.recv().await
    }
}

impl connectrpc::client::Stream for FrameStream {
    type Item = api::PublishBlobRequest;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

pub(crate) fn stream_file_with_chunk_bytes(
    file: File,
    total_len: u64,
    start_offset: u64,
    chunk_bytes: usize,
) -> (
    FrameStream,
    tokio::task::JoinHandle<Result<(), &'static str>>,
) {
    assert!(
        chunk_bytes > 0 && chunk_bytes <= CHUNK_BYTES,
        "test chunk bound must be within the production limit"
    );
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let reader = tokio::task::spawn_blocking(move || {
        produce_frames(file, total_len, start_offset, chunk_bytes, sender)
    });
    (FrameStream { receiver }, reader)
}

fn produce_frames(
    mut file: File,
    total_len: u64,
    start_offset: u64,
    chunk_bytes: usize,
    sender: tokio::sync::mpsc::Sender<api::PublishBlobRequest>,
) -> Result<(), &'static str> {
    if start_offset > total_len {
        return Err("agent returned an invalid Blob resume offset");
    }
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|_| "cannot seek source file to the Blob resume offset")?;
    let mut offset = start_offset;
    let mut remaining = total_len - start_offset;
    while remaining > 0 {
        let length = remaining.min(chunk_bytes as u64) as usize;
        let mut chunk = vec![0_u8; length];
        file.read_exact(&mut chunk)
            .map_err(|_| "cannot read source file while request may have been sent")?;
        remaining = remaining
            .checked_sub(length as u64)
            .ok_or("source file length changed while reading")?;
        if sender
            .blocking_send(api::PublishBlobRequest {
                frame: Some(api::publish_blob_request::Frame::Data(Box::new(
                    api::PublishBlobData {
                        offset,
                        bytes: chunk,
                        ..Default::default()
                    },
                ))),
                ..Default::default()
            })
            .is_err()
        {
            return Ok(());
        }
        offset = offset
            .checked_add(length as u64)
            .ok_or("source file length overflow")?;
    }
    let mut extra = [0_u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err("source file length changed while request may have been sent"),
        Err(_) => Err("cannot finish reading source file while request may have been sent"),
    }
}

pub(crate) fn receipt_matches(
    request: &api::PublishBlobMetadata,
    response: &api::PublishBlobReceipt,
) -> bool {
    response.publication_id.len() == 32
        && response.id.len() == 32
        && response.publisher.len() == 32
        && response.publisher_counter != 0
        && response.priority == request.priority
        && response.ttl_ms == request.ttl_ms
        && response.total_len == request.total_len
        && response.media_type == request.media_type
        && response.schema_id == request.schema_id
        && response.acceptance_marker != 0
}

pub(crate) fn checkpoint_is_valid(
    checkpoint: &api::PublishBlobCheckpoint,
    previous_accepted: u64,
    previous_durable: u64,
    sent_offset: u64,
    total_len: u64,
) -> bool {
    checkpoint.accepted_offset >= previous_accepted
        && checkpoint.accepted_offset <= sent_offset
        && checkpoint.accepted_offset <= total_len
        && checkpoint.durable_offset > previous_durable
        && checkpoint.durable_offset <= checkpoint.accepted_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHUNK_BYTES: usize = 4;

    fn metadata(total_len: u64) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"blob-test".to_vec(),
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            total_len,
            ttl_ms: Some(u64::MAX),
            ..Default::default()
        }
    }

    #[test]
    fn blob_publish_receipt_compares_ttl_presence_unconditionally() {
        let request = metadata(7);
        let response = api::PublishBlobReceipt {
            publication_id: vec![3; 32],
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            priority: request.priority,
            ttl_ms: request.ttl_ms,
            total_len: request.total_len,
            media_type: request.media_type.clone(),
            schema_id: request.schema_id.clone(),
            acceptance_marker: 4,
            ..Default::default()
        };
        assert!(receipt_matches(&request, &response));
        assert!(!receipt_matches(
            &request,
            &api::PublishBlobReceipt {
                publisher_counter: 0,
                ..response.clone()
            }
        ));
        assert!(!receipt_matches(
            &request,
            &api::PublishBlobReceipt {
                acceptance_marker: 0,
                ..response.clone()
            }
        ));
        assert!(!receipt_matches(
            &api::PublishBlobMetadata {
                ttl_ms: None,
                ..request.clone()
            },
            &response
        ));
        assert!(!receipt_matches(
            &request,
            &api::PublishBlobReceipt {
                ttl_ms: None,
                ..response
            }
        ));
    }

    #[test]
    fn blob_publish_receipt_accepts_checked_lengths_above_legacy_boundary() {
        let request = metadata((64 * 1024 * 1024_u64) + 1);
        let response = api::PublishBlobReceipt {
            publication_id: vec![3; 32],
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            priority: request.priority,
            ttl_ms: request.ttl_ms,
            total_len: request.total_len,
            media_type: request.media_type.clone(),
            schema_id: request.schema_id.clone(),
            acceptance_marker: 4,
            ..Default::default()
        };
        assert!(receipt_matches(&request, &response));
    }

    #[test]
    fn blob_publish_rejects_checkpoint_ahead_of_successfully_sent_bytes() {
        let checkpoint = api::PublishBlobCheckpoint {
            accepted_offset: CHUNK_BYTES as u64,
            durable_offset: CHUNK_BYTES as u64,
            ..Default::default()
        };
        assert!(!checkpoint_is_valid(
            &checkpoint,
            0,
            0,
            0,
            CHUNK_BYTES as u64,
        ));
        assert!(checkpoint_is_valid(
            &checkpoint,
            0,
            0,
            CHUNK_BYTES as u64,
            CHUNK_BYTES as u64,
        ));
    }

    #[tokio::test]
    async fn blob_publish_streams_offset_bearing_canonical_bounded_chunks() {
        use connectrpc::client::Stream as _;
        use std::{fs, future::poll_fn};

        let path =
            std::env::temp_dir().join(format!("asterctl-blob-frames-{}", std::process::id()));
        assert_eq!(CHUNK_BYTES, 512 * 1024);
        let bytes = vec![0x5a; TEST_CHUNK_BYTES + 1];
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let (mut frames, reader) =
            stream_file_with_chunk_bytes(file, bytes.len() as u64, 0, TEST_CHUNK_BYTES);
        let mut observed = Vec::new();
        while let Some(frame) = poll_fn(|context| Pin::new(&mut frames).poll_next(context)).await {
            observed.push(frame);
        }
        reader.await.unwrap().unwrap();
        fs::remove_file(path).unwrap();
        let chunks: Vec<_> = observed
            .iter()
            .map(|frame| match frame.frame.as_ref().unwrap() {
                api::publish_blob_request::Frame::Data(chunk) => (chunk.offset, chunk.bytes.len()),
                api::publish_blob_request::Frame::Metadata(_) => {
                    panic!("metadata belongs to the negotiation phase")
                }
                api::publish_blob_request::Frame::Finish(_) => {
                    panic!("finish belongs to the caller-owned RPC phase")
                }
            })
            .collect();
        assert_eq!(
            chunks,
            [(0, TEST_CHUNK_BYTES), (TEST_CHUNK_BYTES as u64, 1)]
        );
    }

    #[tokio::test]
    async fn publish_retry_uses_agent_resume_offset() {
        use connectrpc::client::Stream as _;
        use std::{fs, future::poll_fn};

        let path =
            std::env::temp_dir().join(format!("asterctl-blob-resume-{}", std::process::id()));
        let bytes = vec![0x5a; TEST_CHUNK_BYTES + 3];
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let (mut frames, reader) = stream_file_with_chunk_bytes(
            file,
            bytes.len() as u64,
            TEST_CHUNK_BYTES as u64,
            TEST_CHUNK_BYTES,
        );
        let frame = poll_fn(|context| Pin::new(&mut frames).poll_next(context))
            .await
            .unwrap();
        reader.await.unwrap().unwrap();
        fs::remove_file(path).unwrap();
        let api::publish_blob_request::Frame::Data(chunk) = frame.frame.unwrap() else {
            panic!("expected resumed chunk")
        };
        assert_eq!(chunk.offset, TEST_CHUNK_BYTES as u64);
        assert_eq!(chunk.bytes, vec![0x5a; 3]);
    }

    #[tokio::test]
    async fn blob_publish_detects_source_size_changes_after_preflight() {
        use connectrpc::client::Stream as _;
        use std::{fs, future::poll_fn};

        let path = std::env::temp_dir().join(format!(
            "asterctl-blob-size-mutation-{}",
            std::process::id()
        ));
        fs::write(&path, b"initial bytes").unwrap();
        let file = File::open(&path).unwrap();
        let original_len = file.metadata().unwrap().len();
        fs::write(&path, b"short").unwrap();

        let (mut frames, reader) = stream_file_with_chunk_bytes(file, original_len, 0, CHUNK_BYTES);
        while poll_fn(|context| Pin::new(&mut frames).poll_next(context))
            .await
            .is_some()
        {}
        assert_eq!(
            reader.await.unwrap(),
            Err("cannot read source file while request may have been sent")
        );
        fs::remove_file(path).unwrap();
    }
}
