//! Single-pass local Blob adapters composed over the shared bounded pipeline.

use crate::stream_pipeline::{
    FixedPartitionMapPool, MappedPartition, PipelineError, PipelineLimits, PipelineReport,
    StreamJobId, StreamPartition, run_ordered_pipeline,
};
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobStreamOpen, BlobStreamPlainPartition, BlobStreamSegmentLeaves,
    BlobStreamSegmentSealer, EncryptedBlobStreamSegment, VerifiedBlobStreamOpen,
};
use aster_redb_store::{
    BlobUploadCheckpoint, BlobUploadReservation,
    pack::{BlobPackError, BlobPackWriter},
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, mpsc, oneshot};
use zeroize::Zeroizing;

use super::blob::{
    BlobPublishFinalization, BlobPublishOptions, BlobPublishRequest, BlobPublishResult,
    BlobStreamPublicationId, SelectedBlobCommand,
};
use super::{
    ApplicationError, ApplicationErrorKind, SelectedApplicationCommand, actor_unavailable,
};

const BLOB_STREAM_CHECKPOINT_SEGMENTS: u64 = 64;
const BLOB_STREAM_MAP_WORKERS: usize = 2;
const BLOB_STREAM_MAP_QUEUE_ITEMS: usize = 4;

type SealedBlobStreamPartition = (EncryptedBlobStreamSegment, BlobStreamSegmentLeaves);

pub(super) struct LocalBlobPublishStream {
    pub(super) reservation: BlobUploadReservation,
    pub(super) checkpoint: BlobUploadCheckpoint,
    pub(super) open: VerifiedBlobStreamOpen,
    pub(super) writer: BlobPackWriter,
    pub(super) request: BlobPublishRequest,
    pub(super) options: BlobPublishOptions,
    pub(super) total_len: u64,
    pub(super) accepted_offset: u64,
    pub(super) pending: Zeroizing<Vec<u8>>,
    pub(super) map_pool: Option<FixedPartitionMapPool<SealedBlobStreamPartition>>,
    pub(super) mapped: BTreeMap<u64, MappedPartition<SealedBlobStreamPartition>>,
    pub(super) next_map_index: u64,
    pub(super) next_sink_index: u64,
    pub(super) mapped_segments: u64,
    pub(super) checkpoint_segments: u64,
}

impl LocalBlobPublishStream {
    pub(super) const fn production_checkpoint_segments() -> u64 {
        BLOB_STREAM_CHECKPOINT_SEGMENTS
    }

    pub(super) fn map_checkpoint_due(&self) -> bool {
        self.next_map_index.saturating_sub(
            self.checkpoint
                .durable_pack_checkpoint()
                .map_or(0, |checkpoint| checkpoint.next_index()),
        ) >= self.checkpoint_segments
    }

    pub(super) fn durable_checkpoint_due(&self) -> bool {
        self.writer
            .plaintext_offset()
            .saturating_sub(self.checkpoint.durable_plaintext_offset())
            >= self.checkpoint_segments * BLOB_STREAM_SEGMENT_BYTES as u64
    }

    #[cfg(test)]
    pub(super) fn set_checkpoint_segments_for_test(&mut self, segments: u64) {
        assert!(segments > 0, "checkpoint cadence must be positive");
        self.checkpoint_segments = segments;
    }
}

pub(super) fn take_zeroizing_bytes(mut bytes: Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *bytes)
}

pub(super) fn blob_stream_map_pool(
    open: &VerifiedBlobStreamOpen,
    sealer: &BlobStreamSegmentSealer,
) -> Result<FixedPartitionMapPool<SealedBlobStreamPartition>, ApplicationError> {
    let stream_id = *open.open().stream_id().as_bytes();
    let open_digest = open.open().digest();
    let content_epoch = open.open().content_epoch();
    let total_len = open.open().total_len();
    let sealer = sealer.clone();
    FixedPartitionMapPool::new(
        BLOB_STREAM_MAP_WORKERS,
        BLOB_STREAM_MAP_QUEUE_ITEMS,
        move |partition| {
            let index = partition.index();
            let offset = index.checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64).ok_or(
                PipelineError::MapFailed("blob stream offset overflow".into()),
            )?;
            let partition = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                content_epoch,
                index,
                offset,
                total_len,
                partition.into_bytes(),
            )
            .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            sealer
                .seal(partition)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))
        },
    )
    .map_err(blob_stream_pipeline_error)
}

pub(super) fn blob_stream_pipeline_error(_error: PipelineError) -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Integrity, "blob stream pipeline")
}

pub(super) fn blob_pack_application_error(
    operation: &'static str,
    error: BlobPackError,
) -> ApplicationError {
    let kind = match error {
        BlobPackError::Io(_) | BlobPackError::Store(_) => ApplicationErrorKind::StateUnavailable,
        BlobPackError::Invalid(_) => ApplicationErrorKind::Integrity,
    };
    ApplicationError::new(kind, operation)
}

pub(super) fn sink_mapped_stream_partitions(
    stream: &mut LocalBlobPublishStream,
    wait_for_all: bool,
) -> Result<(), ApplicationError> {
    loop {
        let mapped = if wait_for_all && stream.mapped_segments < stream.next_map_index {
            Some(
                stream
                    .map_pool
                    .as_mut()
                    .expect("open stream map pool")
                    .recv_mapped_blocking()
                    .map_err(blob_stream_pipeline_error)?,
            )
        } else {
            stream
                .map_pool
                .as_mut()
                .expect("open stream map pool")
                .try_recv_mapped()
                .map_err(blob_stream_pipeline_error)?
        };
        let Some(mapped) = mapped else {
            break;
        };
        let index = mapped.index();
        if stream.mapped.insert(index, mapped).is_some() {
            return Err(blob_stream_pipeline_error(
                PipelineError::NonContiguousIndex {
                    expected: stream.next_sink_index,
                    actual: index,
                },
            ));
        }
        stream.mapped_segments += 1;
        while let Some(mapped) = stream.mapped.remove(&stream.next_sink_index) {
            let (segment, leaves) = mapped.into_value();
            stream
                .writer
                .append(&segment, leaves)
                .map_err(|error| blob_pack_application_error("blob stream write", error))?;
            stream.next_sink_index += 1;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishStreamRequest {
    pub publication: BlobPublishRequest,
    pub options: BlobPublishOptions,
    pub total_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPublishProgress {
    pub accepted_offset: u64,
    pub durable_offset: u64,
}

pub(crate) struct BlobPublishStreamSession {
    cleanup: Arc<Notify>,
}

impl BlobPublishStreamSession {
    pub(super) fn new(cleanup: Arc<Notify>) -> Self {
        Self { cleanup }
    }
}

impl Drop for BlobPublishStreamSession {
    fn drop(&mut self) {
        // A stored wake permit survives both a full command queue and the
        // interval between the worker cleanup sweep and its next wait.
        self.cleanup.notify_one();
    }
}

pub struct SelectedBlobPublishStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    session: Arc<BlobPublishStreamSession>,
    durable_offset: u64,
}

impl SelectedBlobPublishStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        progress: BlobPublishProgress,
        session: Arc<BlobPublishStreamSession>,
    ) -> Self {
        Self {
            commands,
            token,
            session,
            durable_offset: progress.durable_offset,
        }
    }

    pub const fn durable_offset(&self) -> u64 {
        self.durable_offset
    }

    pub fn publication_id(&self) -> BlobStreamPublicationId {
        BlobStreamPublicationId::from_bytes(self.token)
            .expect("selected Blob stream token is a validated publication identity")
    }

    pub async fn write(
        &mut self,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<BlobPublishProgress, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::AppendPublishStream {
                    token: self.token,
                    session: Arc::clone(&self.session),
                    offset,
                    bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream write"))?;
        let progress = received
            .await
            .map_err(|_| actor_unavailable("blob stream write"))??;
        self.durable_offset = progress.durable_offset;
        Ok(progress)
    }

    pub async fn finish(self) -> Result<BlobPublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::FinishPublishStream {
                    token: self.token,
                    session: Arc::clone(&self.session),
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?;
        let finalization = received
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))??;
        match finalization {
            BlobPublishFinalization::Completed(result) => Ok(result),
            BlobPublishFinalization::Scheduled(completion) => completion
                .await
                .map_err(|_| actor_unavailable("blob stream finish"))?,
        }
    }
}

pub(crate) struct OpenedBlobPublishStream {
    pub token: [u8; 32],
    pub progress: BlobPublishProgress,
}

#[derive(Debug)]
pub enum BlobStreamApplicationError {
    Io(std::io::Error),
    Pack(BlobPackError),
    Pipeline(PipelineError),
    IncompleteSource,
}

impl Display for BlobStreamApplicationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl Error for BlobStreamApplicationError {}
impl From<std::io::Error> for BlobStreamApplicationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<BlobPackError> for BlobStreamApplicationError {
    fn from(error: BlobPackError) -> Self {
        Self::Pack(error)
    }
}
impl From<PipelineError> for BlobStreamApplicationError {
    fn from(error: PipelineError) -> Self {
        Self::Pipeline(error)
    }
}

pub struct BlobPublishPipelineResult {
    pub plaintext_root: [u8; 32],
    pub ciphertext_root: [u8; 32],
    pub segment_count: u64,
    pub report: PipelineReport,
}

struct PlaintextPartitions<R> {
    source: R,
    total_len: u64,
    offset: u64,
    failed: Arc<Mutex<Option<std::io::Error>>>,
}

impl<R: Read> Iterator for PlaintextPartitions<R> {
    type Item = StreamPartition;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.total_len || self.failed.lock().expect("source state").is_some() {
            return None;
        }
        let len = (self.total_len - self.offset).min(BLOB_STREAM_SEGMENT_BYTES as u64) as usize;
        let mut bytes = vec![0; len];
        if let Err(error) = self.source.read_exact(&mut bytes) {
            *self.failed.lock().expect("source state") = Some(error);
            return None;
        }
        let index = self.offset / BLOB_STREAM_SEGMENT_BYTES as u64;
        self.offset += len as u64;
        Some(StreamPartition::new(index, bytes))
    }
}

pub async fn publish_blob_stream<R: Read>(
    source: R,
    open: &BlobStreamOpen,
    sealer: BlobStreamSegmentSealer,
    pack_root: &Path,
    limits: PipelineLimits,
) -> Result<BlobPublishPipelineResult, BlobStreamApplicationError> {
    let failed = Arc::new(Mutex::new(None));
    let partitions = PlaintextPartitions {
        source,
        total_len: open.total_len(),
        offset: 0,
        failed: Arc::clone(&failed),
    };
    let mut writer = BlobPackWriter::create(pack_root, open)?;
    let stream_id = *open.stream_id().as_bytes();
    let open_digest = open.digest();
    let content_epoch = open.content_epoch();
    let total_len = open.total_len();
    let job_id = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let report = run_ordered_pipeline(
        job_id,
        partitions,
        limits,
        move |partition| {
            let index = partition.index();
            let owned = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                content_epoch,
                index,
                index * BLOB_STREAM_SEGMENT_BYTES as u64,
                total_len,
                partition.into_bytes(),
            )
            .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            sealer
                .seal(owned)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))
        },
        |mapped| {
            let result = mapped.into_value();
            std::future::ready(
                writer
                    .append(&result.0, result.1)
                    .map_err(|error| PipelineError::SinkFailed(error.to_string())),
            )
        },
    )
    .await?;
    if failed.lock().expect("source state").is_some() || report.completed_items() == 0 {
        return Err(BlobStreamApplicationError::IncompleteSource);
    }
    let segment_count = report.completed_items();
    let (plaintext_root, ciphertext_root) = writer.finish()?;
    Ok(BlobPublishPipelineResult {
        plaintext_root,
        ciphertext_root,
        segment_count,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{
        BlobMetadata, BlobPublicationStreamId, Priority, Scope, Topic, VersionVector,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn production_checkpoint_policy_batches_sixty_four_segments() {
        assert_eq!(LocalBlobPublishStream::production_checkpoint_segments(), 64);
    }

    struct TempRoot(std::path::PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-local-stream-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("temp root");
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct CountingReader {
        cursor: std::io::Cursor<Vec<u8>>,
        read: Arc<AtomicU64>,
    }
    impl Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let read = self.cursor.read(output)?;
            self.read.fetch_add(read as u64, Ordering::Relaxed);
            Ok(read)
        }
    }

    fn open(total_len: u64) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream"),
            [0x21; 32],
            b"local-pipeline".to_vec(),
            [0x31; 32],
            1,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            BlobMetadata::new(Some("image/tiff".into()), Vec::new()).expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            [0x41; 32],
            [0x51; 32],
        )
        .expect("open")
    }

    #[tokio::test]
    async fn local_blob_pipeline_reads_plaintext_once_and_round_trips() {
        let root = TempRoot::new();
        let plaintext = (0..(2 * BLOB_STREAM_SEGMENT_BYTES + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let open = open(plaintext.len() as u64);
        let read = Arc::new(AtomicU64::new(0));
        let source = CountingReader {
            cursor: std::io::Cursor::new(plaintext.clone()),
            read: Arc::clone(&read),
        };
        let limits = PipelineLimits::new(4, 4, 5 * 1024 * 1024, 4).expect("limits");
        let key = [0x61; 32];
        let nonce = [0x71; 12];
        let published = publish_blob_stream(
            source,
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &root.0,
            limits,
        )
        .await
        .expect("publish");
        assert_eq!(read.load(Ordering::Relaxed), plaintext.len() as u64);
        assert_eq!(published.segment_count, 3);

        assert_ne!(published.plaintext_root, [0; 32]);
        assert_ne!(published.ciphertext_root, [0; 32]);
    }
}
