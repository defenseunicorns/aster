use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StreamJobId([u8; 16]);

impl StreamJobId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug)]
pub struct StreamPartition {
    index: u64,
    source_end: u64,
    accounted_bytes: usize,
    bytes: Vec<u8>,
    #[cfg(test)]
    zeroize_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl StreamPartition {
    pub fn new(index: u64, bytes: Vec<u8>) -> Self {
        Self {
            index,
            source_end: 0,
            accounted_bytes: bytes.len(),
            bytes,
            #[cfg(test)]
            zeroize_observer: None,
        }
    }

    pub fn new_at(index: u64, source_end: u64, bytes: Vec<u8>) -> Self {
        Self {
            index,
            source_end,
            accounted_bytes: bytes.len(),
            bytes,
            #[cfg(test)]
            zeroize_observer: None,
        }
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn source_end(&self) -> u64 {
        self.source_end
    }

    pub fn len(&self) -> usize {
        self.accounted_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.accounted_bytes == 0
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }

    #[cfg(test)]
    pub(crate) fn observe_zeroize_for_test(
        mut self,
        observer: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.zeroize_observer = Some(observer);
        self
    }

    fn zeroize_now(&mut self) {
        #[cfg(test)]
        let had_plaintext = !self.bytes.is_empty();
        self.bytes.zeroize();
        #[cfg(test)]
        if had_plaintext && let Some(observer) = self.zeroize_observer.take() {
            observer.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl Drop for StreamPartition {
    fn drop(&mut self) {
        self.zeroize_now();
    }
}

#[cfg(test)]
#[derive(Default)]
struct PipelineTestProbeInner {
    cleanup_observed: AtomicBool,
    admission_open: AtomicBool,
    admission_rejected: AtomicBool,
    rejected_plaintext_zeroized: AtomicBool,
    rejected_permits_reclaimed: AtomicBool,
    cancellation_signalled: AtomicBool,
    channels_closed: AtomicBool,
    worker_exits: std::sync::atomic::AtomicUsize,
    joined_workers: std::sync::atomic::AtomicUsize,
    active_workers: std::sync::atomic::AtomicUsize,
    peak_active_workers: std::sync::atomic::AtomicUsize,
    hold_workers: AtomicBool,
    peak_reorder_items: std::sync::atomic::AtomicUsize,
    current_reorder_items: std::sync::atomic::AtomicUsize,
    available_item_permits: std::sync::atomic::AtomicUsize,
    available_byte_permits: std::sync::atomic::AtomicUsize,
    fail_spawn_at: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct PipelineTestProbe(Arc<PipelineTestProbeInner>);

#[cfg(test)]
static PIPELINE_TEST_PROBES: std::sync::LazyLock<
    Mutex<std::collections::HashMap<StreamJobId, std::sync::Weak<PipelineTestProbeInner>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
impl PipelineTestProbe {
    pub(crate) fn install(job: StreamJobId) -> Self {
        let inner = Arc::new(PipelineTestProbeInner::default());
        PIPELINE_TEST_PROBES
            .lock()
            .expect("pipeline probe registry")
            .insert(job, Arc::downgrade(&inner));
        Self(inner)
    }

    fn for_job(job: StreamJobId) -> Option<Self> {
        PIPELINE_TEST_PROBES
            .lock()
            .expect("pipeline probe registry")
            .get(&job)
            .and_then(std::sync::Weak::upgrade)
            .map(Self)
    }

    pub(crate) fn hold_workers_for_test(&self) {
        self.0.hold_workers.store(true, Ordering::SeqCst);
    }
    pub(crate) fn peak_active_workers(&self) -> usize {
        self.0.peak_active_workers.load(Ordering::SeqCst)
    }
    pub(crate) fn admission_open(&self) -> bool {
        self.0.admission_open.load(Ordering::SeqCst)
    }
    pub(crate) fn admission_rejected(&self) -> bool {
        self.0.admission_rejected.load(Ordering::SeqCst)
    }
    pub(crate) fn rejected_plaintext_zeroized(&self) -> bool {
        self.0.rejected_plaintext_zeroized.load(Ordering::SeqCst)
    }
    pub(crate) fn rejected_permits_reclaimed(&self) -> bool {
        self.0.rejected_permits_reclaimed.load(Ordering::SeqCst)
    }
    pub(crate) fn cleanup_observed(&self) -> bool {
        self.0.cleanup_observed.load(Ordering::SeqCst)
    }
    pub(crate) fn cancellation_signalled(&self) -> bool {
        self.0.cancellation_signalled.load(Ordering::SeqCst)
    }
    pub(crate) fn channels_closed(&self) -> bool {
        self.0.channels_closed.load(Ordering::SeqCst)
    }
    pub(crate) fn worker_exits(&self) -> usize {
        self.0.worker_exits.load(Ordering::SeqCst)
    }
    pub(crate) fn joined_workers(&self) -> usize {
        self.0.joined_workers.load(Ordering::SeqCst)
    }
    pub(crate) fn active_workers(&self) -> usize {
        self.0.active_workers.load(Ordering::SeqCst)
    }
    pub(crate) fn peak_reorder_items(&self) -> usize {
        self.0.peak_reorder_items.load(Ordering::SeqCst)
    }
    pub(crate) fn current_reorder_items(&self) -> usize {
        self.0.current_reorder_items.load(Ordering::SeqCst)
    }
    pub(crate) fn available_item_permits(&self) -> usize {
        self.0.available_item_permits.load(Ordering::SeqCst)
    }
    pub(crate) fn available_byte_permits(&self) -> usize {
        self.0.available_byte_permits.load(Ordering::SeqCst)
    }

    fn fail_spawn_at_for_test(&self, worker_index: usize) {
        self.0
            .fail_spawn_at
            .store(worker_index.saturating_add(1), Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub struct MappedPartition<T> {
    index: u64,
    input_bytes: usize,
    value: T,
    _item_permit: Option<OwnedSemaphorePermit>,
    _byte_permit: Option<OwnedSemaphorePermit>,
}

impl<T> MappedPartition<T> {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineLimits {
    workers: usize,
    max_in_flight_items: usize,
    max_in_flight_bytes: usize,
    max_reorder_items: usize,
}

impl PipelineLimits {
    pub fn new(
        workers: usize,
        max_in_flight_items: usize,
        max_in_flight_bytes: usize,
        max_reorder_items: usize,
    ) -> Result<Self, PipelineError> {
        if workers == 0
            || max_in_flight_items == 0
            || max_in_flight_bytes == 0
            || max_in_flight_bytes > u32::MAX as usize
            || max_reorder_items == 0
            || workers > max_in_flight_items
            || max_reorder_items > max_in_flight_items
        {
            return Err(PipelineError::InvalidLimits);
        }
        Ok(Self {
            workers,
            max_in_flight_items,
            max_in_flight_bytes,
            max_reorder_items,
        })
    }

    pub const fn max_in_flight_items(&self) -> usize {
        self.max_in_flight_items
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum PipelineStage {
    Admission = 0,
    Map = 1,
    Reorder = 2,
    Sink = 3,
}

const PIPELINE_STAGE_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StageObservation {
    pub items: u64,
    pub bytes: u64,
    pub queue_wait_ns: u64,
    pub service_ns: u64,
    pub output_blocked_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineReport {
    job_id: StreamJobId,
    accepted_items: u64,
    completed_items: u64,
    peak_in_flight_items: usize,
    peak_in_flight_bytes: usize,
    peak_owned_bytes: usize,
    peak_encoding_bytes: usize,
    peak_reorder_items: usize,
    worker_count: usize,
    peak_active_workers: usize,
    stages: [StageObservation; PIPELINE_STAGE_COUNT],
}

impl PipelineReport {
    pub const fn accepted_items(&self) -> u64 {
        self.accepted_items
    }
    pub const fn completed_items(&self) -> u64 {
        self.completed_items
    }
    pub const fn peak_in_flight_items(&self) -> usize {
        self.peak_in_flight_items
    }
    pub const fn peak_in_flight_bytes(&self) -> usize {
        self.peak_in_flight_bytes
    }
    pub const fn peak_owned_bytes(&self) -> usize {
        self.peak_owned_bytes
    }
    pub const fn peak_encoding_bytes(&self) -> usize {
        self.peak_encoding_bytes
    }
    pub const fn peak_reorder_items(&self) -> usize {
        self.peak_reorder_items
    }
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }
    pub const fn peak_active_workers(&self) -> usize {
        self.peak_active_workers
    }
    pub const fn stage(&self, stage: PipelineStage) -> StageObservation {
        self.stages[stage as usize]
    }
}

impl Display for PipelineReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "workers:{};peak_active_workers:{};peak_items:{};peak_bytes:{};peak_owned_bytes:{};peak_encoding_bytes:{};peak_reorder:{}",
            self.worker_count,
            self.peak_active_workers,
            self.peak_in_flight_items,
            self.peak_in_flight_bytes,
            self.peak_owned_bytes,
            self.peak_encoding_bytes,
            self.peak_reorder_items,
        )?;
        for (name, stage) in [
            ("admission", PipelineStage::Admission),
            ("map", PipelineStage::Map),
            ("reorder", PipelineStage::Reorder),
            ("sink", PipelineStage::Sink),
        ] {
            let observation = self.stage(stage);
            write!(
                formatter,
                ";{name}:{}:{}:{}:{}:{}",
                observation.items,
                observation.bytes,
                observation.queue_wait_ns,
                observation.service_ns,
                observation.output_blocked_ns,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum PipelineError {
    InvalidLimits,
    EmptyPartition,
    PartitionTooLarge,
    NonContiguousIndex { expected: u64, actual: u64 },
    WorkerPanicked,
    MapFailed(String),
    SinkFailed(String),
    Adapter(Arc<dyn Error + Send + Sync>),
}

impl Display for PipelineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PipelineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Adapter(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

struct Pending<T> {
    mapped: MappedPartition<T>,
    queue_wait: Duration,
    map_time: Duration,
    mapped_at: Instant,
}

struct ReorderBuffer<T> {
    items: BTreeMap<u64, Pending<T>>,
    #[cfg(test)]
    probe: Option<PipelineTestProbe>,
}

impl<T> ReorderBuffer<T> {
    fn new(
        #[cfg(test)] probe: Option<PipelineTestProbe>,
        #[cfg(not(test))] _probe: Option<()>,
    ) -> Self {
        Self {
            items: BTreeMap::new(),
            #[cfg(test)]
            probe,
        }
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn insert(&mut self, index: u64, pending: Pending<T>) -> Option<Pending<T>> {
        let replaced = self.items.insert(index, pending);
        self.observe();
        replaced
    }

    fn remove(&mut self, index: &u64) -> Option<Pending<T>> {
        let removed = self.items.remove(index);
        self.observe();
        removed
    }

    #[cfg(test)]
    fn observe(&self) {
        if let Some(probe) = &self.probe {
            probe
                .0
                .peak_reorder_items
                .fetch_max(self.items.len(), Ordering::SeqCst);
            probe
                .0
                .current_reorder_items
                .store(self.items.len(), Ordering::SeqCst);
        }
    }

    #[cfg(not(test))]
    fn observe(&self) {}
}

impl<T> Drop for ReorderBuffer<T> {
    fn drop(&mut self) {
        self.items.clear();
        self.observe();
    }
}

struct Work {
    partition: StreamPartition,
    queued_at: Instant,
    item_permit: Option<OwnedSemaphorePermit>,
    byte_permit: Option<OwnedSemaphorePermit>,
}

fn submit_work_through_admission(
    admission_accepting: &AtomicBool,
    work_sender: Option<&std_mpsc::SyncSender<Work>>,
    work: Work,
) -> Result<(), PipelineError> {
    if !admission_accepting.load(Ordering::Acquire) {
        return Err(PipelineError::WorkerPanicked);
    }
    work_sender
        .ok_or(PipelineError::WorkerPanicked)?
        .send(work)
        .map_err(|_| PipelineError::WorkerPanicked)
}

#[cfg(test)]
fn observe_rejected_submission(
    admission_accepting: &AtomicBool,
    work_sender: &std_mpsc::SyncSender<Work>,
    probe: &PipelineTestProbe,
) {
    let zeroized = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let item_budget = Arc::new(Semaphore::new(1));
    let byte_budget = Arc::new(Semaphore::new(16));
    let sentinel = Work {
        partition: StreamPartition::new(u64::MAX, vec![0xa5; 16])
            .observe_zeroize_for_test(Arc::clone(&zeroized)),
        queued_at: Instant::now(),
        item_permit: Some(
            Arc::clone(&item_budget)
                .try_acquire_owned()
                .expect("sentinel item permit"),
        ),
        byte_permit: Some(
            Arc::clone(&byte_budget)
                .try_acquire_many_owned(16)
                .expect("sentinel byte permits"),
        ),
    };
    let rejected = matches!(
        submit_work_through_admission(admission_accepting, Some(work_sender), sentinel),
        Err(PipelineError::WorkerPanicked)
    );
    probe.0.admission_rejected.store(rejected, Ordering::SeqCst);
    probe
        .0
        .rejected_plaintext_zeroized
        .store(zeroized.load(Ordering::SeqCst) == 1, Ordering::SeqCst);
    probe.0.rejected_permits_reclaimed.store(
        item_budget.available_permits() == 1 && byte_budget.available_permits() == 16,
        Ordering::SeqCst,
    );
}

pub(crate) struct FixedPartitionMapPool<T> {
    work_sender: Option<std_mpsc::SyncSender<Work>>,
    work_receiver: Arc<Mutex<std_mpsc::Receiver<Work>>>,
    result_receiver: mpsc::UnboundedReceiver<Result<Pending<T>, PipelineError>>,
    admission_accepting: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    active_workers: Arc<std::sync::atomic::AtomicUsize>,
    peak_active_workers: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    test_probe: Option<PipelineTestProbe>,
    #[cfg(test)]
    test_item_budget: Option<Arc<Semaphore>>,
    #[cfg(test)]
    test_byte_budget: Option<Arc<Semaphore>>,
}

impl<T: Send + 'static> FixedPartitionMapPool<T> {
    pub(crate) fn new<Map>(
        worker_count: usize,
        queue_capacity: usize,
        map: Map,
    ) -> Result<Self, PipelineError>
    where
        Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    {
        Self::new_with_probe(worker_count, queue_capacity, map, None)
    }

    fn new_with_probe<Map>(
        worker_count: usize,
        queue_capacity: usize,
        map: Map,
        #[cfg(test)] probe: Option<PipelineTestProbe>,
        #[cfg(not(test))] _probe: Option<()>,
    ) -> Result<Self, PipelineError>
    where
        Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    {
        Self::new_with_probe_and_initial_work(
            worker_count,
            queue_capacity,
            map,
            #[cfg(test)]
            probe,
            #[cfg(not(test))]
            _probe,
            #[cfg(test)]
            Vec::new(),
        )
    }

    fn new_with_probe_and_initial_work<Map>(
        worker_count: usize,
        queue_capacity: usize,
        map: Map,
        #[cfg(test)] probe: Option<PipelineTestProbe>,
        #[cfg(not(test))] _probe: Option<()>,
        #[cfg(test)] initial_work: Vec<Work>,
    ) -> Result<Self, PipelineError>
    where
        Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    {
        if worker_count == 0 || queue_capacity == 0 {
            return Err(PipelineError::InvalidLimits);
        }
        let map = Arc::new(map);
        let admission_accepting = Arc::new(AtomicBool::new(true));
        let cancelled = Arc::new(AtomicBool::new(false));
        let (work_sender, work_receiver) = std_mpsc::sync_channel::<Work>(queue_capacity);
        #[cfg(test)]
        for work in initial_work {
            work_sender
                .send(work)
                .map_err(|_| PipelineError::WorkerPanicked)?;
        }
        let work_receiver = Arc::new(Mutex::new(work_receiver));
        let (result_sender, mut result_receiver) = mpsc::unbounded_channel();
        let active_workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak_active_workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let receiver = Arc::clone(&work_receiver);
            let map = Arc::clone(&map);
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_active = Arc::clone(&active_workers);
            let worker_peak_active = Arc::clone(&peak_active_workers);
            #[cfg(test)]
            let worker_probe = probe.clone();
            #[cfg(test)]
            let injected_failure = probe.as_ref().is_some_and(|probe| {
                probe.0.fail_spawn_at.load(Ordering::SeqCst) == worker_index + 1
            });
            #[cfg(not(test))]
            let injected_failure = false;
            let worker = if injected_failure {
                Err(std::io::Error::other("injected worker spawn failure"))
            } else {
                let results = result_sender.clone();
                std::thread::Builder::new()
                    .name(format!("aster-stream-map-{worker_index}"))
                    .spawn(move || {
                        loop {
                            if worker_cancelled.load(Ordering::Acquire) {
                                break;
                            }
                            let work = match receiver.lock() {
                                Ok(receiver) => receiver.recv(),
                                Err(_) => {
                                    _ = results.send(Err(PipelineError::WorkerPanicked));
                                    break;
                                }
                            };
                            let Ok(work) = work else {
                                break;
                            };
                            if worker_cancelled.load(Ordering::Acquire) {
                                break;
                            }
                            let started = Instant::now();
                            let queue_wait = started.saturating_duration_since(work.queued_at);
                            let index = work.partition.index;
                            let bytes = work.partition.len();
                            let active = worker_active.fetch_add(1, Ordering::AcqRel) + 1;
                            worker_peak_active.fetch_max(active, Ordering::AcqRel);
                            #[cfg(test)]
                            if let Some(probe) = &worker_probe {
                                let active =
                                    probe.0.active_workers.fetch_add(1, Ordering::SeqCst) + 1;
                                probe
                                    .0
                                    .peak_active_workers
                                    .fetch_max(active, Ordering::SeqCst);
                                while probe.0.hold_workers.load(Ordering::SeqCst)
                                    && !worker_cancelled.load(Ordering::Acquire)
                                {
                                    std::thread::yield_now();
                                }
                            }
                            if worker_cancelled.load(Ordering::Acquire) {
                                worker_active.fetch_sub(1, Ordering::AcqRel);
                                #[cfg(test)]
                                if let Some(probe) = &worker_probe {
                                    probe.0.active_workers.fetch_sub(1, Ordering::SeqCst);
                                }
                                break;
                            }
                            let mapped =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    map(work.partition)
                                }));
                            worker_active.fetch_sub(1, Ordering::AcqRel);
                            #[cfg(test)]
                            if let Some(probe) = &worker_probe {
                                probe.0.active_workers.fetch_sub(1, Ordering::SeqCst);
                            }
                            let result = match mapped {
                                Ok(Ok(value)) => Ok(Pending {
                                    mapped: MappedPartition {
                                        index,
                                        input_bytes: bytes,
                                        value,
                                        _item_permit: work.item_permit,
                                        _byte_permit: work.byte_permit,
                                    },
                                    queue_wait,
                                    map_time: started.elapsed(),
                                    mapped_at: Instant::now(),
                                }),
                                Ok(Err(error)) => Err(error),
                                Err(_) => Err(PipelineError::WorkerPanicked),
                            };
                            let terminal = result.is_err();
                            if results.send(result).is_err() || terminal {
                                break;
                            }
                        }
                        #[cfg(test)]
                        if let Some(probe) = worker_probe {
                            probe.0.worker_exits.fetch_add(1, Ordering::SeqCst);
                        }
                    })
            };
            let worker = match worker {
                Ok(worker) => worker,
                Err(_) => {
                    admission_accepting.store(false, Ordering::Release);
                    cancelled.store(true, Ordering::Release);
                    #[cfg(test)]
                    if let Some(probe) = &probe {
                        observe_rejected_submission(&admission_accepting, &work_sender, probe);
                    }
                    drop(work_sender);
                    drop(result_sender);
                    for worker in workers.drain(..) {
                        if worker.join().is_ok() {
                            #[cfg(test)]
                            if let Some(probe) = &probe {
                                probe.0.joined_workers.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    if let Ok(receiver) = work_receiver.lock() {
                        for mut work in receiver.try_iter() {
                            work.partition.zeroize_now();
                        }
                    }
                    while result_receiver.try_recv().is_ok() {}
                    #[cfg(test)]
                    if let Some(probe) = &probe {
                        probe.0.admission_open.store(
                            admission_accepting.load(Ordering::Acquire),
                            Ordering::SeqCst,
                        );
                        probe
                            .0
                            .cancellation_signalled
                            .store(cancelled.load(Ordering::Acquire), Ordering::SeqCst);
                        let work_closed = work_receiver.lock().is_ok_and(|receiver| {
                            matches!(
                                receiver.try_recv(),
                                Err(std_mpsc::TryRecvError::Disconnected)
                            )
                        });
                        let results_closed = matches!(
                            result_receiver.try_recv(),
                            Err(mpsc::error::TryRecvError::Disconnected)
                        );
                        probe
                            .0
                            .channels_closed
                            .store(work_closed && results_closed, Ordering::SeqCst);
                        probe.0.cleanup_observed.store(true, Ordering::SeqCst);
                    }
                    return Err(PipelineError::WorkerPanicked);
                }
            };
            workers.push(worker);
        }
        drop(result_sender);
        Ok(Self {
            work_sender: Some(work_sender),
            work_receiver,
            result_receiver,
            admission_accepting,
            cancelled,
            workers,
            active_workers,
            peak_active_workers,
            #[cfg(test)]
            test_probe: probe,
            #[cfg(test)]
            test_item_budget: None,
            #[cfg(test)]
            test_byte_budget: None,
        })
    }

    #[cfg(test)]
    fn observe_budgets_for_test(
        &mut self,
        item_budget: Arc<Semaphore>,
        byte_budget: Arc<Semaphore>,
    ) {
        self.test_item_budget = Some(item_budget);
        self.test_byte_budget = Some(byte_budget);
    }

    fn submit(
        &self,
        partition: StreamPartition,
        item_permit: OwnedSemaphorePermit,
        byte_permit: OwnedSemaphorePermit,
    ) -> Result<(), PipelineError> {
        self.submit_work(Work {
            partition,
            queued_at: Instant::now(),
            item_permit: Some(item_permit),
            byte_permit: Some(byte_permit),
        })
    }

    fn submit_work(&self, work: Work) -> Result<(), PipelineError> {
        submit_work_through_admission(&self.admission_accepting, self.work_sender.as_ref(), work)
    }

    async fn recv(&mut self) -> Result<Pending<T>, PipelineError> {
        self.result_receiver
            .recv()
            .await
            .ok_or(PipelineError::WorkerPanicked)?
    }

    pub(crate) fn submit_unbudgeted(
        &self,
        partition: StreamPartition,
    ) -> Result<(), PipelineError> {
        self.submit_work(Work {
            partition,
            queued_at: Instant::now(),
            item_permit: None,
            byte_permit: None,
        })
    }

    pub(crate) fn try_recv_mapped(&mut self) -> Result<Option<MappedPartition<T>>, PipelineError> {
        match self.result_receiver.try_recv() {
            Ok(result) => result.map(|pending| Some(pending.mapped)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(PipelineError::WorkerPanicked),
        }
    }

    pub(crate) fn recv_mapped_blocking(&mut self) -> Result<MappedPartition<T>, PipelineError> {
        loop {
            match self.result_receiver.try_recv() {
                Ok(result) => return result.map(|pending| pending.mapped),
                Err(mpsc::error::TryRecvError::Empty) => {
                    // The public file-publish API is synchronous and may be
                    // called by an application already inside a Tokio runtime.
                    // Tokio's `blocking_recv` panics in that context; mapper
                    // workers are independent OS threads, so a short parked
                    // poll waits without entering or nesting the runtime.
                    std::thread::park_timeout(std::time::Duration::from_micros(50));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(PipelineError::WorkerPanicked);
                }
            }
        }
    }

    fn peak_active_workers(&self) -> usize {
        self.peak_active_workers.load(Ordering::Acquire)
    }

    pub(crate) fn shutdown(mut self) -> Result<(), PipelineError> {
        self.admission_accepting.store(false, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
        #[cfg(test)]
        if let (Some(probe), Some(work_sender)) = (&self.test_probe, &self.work_sender) {
            observe_rejected_submission(&self.admission_accepting, work_sender, probe);
        }
        drop(self.work_sender.take());
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                panicked = true;
            } else {
                #[cfg(test)]
                if let Some(probe) = &self.test_probe {
                    probe.0.joined_workers.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        debug_assert_eq!(self.active_workers.load(Ordering::Acquire), 0);
        if let Ok(receiver) = self.work_receiver.lock() {
            for mut work in receiver.try_iter() {
                work.partition.zeroize_now();
            }
        } else {
            panicked = true;
        }
        if panicked {
            Err(PipelineError::WorkerPanicked)
        } else {
            Ok(())
        }
    }
}

async fn stop_workers<T: Send + 'static>(pool: FixedPartitionMapPool<T>) -> bool {
    tokio::task::spawn_blocking(move || pool.shutdown().is_err())
        .await
        .unwrap_or(true)
}

impl<T> Drop for FixedPartitionMapPool<T> {
    fn drop(&mut self) {
        self.admission_accepting.store(false, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
        #[cfg(test)]
        if let (Some(probe), Some(work_sender)) = (&self.test_probe, &self.work_sender) {
            observe_rejected_submission(&self.admission_accepting, work_sender, probe);
        }
        drop(self.work_sender.take());
        // Normal paths call shutdown. On cancellation, joining here guarantees
        // map workers never outlive the job whose plaintext they own.
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                panicked = true;
            } else {
                #[cfg(test)]
                if let Some(probe) = &self.test_probe {
                    probe.0.joined_workers.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        debug_assert_eq!(self.active_workers.load(Ordering::Acquire), 0);
        if let Ok(receiver) = self.work_receiver.lock() {
            for mut work in receiver.try_iter() {
                work.partition.zeroize_now();
            }
        }
        while self.result_receiver.try_recv().is_ok() {}
        #[cfg(test)]
        if let Some(probe) = &self.test_probe {
            probe.0.admission_open.store(
                self.admission_accepting.load(Ordering::Acquire) && self.work_sender.is_some(),
                Ordering::SeqCst,
            );
            probe
                .0
                .cancellation_signalled
                .store(self.cancelled.load(Ordering::Acquire), Ordering::SeqCst);
            let work_closed = self.work_receiver.lock().is_ok_and(|receiver| {
                matches!(
                    receiver.try_recv(),
                    Err(std_mpsc::TryRecvError::Disconnected)
                )
            });
            let results_closed = matches!(
                self.result_receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Disconnected)
            );
            probe
                .0
                .channels_closed
                .store(work_closed && results_closed, Ordering::SeqCst);
            probe.0.cleanup_observed.store(true, Ordering::SeqCst);
            if let Some(budget) = &self.test_item_budget {
                probe
                    .0
                    .available_item_permits
                    .store(budget.available_permits(), Ordering::SeqCst);
            }
            if let Some(budget) = &self.test_byte_budget {
                probe
                    .0
                    .available_byte_permits
                    .store(budget.available_permits(), Ordering::SeqCst);
            }
        }
        let _ = panicked;
    }
}

fn add_observation(
    stages: &mut [StageObservation; PIPELINE_STAGE_COUNT],
    stage: PipelineStage,
    bytes: usize,
    queue_wait: Duration,
    service: Duration,
    output_blocked: Duration,
) {
    let observation = &mut stages[stage as usize];
    observation.items = observation.items.saturating_add(1);
    observation.bytes = observation.bytes.saturating_add(bytes as u64);
    observation.queue_wait_ns = observation
        .queue_wait_ns
        .saturating_add(queue_wait.as_nanos().min(u128::from(u64::MAX)) as u64);
    observation.service_ns = observation
        .service_ns
        .saturating_add(service.as_nanos().min(u128::from(u64::MAX)) as u64);
    observation.output_blocked_ns = observation
        .output_blocked_ns
        .saturating_add(output_blocked.as_nanos().min(u128::from(u64::MAX)) as u64);
}

enum PartitionSourcePoll {
    Ready(Result<Option<StreamPartition>, PipelineError>),
    Pending,
}

trait PartitionSource {
    fn try_next_partition(&mut self) -> PartitionSourcePoll;

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>;
}

struct IteratorPartitionSource<I> {
    iterator: I,
}

impl<I> PartitionSource for IteratorPartitionSource<I>
where
    I: Iterator<Item = StreamPartition>,
{
    fn try_next_partition(&mut self) -> PartitionSourcePoll {
        PartitionSourcePoll::Ready(Ok(self.iterator.next()))
    }

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>
    {
        Box::pin(std::future::ready(Ok(self.iterator.next())))
    }
}

struct ChannelPartitionSource {
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
}

impl PartitionSource for ChannelPartitionSource {
    fn try_next_partition(&mut self) -> PartitionSourcePoll {
        match self.receiver.try_recv() {
            Ok(partition) => PartitionSourcePoll::Ready(partition.map(Some)),
            Err(mpsc::error::TryRecvError::Empty) => PartitionSourcePoll::Pending,
            Err(mpsc::error::TryRecvError::Disconnected) => PartitionSourcePoll::Ready(Ok(None)),
        }
    }

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>
    {
        Box::pin(async move { self.receiver.recv().await.transpose() })
    }
}

pub async fn run_ordered_pipeline<I, T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    partitions: I,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    I: IntoIterator<Item = StreamPartition>,
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_pipeline_source(
        job_id,
        IteratorPartitionSource {
            iterator: partitions.into_iter(),
        },
        0,
        limits,
        map,
        sink,
    )
    .await
}

pub async fn run_ordered_channel_pipeline<T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_channel_pipeline_from(job_id, receiver, 0, limits, map, sink).await
}

pub async fn run_ordered_channel_pipeline_from<T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
    initial_index: u64,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_pipeline_source(
        job_id,
        ChannelPartitionSource { receiver },
        initial_index,
        limits,
        map,
        sink,
    )
    .await
}

async fn run_ordered_pipeline_source<Source, T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    mut source: Source,
    initial_index: u64,
    limits: PipelineLimits,
    map: Map,
    mut sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    Source: PartitionSource,
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    let item_budget = Arc::new(Semaphore::new(limits.max_in_flight_items));
    let byte_budget = Arc::new(Semaphore::new(limits.max_in_flight_bytes));
    #[cfg(test)]
    let test_probe = PipelineTestProbe::for_job(job_id);
    #[cfg(not(test))]
    let test_probe = None;
    #[cfg(test)]
    let map_probe = test_probe.clone();
    #[cfg(not(test))]
    let map_probe = test_probe;
    let mut map_pool = FixedPartitionMapPool::new_with_probe(
        limits.workers,
        limits.max_in_flight_items,
        map,
        map_probe,
    )?;
    #[cfg(test)]
    map_pool.observe_budgets_for_test(Arc::clone(&item_budget), Arc::clone(&byte_budget));

    let outcome = async {
        #[cfg(test)]
        let reorder_probe = test_probe.clone();
        #[cfg(not(test))]
        let reorder_probe = test_probe;
        let mut reorder = ReorderBuffer::new(reorder_probe);
        let mut stages = [StageObservation::default(); PIPELINE_STAGE_COUNT];
        let mut accepted_items = 0_u64;
        let mut completed_items = 0_u64;
        let mut next_index = initial_index;
        let mut peak_items = 0_usize;
        let mut peak_bytes = 0_usize;
        let mut peak_reorder = 0_usize;
        let mut next_partition = None;
        let mut source_done = false;

        loop {
            let mut in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            let admission_limit = limits
                .max_reorder_items
                .saturating_add(1)
                .min(limits.max_in_flight_items);
            while in_flight_items < admission_limit {
                if next_partition.is_none() && !source_done {
                    let next = if in_flight_items == 0 {
                        source.next_partition().await
                    } else {
                        match source.try_next_partition() {
                            PartitionSourcePoll::Ready(next) => next,
                            PartitionSourcePoll::Pending => break,
                        }
                    };
                    match next {
                        Ok(Some(partition)) => next_partition = Some(partition),
                        Ok(None) => source_done = true,
                        Err(error) => return Err(error),
                    }
                }
                let Some(next) = next_partition.as_ref() else {
                    break;
                };
                if next.len() > limits.max_in_flight_bytes {
                    return Err(PipelineError::PartitionTooLarge);
                }
                if next.len() > byte_budget.available_permits() {
                    break;
                }
                let partition = next_partition.take().expect("buffered partition");
                let index = partition.index;
                if partition.is_empty() {
                    return Err(PipelineError::EmptyPartition);
                }
                let expected = initial_index.checked_add(accepted_items).ok_or(
                    PipelineError::NonContiguousIndex {
                        expected: u64::MAX,
                        actual: index,
                    },
                )?;
                if index != expected {
                    return Err(PipelineError::NonContiguousIndex {
                        expected,
                        actual: index,
                    });
                }
                let bytes = partition.len();
                let admission_started = Instant::now();
                let item_permit = Arc::clone(&item_budget)
                    .acquire_owned()
                    .await
                    .map_err(|_| PipelineError::WorkerPanicked)?;
                let byte_permit = Arc::clone(&byte_budget)
                    .acquire_many_owned(bytes as u32)
                    .await
                    .map_err(|_| PipelineError::WorkerPanicked)?;
                add_observation(
                    &mut stages,
                    PipelineStage::Admission,
                    bytes,
                    Duration::ZERO,
                    admission_started.elapsed(),
                    Duration::ZERO,
                );
                accepted_items += 1;
                let current_items = limits.max_in_flight_items - item_budget.available_permits();
                let in_flight_bytes = limits.max_in_flight_bytes - byte_budget.available_permits();
                peak_items = peak_items.max(current_items);
                peak_bytes = peak_bytes.max(in_flight_bytes);
                map_pool.submit(partition, item_permit, byte_permit)?;
                in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            }

            let in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            if in_flight_items == 0 {
                if source_done && next_partition.is_none() && reorder.is_empty() {
                    break;
                }
                continue;
            }

            let pending = map_pool.recv().await?;
            let reorder_started = Instant::now();
            let index = pending.mapped.index;
            let bytes = pending.mapped.input_bytes;
            if index < next_index {
                return Err(PipelineError::NonContiguousIndex {
                    expected: next_index,
                    actual: index,
                });
            }
            if index != next_index {
                if reorder.len() >= limits.max_reorder_items
                    || reorder.insert(index, pending).is_some()
                {
                    return Err(PipelineError::NonContiguousIndex {
                        expected: next_index,
                        actual: index,
                    });
                }
                peak_reorder = peak_reorder.max(reorder.len());
                add_observation(
                    &mut stages,
                    PipelineStage::Reorder,
                    bytes,
                    Duration::ZERO,
                    reorder_started.elapsed(),
                    Duration::ZERO,
                );
                continue;
            }

            add_observation(
                &mut stages,
                PipelineStage::Reorder,
                bytes,
                Duration::ZERO,
                reorder_started.elapsed(),
                Duration::ZERO,
            );

            let mut ready = Some(pending);
            while let Some(pending) = ready.take().or_else(|| reorder.remove(&next_index)) {
                let bytes = pending.mapped.input_bytes;
                add_observation(
                    &mut stages,
                    PipelineStage::Map,
                    bytes,
                    pending.queue_wait,
                    pending.map_time,
                    pending.mapped_at.elapsed(),
                );
                let sink_started = Instant::now();
                sink(pending.mapped).await?;
                add_observation(
                    &mut stages,
                    PipelineStage::Sink,
                    bytes,
                    Duration::ZERO,
                    sink_started.elapsed(),
                    Duration::ZERO,
                );
                completed_items += 1;
                next_index += 1;
            }
        }

        Ok(PipelineReport {
            job_id,
            accepted_items,
            completed_items,
            peak_in_flight_items: peak_items,
            peak_in_flight_bytes: peak_bytes,
            peak_owned_bytes: peak_bytes,
            peak_encoding_bytes: 0,
            peak_reorder_items: peak_reorder,
            worker_count: limits.workers,
            peak_active_workers: map_pool.peak_active_workers(),
            stages,
        })
    }
    .await;

    let worker_panicked = stop_workers(map_pool).await;
    if worker_panicked && outcome.is_ok() {
        Err(PipelineError::WorkerPanicked)
    } else {
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{
            Arc, Barrier, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Debug)]
    struct TestAdapterError;

    impl std::fmt::Display for TestAdapterError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("test adapter failure")
        }
    }

    impl std::error::Error for TestAdapterError {}

    #[test]
    fn pipeline_error_retains_adapter_neutral_typed_source() {
        let error = PipelineError::Adapter(Arc::new(TestAdapterError));
        let source = std::error::Error::source(&error).expect("adapter source");
        assert!(source.downcast_ref::<TestAdapterError>().is_some());
    }

    #[tokio::test]
    async fn pipeline_accepts_async_partitions_and_preserves_order() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::spawn(async move {
            for index in 0..8 {
                sender
                    .send(Ok(StreamPartition::new(index, vec![index as u8; 32])))
                    .await
                    .expect("pipeline remains open");
            }
        });
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let report = run_ordered_channel_pipeline(
            StreamJobId::from_bytes([6; 16]),
            receiver,
            PipelineLimits::new(4, 4, 128, 4).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(partition.into_bytes())
            },
            move |mapped| {
                sink_observed
                    .lock()
                    .expect("sink lock")
                    .push(mapped.index());
                std::future::ready(Ok(()))
            },
        )
        .await
        .expect("pipeline");
        producer.await.expect("producer");

        assert_eq!(
            *observed.lock().expect("observed lock"),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(report.completed_items(), 8);
        assert!(report.peak_in_flight_bytes() <= 128);
    }

    #[tokio::test]
    async fn pipeline_propagates_async_source_failure_after_drain() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(Ok(StreamPartition::new(0, vec![0; 16])))
            .await
            .expect("partition");
        sender
            .send(Err(PipelineError::MapFailed("source".into())))
            .await
            .expect("failure");
        drop(sender);

        let result = run_ordered_channel_pipeline(
            StreamJobId::from_bytes([5; 16]),
            receiver,
            PipelineLimits::new(1, 1, 16, 1).expect("limits"),
            |partition| Ok(partition.into_bytes()),
            |_| std::future::ready(Ok(())),
        )
        .await;

        assert!(matches!(result, Err(PipelineError::MapFailed(message)) if message == "source"));
    }

    #[tokio::test]
    async fn pipeline_reorders_shuffled_worker_results() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let partitions = (0..8)
            .map(|index| StreamPartition::new(index, vec![index as u8; 32]))
            .collect::<Vec<_>>();
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([7; 16]),
            partitions,
            PipelineLimits::new(4, 4, 256, 4).expect("limits"),
            |partition| {
                if partition.index() % 2 == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Ok(partition.into_bytes())
            },
            move |mapped| {
                sink_observed
                    .lock()
                    .expect("sink lock")
                    .push(mapped.index());
                std::future::ready(Ok(()))
            },
        )
        .await
        .expect("pipeline");
        assert_eq!(
            *observed.lock().expect("observed lock"),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(report.accepted_items(), 8);
        assert_eq!(report.completed_items(), 8);
    }

    #[tokio::test]
    async fn pipeline_never_exceeds_byte_or_item_budget() {
        let partitions = (0..32)
            .map(|index| StreamPartition::new(index, vec![0; 64]))
            .collect::<Vec<_>>();
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([8; 16]),
            partitions,
            PipelineLimits::new(3, 3, 192, 3).expect("limits"),
            |partition| Ok(partition.into_bytes()),
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");
        assert!(report.peak_in_flight_items() <= 3);
        assert!(report.peak_in_flight_bytes() <= 192);
        assert!(report.peak_reorder_items() <= 3);
    }

    #[tokio::test]
    async fn pipeline_uses_one_fixed_worker_set_for_the_complete_job() {
        let threads = Arc::new(Mutex::new(HashSet::new()));
        let observed_threads = Arc::clone(&threads);
        let first_workers = Arc::new(Barrier::new(2));
        let worker_rendezvous = Arc::clone(&first_workers);
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([0x81; 16]),
            (0..64)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(2, 4, 64, 4).expect("limits"),
            move |partition| {
                observed_threads
                    .lock()
                    .expect("thread set")
                    .insert(std::thread::current().id());
                if partition.index() < 2 {
                    worker_rendezvous.wait();
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");

        assert_eq!(report.worker_count(), 2);
        assert_eq!(threads.lock().expect("thread set").len(), 2);
    }

    #[test]
    fn fixed_pool_admission_does_not_wait_for_an_active_map() {
        let map_started = Arc::new(std::sync::Barrier::new(2));
        let release_map = Arc::new(std::sync::Barrier::new(2));
        let started = Arc::clone(&map_started);
        let release = Arc::clone(&release_map);
        let mut pool = FixedPartitionMapPool::new(1, 1, move |partition| {
            if partition.index() == 0 {
                started.wait();
                release.wait();
            }
            Ok(partition.into_bytes())
        })
        .expect("pool");

        pool.submit_unbudgeted(StreamPartition::new(0, vec![0; 16]))
            .expect("first partition");
        map_started.wait();

        let (submitted_tx, submitted_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let result = pool.submit_unbudgeted(StreamPartition::new(1, vec![1; 16]));
                submitted_tx.send(result).expect("submission observer");
            });
            let submitted = submitted_rx.recv_timeout(Duration::from_secs(1));
            release_map.wait();
            submitted
                .expect("queued admission waited for the active map")
                .expect("queued partition");
        });

        assert_eq!(pool.recv_mapped_blocking().expect("first map").index(), 0);
        assert_eq!(pool.recv_mapped_blocking().expect("second map").index(), 1);
        pool.shutdown().expect("joined pool");
    }

    #[tokio::test]
    async fn pipeline_early_validation_failure_joins_active_workers() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let active = Arc::new(AtomicUsize::new(0));
        let active_worker = Arc::clone(&active);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let source_release = Arc::clone(&release);
        let worker_release = Arc::clone(&release);
        let mut index = 0_u64;
        let partitions = std::iter::from_fn(move || {
            let partition = match index {
                0 => StreamPartition::new(0, vec![0; 16]),
                1 => {
                    started_rx
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .expect("first worker started");
                    let (released, condition) = &*source_release;
                    *released.lock().expect("release state") = true;
                    condition.notify_all();
                    StreamPartition::new(1, vec![0; 33])
                }
                _ => return None,
            };
            index += 1;
            Some(partition)
        });
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([0x82; 16]),
            partitions,
            PipelineLimits::new(2, 2, 32, 2).expect("limits"),
            move |partition| {
                active_worker.fetch_add(1, Ordering::SeqCst);
                started_tx.send(()).expect("signal worker start");
                let (released, condition) = &*worker_release;
                let mut released = released.lock().expect("release state");
                while !*released {
                    released = condition.wait(released).expect("release worker");
                }
                active_worker.fetch_sub(1, Ordering::SeqCst);
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await;

        assert!(matches!(result, Err(PipelineError::PartitionTooLarge)));
        assert_eq!(active.load(Ordering::SeqCst), 0, "worker still running");
    }

    #[tokio::test]
    async fn pipeline_reports_queue_service_and_output_blocking_separately() {
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([0x83; 16]),
            (0..8)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(2, 4, 64, 4).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");

        let map = report.stage(PipelineStage::Map);
        assert_eq!(map.items, 8);
        assert!(map.queue_wait_ns > 0);
        assert!(map.service_ns > 0);
        assert!(map.output_blocked_ns > 0);
        let metrics = report.to_string();
        assert!(metrics.starts_with("workers:2;peak_active_workers:"));
        assert!(metrics.contains(";map:8:128:"));
        assert!(metrics.contains(";sink:8:128:"));
    }

    #[tokio::test]
    async fn pipeline_worker_panic_is_terminal_not_success() {
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([9; 16]),
            vec![StreamPartition::new(0, vec![0; 4])],
            PipelineLimits::new(1, 1, 4, 1).expect("limits"),
            |_| -> Result<Vec<u8>, PipelineError> { panic!("worker failure") },
            |_| std::future::ready(Ok(())),
        )
        .await;
        assert!(matches!(result, Err(PipelineError::WorkerPanicked)));
    }

    #[tokio::test]
    async fn pipeline_slow_first_partition_backpressures_at_reorder_limit() {
        let job = StreamJobId::from_bytes([10; 16]);
        let probe = PipelineTestProbe::install(job);
        let report = run_ordered_pipeline(
            job,
            (0..12)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(4, 4, 64, 2).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");
        assert_eq!(report.peak_reorder_items(), 2);
        assert!(report.peak_in_flight_items() <= 3);
        assert_eq!(probe.peak_reorder_items(), 2);
        assert_eq!(probe.current_reorder_items(), 0);
    }

    #[tokio::test]
    async fn pipeline_sink_failure_joins_workers_and_reclaims_permits() {
        let job = StreamJobId::from_bytes([11; 16]);
        let probe = PipelineTestProbe::install(job);
        let zeroized = Arc::new(AtomicUsize::new(0));
        struct Plaintext {
            bytes: Vec<u8>,
            zeroized: Arc<AtomicUsize>,
        }
        impl Drop for Plaintext {
            fn drop(&mut self) {
                self.bytes.zeroize();
                self.zeroized.fetch_add(1, Ordering::SeqCst);
            }
        }

        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let map_release = Arc::clone(&release);
        let map_zeroized = Arc::clone(&zeroized);
        let (sender, receiver) = mpsc::channel(3);
        for index in 0..3 {
            sender
                .send(Ok(StreamPartition::new(index, vec![0x5a; 16])
                    .observe_zeroize_for_test(Arc::clone(&zeroized))))
                .await
                .unwrap();
        }
        let pipeline = tokio::spawn(run_ordered_channel_pipeline(
            job,
            receiver,
            PipelineLimits::new(2, 3, 48, 1).expect("limits"),
            move |partition| {
                if partition.index() == 0 {
                    let (released, condition) = &*map_release;
                    let mut released = released.lock().expect("failure gate");
                    while !*released {
                        released = condition.wait(released).expect("wait for failure release");
                    }
                }
                Ok(Plaintext {
                    bytes: partition.into_bytes(),
                    zeroized: Arc::clone(&map_zeroized),
                })
            },
            |_| std::future::ready(Err(PipelineError::SinkFailed("cancel".into()))),
        ));

        while probe.current_reorder_items() != 1 || probe.active_workers() != 1 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            sender.capacity(),
            2,
            "one plaintext partition must remain queued"
        );
        assert_eq!(
            zeroized.load(Ordering::SeqCst),
            0,
            "failure not injected yet"
        );
        {
            let (released, condition) = &*release;
            *released.lock().expect("release failure gate") = true;
            condition.notify_all();
        }
        let result = pipeline.await.expect("join pipeline task");
        assert!(matches!(result, Err(PipelineError::SinkFailed(_))));
        assert!(
            sender
                .send(Err(PipelineError::EmptyPartition))
                .await
                .is_err()
        );
        assert!(!probe.admission_open(), "admission remained open");
        assert!(
            probe.admission_rejected(),
            "internal admission still accepts"
        );
        assert!(
            probe.rejected_plaintext_zeroized(),
            "rejected sentinel plaintext was not zeroized"
        );
        assert!(
            probe.rejected_permits_reclaimed(),
            "rejected sentinel permits leaked"
        );
        assert!(probe.cleanup_observed(), "cleanup state was not observed");
        assert!(
            probe.cancellation_signalled(),
            "cancellation was not signalled"
        );
        assert!(probe.channels_closed(), "pipeline channels remained open");
        assert_eq!(probe.worker_exits(), 2, "not every fixed worker exited");
        assert_eq!(probe.joined_workers(), 2, "not every fixed worker joined");
        assert_eq!(probe.peak_active_workers(), 2);
        assert_eq!(probe.peak_reorder_items(), 1);
        assert_eq!(probe.available_item_permits(), 3);
        assert_eq!(probe.available_byte_permits(), 48);
        assert_eq!(probe.current_reorder_items(), 0);
        assert_eq!(zeroized.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn partial_worker_spawn_failure_joins_created_workers_before_returning() {
        let job = StreamJobId::from_bytes([13; 16]);
        let probe = PipelineTestProbe::install(job);
        probe.hold_workers_for_test();
        probe.fail_spawn_at_for_test(2);
        let zeroized = Arc::new(AtomicUsize::new(0));
        let item_budget = Arc::new(Semaphore::new(1));
        let byte_budget = Arc::new(Semaphore::new(16));
        let work = Work {
            partition: StreamPartition::new(0, vec![0x5a; 16])
                .observe_zeroize_for_test(Arc::clone(&zeroized)),
            queued_at: Instant::now(),
            item_permit: Some(Arc::clone(&item_budget).try_acquire_owned().unwrap()),
            byte_permit: Some(Arc::clone(&byte_budget).try_acquire_many_owned(16).unwrap()),
        };
        let result = FixedPartitionMapPool::<Vec<u8>>::new_with_probe_and_initial_work(
            3,
            3,
            |partition| Ok(partition.into_bytes()),
            Some(probe.clone()),
            vec![work],
        );
        assert!(matches!(result, Err(PipelineError::WorkerPanicked)));
        assert!(!probe.admission_open());
        assert!(probe.admission_rejected());
        assert!(probe.rejected_plaintext_zeroized());
        assert!(probe.rejected_permits_reclaimed());
        assert!(probe.cleanup_observed());
        assert!(probe.cancellation_signalled());
        assert!(probe.channels_closed());
        assert_eq!(probe.worker_exits(), 2);
        assert_eq!(probe.joined_workers(), 2);
        assert_eq!(probe.active_workers(), 0);
        assert_eq!(zeroized.load(Ordering::SeqCst), 1);
        assert_eq!(item_budget.available_permits(), 1);
        assert_eq!(byte_budget.available_permits(), 16);
    }

    #[tokio::test]
    async fn resumed_channel_pipeline_starts_at_durable_partition_index() {
        let (sender, receiver) = mpsc::channel(2);
        sender
            .send(Ok(StreamPartition::new(7, vec![7])))
            .await
            .unwrap();
        sender
            .send(Ok(StreamPartition::new(8, vec![8])))
            .await
            .unwrap();
        drop(sender);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let report = run_ordered_channel_pipeline_from(
            StreamJobId::from_bytes([12; 16]),
            receiver,
            7,
            PipelineLimits::new(2, 2, 2, 2).unwrap(),
            |partition| Ok(partition.into_bytes()),
            move |mapped| {
                sink_observed.lock().unwrap().push(mapped.index());
                std::future::ready(Ok(()))
            },
        )
        .await
        .unwrap();
        assert_eq!(*observed.lock().unwrap(), vec![7, 8]);
        assert_eq!(report.completed_items(), 2);
    }
}
