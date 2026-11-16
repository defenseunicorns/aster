//! Synchronous, versioned C facade over the selected node's single redb authority.
//! Handles are non-reused, node-owned capabilities. Each call serializes with
//! close/zeroize. Caller-owned output copies remain valid until explicitly freed.
#![allow(unsafe_code, missing_docs, clippy::not_unsafe_ptr_arg_deref)]
use aster_mesh::{Priority, Scope, Topic};
use aster_node::{
    ControlAdminError, ControlAdminErrorKind, EventEmissionPolicy, MAX_SELECTED_REKEY_RECIPIENTS,
    MAX_SELECTED_REKEY_TOPIC_GRANTS, MutableSourceInterests, NodeApplication, NodeError,
    NodeOperatorOutputPolicy, RegistryGenerationWitness, RunningNode, ScopeRekeyRequest,
    SelectedForwardingConfig, StoreLimits, TransportNeutralNodeConfig,
    application::{
        ApplicationError, ApplicationErrorKind, AuthenticatedPeerStatus, BlobDeliveryItem,
        BlobDeliveryToken, BlobDepotLimits, BlobId, BlobPollRequest, BlobPublicationId,
        BlobPublishOptions, BlobPublishRequest, BlobPublishResult, BlobPublishStreamRequest,
        BlobReadPageRequest, BlobReadRequest, BlobRetirementReason, BlobSubscriptionId,
        BlobSubscriptionRequest, CommittedEventContent, ContactSyncStatus, EventClientContext,
        EventClientId, EventId, EventItem, EventOperationSequence, EventPollRequest,
        EventPublicationSession, EventPublishOptions, EventQuery, EventSubscriptionId,
        EventSubscriptionRequest, MAX_SELECTED_BLOB_PAGE_BYTES, MAX_SELECTED_EVENT_PAGE,
        NumberedEventPublishRequest, NumberedEventResult, PeerAuthorization, RecordDeliveryToken,
        RecordItem, RecordPollRequest, RecordProjection, RecordProjectionId, RecordPublishRequest,
        RecordQuery, RecordResolutionGuard, RecordResolveRequest, RecordSubscriptionId,
        RecordSubscriptionRequest, RecordVersionDisposition, SelectedBlobPublishStream,
        StateDeliveryToken, StateId, StateItem, StatePollRequest, StatePublishRequest, StateQuery,
        StateSubscriptionId, StateSubscriptionRequest, StateVersionDisposition,
    },
    ensure_state_accepts_normal_operation,
    mission::UnprotectedReferenceMission,
    start_externally_supervised_local_node,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    future::Future,
    mem::{align_of, size_of},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    slice, str,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;
mod abi;
pub use abi::*;
mod operations;

pub const ABI_VERSION: u32 = 2;
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHILD_HANDLES: usize = 64;
const STATUS_OK: u32 = 0;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_ABI_MISMATCH: u32 = 2;
const STATUS_INVALID_UTF8: u32 = 3;
const STATUS_NOT_FOUND: u32 = 4;
const STATUS_CLOSED: u32 = 5;
const STATUS_ZEROIZED: u32 = 6;
const STATUS_QUOTA_EXCEEDED: u32 = 7;
const STATUS_STALE_CONFLICT: u32 = 8;
const STATUS_SECURITY_ERROR: u32 = 9;
const STATUS_STORAGE_ERROR: u32 = 10;
const STATUS_UNSUPPORTED: u32 = 11;
const STATUS_EXPIRED: u32 = 12;
const STATUS_FENCED: u32 = 13;
const STATUS_SEQUENCE_GAP: u32 = 14;
const STATUS_SEQUENCE_RETIRED: u32 = 15;
const STATUS_RECOVERY_REQUIRED: u32 = 16;
const STATUS_POLICY_UNSETTLED: u32 = 17;
const STATUS_PANIC: u32 = 254;
const STATUS_INTERNAL_ERROR: u32 = 255;
#[derive(Debug)]
struct FfiError {
    status: u32,
    message: String,
}

impl FfiError {
    fn new(status: u32, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(STATUS_INVALID_ARGUMENT, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(STATUS_INTERNAL_ERROR, message)
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    LAST_ERROR.with(|slot| slot.borrow_mut().clone_from(&message));
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| slot.borrow_mut().clear());
}

fn boundary(operation: impl FnOnce() -> Result<(), FfiError>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => {
            clear_last_error();
            STATUS_OK
        }
        Ok(Err(error)) => {
            set_last_error(error.message);
            error.status
        }
        Err(_) => {
            set_last_error("Rust panic contained at the Aster ABI boundary");
            STATUS_PANIC
        }
    }
}

fn boundary_preserve_error(operation: impl FnOnce() -> Result<(), FfiError>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(error)) => {
            set_last_error(error.message);
            error.status
        }
        Err(_) => {
            set_last_error("Rust panic contained at the Aster ABI boundary");
            STATUS_PANIC
        }
    }
}

#[repr(C)]
struct AbiHeader {
    abi_version: u32,
    struct_size: u32,
}
const fn struct_size<T>() -> u32 {
    assert!(size_of::<T>() <= u32::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    {
        size_of::<T>() as u32
    }
}
fn check_pointer<T>(pointer: *const T, name: &str) -> Result<(), FfiError> {
    if pointer.is_null() {
        return Err(FfiError::invalid(format!("{name} must not be null")));
    }
    if !(pointer as usize).is_multiple_of(align_of::<T>()) {
        return Err(FfiError::invalid(format!(
            "{name} is not correctly aligned"
        )));
    }
    Ok(())
}

fn empty_handle(pointer: *mut u64, name: &str) -> Result<(), FfiError> {
    check_mut_pointer(pointer, name)?;
    // SAFETY: the ABI requires a readable, writable initialized output handle.
    if unsafe { pointer.read() } != 0 {
        return Err(FfiError::invalid(format!(
            "{name} output handle must be zero"
        )));
    }
    Ok(())
}

fn check_mut_pointer<T>(pointer: *mut T, name: &str) -> Result<(), FfiError> {
    check_pointer(pointer.cast_const(), name)
}

fn versioned<'a, T>(pointer: *const T, name: &str) -> Result<&'a T, FfiError> {
    check_pointer(pointer, name)?;
    // SAFETY: null and alignment were checked. The C contract requires the
    // pointed allocation to remain readable for this call; no reference escapes.
    let header = unsafe { &*pointer.cast::<AbiHeader>() };
    if header.abi_version != ABI_VERSION {
        return Err(FfiError::new(
            STATUS_ABI_MISMATCH,
            format!("{name}.abi_version is not supported"),
        ));
    }
    let required = struct_size::<T>();
    if header.struct_size < required {
        return Err(FfiError::new(
            STATUS_ABI_MISMATCH,
            format!("{name}.struct_size is smaller than {required}"),
        ));
    }
    // SAFETY: the checked size covers T and alignment was checked above.
    Ok(unsafe { &*pointer })
}

fn versioned_mut<'a, T>(pointer: *mut T, name: &str) -> Result<&'a mut T, FfiError> {
    let _ = versioned(pointer.cast_const(), name)?;
    // SAFETY: versioned checked null, alignment, and allocation size. The ABI
    // requires exclusive access to output structs while a call mutates them.
    Ok(unsafe { &mut *pointer })
}

fn write_output<T>(pointer: *mut T, value: T, name: &str) -> Result<(), FfiError> {
    check_mut_pointer(pointer, name)?;
    // SAFETY: null and alignment were checked; outputs are caller-owned and the
    // ABI requires at least size_of::<T>() writable bytes.
    unsafe { pointer.write(value) };
    Ok(())
}

fn take_handle<T: Copy + Default>(pointer: *mut T, name: &str) -> Result<T, FfiError> {
    check_mut_pointer(pointer, name)?;
    // SAFETY: pointer null/alignment were checked and the close contract grants
    // exclusive access. Replacing with the all-zero Default invalidates the
    // caller's capability before any potentially blocking cleanup.
    let value = unsafe { pointer.read() };
    unsafe { pointer.write(T::default()) };
    Ok(value)
}

fn input_bytes<'a>(value: AsterBytes, name: &str) -> Result<&'a [u8], FfiError> {
    if value.len > MAX_INPUT_BYTES || value.len > isize::MAX as usize {
        return Err(FfiError::invalid(format!("{name} length is too large")));
    }
    if value.len == 0 {
        return Ok(&[]);
    }
    if value.data.is_null() {
        return Err(FfiError::invalid(format!(
            "{name}.data must not be null when length is nonzero"
        )));
    }
    // u8 has alignment one. The C contract requires readable storage for len
    // bytes during the call. Every caller is copied before returning.
    Ok(unsafe { slice::from_raw_parts(value.data, value.len) })
}

fn input_array<'a, T>(
    pointer: *const T,
    count: usize,
    maximum: usize,
    name: &str,
) -> Result<&'a [T], FfiError> {
    if count > maximum {
        return Err(FfiError::invalid(format!("{name} count exceeds {maximum}")));
    }
    if count == 0 {
        return Ok(&[]);
    }
    check_pointer(pointer, name)?;
    let byte_len = size_of::<T>()
        .checked_mul(count)
        .filter(|length| isize::try_from(*length).is_ok())
        .ok_or_else(|| FfiError::invalid(format!("{name} byte length is too large")))?;
    if byte_len == 0 {
        return Err(FfiError::internal("zero-sized ABI array element"));
    }
    // SAFETY: pointer null/alignment and a strict element/byte bound were
    // checked. The ABI requires the array to remain readable for this call.
    Ok(unsafe { slice::from_raw_parts(pointer, count) })
}

fn input_string(value: AsterBytes, name: &str) -> Result<String, FfiError> {
    let bytes = input_bytes(value, name)?;
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FfiError::new(STATUS_INVALID_UTF8, format!("{name} is not valid UTF-8")))
}

fn input_topic(value: AsterBytes, name: &str) -> Result<Topic, FfiError> {
    Topic::new(input_string(value, name)?).map_err(|error| FfiError::invalid(error.to_string()))
}

fn input_scope(value: AsterBytes, name: &str) -> Result<Scope, FfiError> {
    Scope::new(input_string(value, name)?).map_err(|error| FfiError::invalid(error.to_string()))
}

impl From<ApplicationError> for FfiError {
    fn from(error: ApplicationError) -> Self {
        let status = match error.kind() {
            ApplicationErrorKind::InvalidRequest | ApplicationErrorKind::RequestRejected => {
                STATUS_INVALID_ARGUMENT
            }
            ApplicationErrorKind::UnsupportedValue | ApplicationErrorKind::LegacyState => {
                STATUS_UNSUPPORTED
            }
            ApplicationErrorKind::NotFound => STATUS_NOT_FOUND,
            ApplicationErrorKind::Conflict => STATUS_STALE_CONFLICT,
            ApplicationErrorKind::UnauthorizedOrRevoked
            | ApplicationErrorKind::Integrity
            | ApplicationErrorKind::Provisioning => STATUS_SECURITY_ERROR,
            ApplicationErrorKind::ResourceLimit | ApplicationErrorKind::OperationCapacity => {
                STATUS_QUOTA_EXCEEDED
            }
            ApplicationErrorKind::ExpiredOrRetired => STATUS_EXPIRED,
            ApplicationErrorKind::SessionFenced => STATUS_FENCED,
            ApplicationErrorKind::SequenceGap => STATUS_SEQUENCE_GAP,
            ApplicationErrorKind::SequenceRetired => STATUS_SEQUENCE_RETIRED,
            ApplicationErrorKind::RecoveryRequired => STATUS_RECOVERY_REQUIRED,
            ApplicationErrorKind::PolicyUnsettled => STATUS_POLICY_UNSETTLED,
            _ => STATUS_STORAGE_ERROR,
        };
        Self::new(status, error.to_string())
    }
}
impl From<NodeError> for FfiError {
    fn from(error: NodeError) -> Self {
        // NodeError may contain local paths or provider details. Never expose them.
        let (status, message) = match error {
            NodeError::Configuration(_) => (STATUS_INVALID_ARGUMENT, "invalid node configuration"),
            NodeError::MissionProvisioning(_) | NodeError::Revoked(_) => {
                (STATUS_SECURITY_ERROR, "mission provisioning rejected")
            }
            _ => (STATUS_STORAGE_ERROR, "selected node lifecycle failed"),
        };
        Self::new(status, message)
    }
}
impl From<ControlAdminError> for FfiError {
    fn from(error: ControlAdminError) -> Self {
        let status = match error.kind() {
            ControlAdminErrorKind::InvalidRequest => STATUS_INVALID_ARGUMENT,
            ControlAdminErrorKind::Conflict => STATUS_STALE_CONFLICT,
            ControlAdminErrorKind::UnauthorizedOrRevoked
            | ControlAdminErrorKind::Integrity
            | ControlAdminErrorKind::Provisioning => STATUS_SECURITY_ERROR,
            ControlAdminErrorKind::ResourceLimit => STATUS_QUOTA_EXCEEDED,
            ControlAdminErrorKind::PolicyUnsettled => STATUS_POLICY_UNSETTLED,
            _ => STATUS_STORAGE_ERROR,
        };
        Self::new(status, error.to_string())
    }
}
fn boolean(value: u8, name: &str) -> Result<bool, FfiError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FfiError::invalid(format!("{name} must be 0 or 1"))),
    }
}
fn priority(value: u32) -> Result<Priority, FfiError> {
    u8::try_from(value)
        .ok()
        .and_then(Priority::from_wire)
        .ok_or_else(|| FfiError::invalid("invalid priority"))
}
fn emission(value: u32) -> Result<EventEmissionPolicy, FfiError> {
    if value == 4 {
        Ok(EventEmissionPolicy::ReceiveOnly)
    } else {
        Ok(EventEmissionPolicy::at_least(priority(value)?))
    }
}
fn bounded(value: u64, max: usize, name: &str) -> Result<usize, FfiError> {
    usize::try_from(value)
        .ok()
        .filter(|n| *n > 0 && *n <= max)
        .ok_or_else(|| FfiError::invalid(format!("{name} is outside its bound")))
}
fn fixed<const N: usize>(bytes: AsterBytes, name: &str) -> Result<[u8; N], FfiError> {
    input_bytes(bytes, name)?
        .try_into()
        .map_err(|_| FfiError::invalid(format!("invalid {name} length")))
}
fn client(value: AsterClient) -> Result<EventClientContext, FfiError> {
    Ok(EventClientContext {
        client_id: client_id(value.client_id)?,
        session: EventPublicationSession::new(value.session)
            .map_err(|_| FfiError::invalid("session must be positive"))?,
    })
}
fn client_id(value: AsterBytes) -> Result<EventClientId, FfiError> {
    EventClientId::new(input_bytes(value, "client_id")?.to_vec())
        .map_err(|_| FfiError::invalid("invalid client_id"))
}
fn sequence(value: u64) -> Result<EventOperationSequence, FfiError> {
    EventOperationSequence::new(value).map_err(|_| FfiError::invalid("sequence must be positive"))
}
fn lock<'a, T>(m: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, FfiError> {
    m.lock()
        .map_err(|_| FfiError::internal(format!("{name} lock poisoned")))
}
static NEXT: AtomicU64 = AtomicU64::new(1);
fn new_handle() -> Result<u64, FfiError> {
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| FfiError::internal("handle space exhausted"))
}
fn closed() -> FfiError {
    FfiError::new(STATUS_CLOSED, "unknown, foreign, or closed handle")
}
fn capacity(len: usize) -> Result<(), FfiError> {
    if len >= MAX_CHILD_HANDLES {
        Err(FfiError::new(
            STATUS_QUOTA_EXCEEDED,
            "close outstanding handles before allocating more",
        ))
    } else {
        Ok(())
    }
}
// The runtime stays independent of the calling language's async executor. The
// scoped thread also permits safe calls from Rust/Tokio and joins every operation.
fn wait<F: Future + Send>(rt: &Runtime, future: F) -> Result<F::Output, FfiError>
where
    F::Output: Send,
{
    std::thread::scope(|s| s.spawn(|| rt.block_on(future)).join())
        .map_err(|_| FfiError::internal("node operation panicked"))
}
struct Node {
    runtime: Option<Runtime>,
    running: Option<RunningNode>,
    provisioning: PathBuf,
    results: HashMap<u64, Snapshot>,
    writers: HashMap<u64, Writer>,
    readers: HashMap<u64, Reader>,
}
impl Node {
    fn running(&self) -> Result<&RunningNode, FfiError> {
        self.running.as_ref().ok_or_else(closed)
    }
    fn wait<F: Future + Send>(&self, f: F) -> Result<F::Output, FfiError>
    where
        F::Output: Send,
    {
        wait(self.runtime.as_ref().ok_or_else(closed)?, f)
    }
    fn insert(&mut self, snapshot: Snapshot) -> Result<u64, FfiError> {
        capacity(self.results.len())?;
        let id = new_handle()?;
        self.results.insert(id, snapshot);
        Ok(id)
    }
    fn shutdown(&mut self) -> Result<(), FfiError> {
        self.results.clear();
        self.writers.clear();
        self.readers.clear();
        let result = if let Some(running) = self.running.take() {
            self.wait(running.shutdown())?
                .map(|_| ())
                .map_err(FfiError::from)
        } else {
            Ok(())
        };
        if let Some(rt) = self.runtime.take() {
            std::thread::spawn(move || drop(rt))
                .join()
                .map_err(|_| FfiError::internal("runtime shutdown panicked"))?;
        }
        result
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
type NodeCell = Arc<Mutex<Option<Node>>>;
fn nodes() -> &'static Mutex<HashMap<u64, NodeCell>> {
    static N: OnceLock<Mutex<HashMap<u64, NodeCell>>> = OnceLock::new();
    N.get_or_init(Mutex::default)
}
fn with_node<T>(id: u64, f: impl FnOnce(&mut Node) -> Result<T, FfiError>) -> Result<T, FfiError> {
    let cell = lock(nodes(), "nodes")?
        .get(&id)
        .cloned()
        .ok_or_else(closed)?;
    let mut guard = lock(&cell, "node")?;
    f(guard.as_mut().ok_or_else(closed)?)
}
#[derive(Default)]
struct Item {
    id: [u8; 32],
    blob_id: [u8; 32],
    publisher: [u8; 32],
    counter: u64,
    class: u32,
    priority: u32,
    disposition: u32,
    sequence: u64,
    marker: u64,
    total_len: u64,
    ttl: Option<u64>,
    tombstone: bool,
    topic: String,
    scope: String,
    key: Vec<u8>,
    payload: Zeroizing<Vec<u8>>,
    media: String,
    schema: Vec<u8>,
}
#[derive(Default)]
struct Entry {
    items: Vec<Item>,
    id: [u8; 32],
    attempt: u64,
    token: Vec<u8>,
    siblings: Vec<u8>,
    topic: String,
    scope: String,
    key: Vec<u8>,
    guard: Option<RecordResolutionGuard>,
    kind: u32,
    retirement_reason: u32,
    retirement_generation: u64,
}
#[derive(Default)]
struct Snapshot {
    entries: Vec<Entry>,
    receipts: Vec<AsterPublishReceipt>,
    peers: Vec<AsterPeerSnapshot>,
    marker: u64,
    more: bool,
}
struct Writer {
    request: BlobPublishStreamRequest,
    stream: Option<SelectedBlobPublishStream>,
    offset: u64,
    finished: Option<AsterPublishReceipt>,
}
struct Reader {
    request: BlobReadRequest,
    offset: u64,
    complete: bool,
}
// Allocation IDs prevent a stale copied buffer from freeing a later allocation
// at a reused address. The caller must still honor its own borrowed lifetimes.
type Allocations = HashMap<u64, Zeroizing<Box<[u8]>>>;
fn allocations() -> &'static Mutex<Allocations> {
    static A: OnceLock<Mutex<Allocations>> = OnceLock::new();
    A.get_or_init(Mutex::default)
}
fn owned_buffer(bytes: &[u8]) -> Result<AsterOwnedBuffer, FfiError> {
    if bytes.is_empty() {
        return Ok(AsterOwnedBuffer::default());
    }
    let mut all = lock(allocations(), "allocations")?;
    if all.len() >= 65536 {
        return Err(FfiError::new(
            STATUS_QUOTA_EXCEEDED,
            "too many output allocations",
        ));
    }
    let id = new_handle()?;
    let mut data = Zeroizing::new(bytes.to_vec().into_boxed_slice());
    let result = AsterOwnedBuffer {
        allocation: id,
        data: data.as_mut_ptr(),
        len: data.len(),
        ..Default::default()
    };
    all.insert(id, data);
    Ok(result)
}
fn require_empty_buffer(b: &AsterOwnedBuffer, name: &str) -> Result<(), FfiError> {
    if b.allocation == 0 && b.data.is_null() && b.len == 0 {
        Ok(())
    } else {
        Err(FfiError::invalid(format!("{name} must be empty")))
    }
}
fn release_buffer(b: &mut AsterOwnedBuffer) -> Result<(), FfiError> {
    if b.allocation == 0 {
        require_empty_buffer(b, "buffer")?;
        *b = AsterOwnedBuffer::default();
        return Ok(());
    }
    let mut all = lock(allocations(), "allocations")?;
    let data = all
        .get(&b.allocation)
        .ok_or_else(|| FfiError::invalid("foreign or freed buffer"))?;
    if data.as_ptr() != b.data.cast_const() || data.len() != b.len {
        return Err(FfiError::invalid("modified output buffer"));
    }
    all.remove(&b.allocation);
    *b = AsterOwnedBuffer::default();
    Ok(())
}
struct OutputBuffers(Vec<AsterOwnedBuffer>);
impl OutputBuffers {
    fn add(&mut self, bytes: &[u8]) -> Result<AsterOwnedBuffer, FfiError> {
        let b = owned_buffer(bytes)?;
        self.0.push(b);
        Ok(b)
    }
    fn commit(mut self) {
        self.0.clear();
    }
}
impl Drop for OutputBuffers {
    fn drop(&mut self) {
        for b in &mut self.0 {
            let _ = release_buffer(b);
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_abi_version() -> u32 {
    ABI_VERSION
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_protocol_version() -> u16 {
    aster_mesh::PROTOCOL_VERSION
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_replication_wire_version() -> u16 {
    aster_mesh::REPLICATION_WIRE_VERSION
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_default_semantic_version() -> u16 {
    aster_mesh::DEFAULT_SEMANTIC_VERSION
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_highest_supported_semantic_version() -> u16 {
    aster_mesh::HIGHEST_SUPPORTED_SEMANTIC_VERSION
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_last_error(out: *mut AsterOwnedBuffer) -> u32 {
    boundary_preserve_error(|| {
        let out = versioned_mut(out, "error")?;
        require_empty_buffer(out, "error")?;
        *out = LAST_ERROR.with(|s| owned_buffer(s.borrow().as_bytes()))?;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_buffer_free(out: *mut AsterOwnedBuffer) -> u32 {
    boundary_preserve_error(|| release_buffer(versioned_mut(out, "buffer")?))
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_options_init(out: *mut AsterNodeOptions) -> u32 {
    boundary(|| {
        write_output(
            out,
            AsterNodeOptions {
                max_items: StoreLimits::default().max_items(),
                max_bytes: StoreLimits::default().max_total_payload_bytes(),
                max_blob_bytes: BlobDepotLimits::DEFAULT.max_bytes(),
                max_blob_chunks: BlobDepotLimits::DEFAULT.max_chunks(),
                max_blob_variants: BlobDepotLimits::DEFAULT.max_variants(),
                ..Default::default()
            },
            "options",
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_open(options: *const AsterNodeOptions, out: *mut u64) -> u32 {
    boundary(|| {
        let o = versioned(options, "options")?;
        empty_handle(out, "node")?;
        let state = PathBuf::from(input_string(o.state_path, "state_path")?);
        let provisioning = PathBuf::from(input_string(o.provisioning_path, "provisioning_path")?);
        if !state.is_absolute() || !provisioning.is_absolute() {
            return Err(FfiError::invalid(
                "state and provisioning paths must be absolute",
            ));
        }
        let forwarding = SelectedForwardingConfig::new(
            emission(o.emission_threshold)?,
            StoreLimits::new(o.max_items, o.max_bytes)
                .map_err(|_| FfiError::invalid("storage limits must be positive"))?,
        )
        .with_blob_depot_limits(
            BlobDepotLimits::new(o.max_blob_bytes, o.max_blob_chunks, o.max_blob_variants)
                .map_err(|_| FfiError::invalid("Blob limits must be positive"))?,
        );
        ensure_state_accepts_normal_operation(&state)
            .map_err(|_| FfiError::new(STATUS_ZEROIZED, "state is unavailable or terminal"))?;
        let mission = UnprotectedReferenceMission::load(&provisioning).map_err(|_| {
            FfiError::new(
                STATUS_SECURITY_ERROR,
                "owner-only reference provisioning rejected",
            )
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| FfiError::internal("runtime creation failed"))?;
        let mut node = Node {
            runtime: Some(runtime),
            running: None,
            provisioning,
            results: HashMap::new(),
            writers: HashMap::new(),
            readers: HashMap::new(),
        };
        node.running = Some(node.wait(start_externally_supervised_local_node(
            TransportNeutralNodeConfig {
                state,
                mission,
                mutable_interests: MutableSourceInterests::default(),
                sync_interval: Duration::from_secs(1),
                run_for: None,
                application: NodeApplication::Relay,
            },
            forwarding,
            NodeOperatorOutputPolicy::CustomerSafe,
        ))??);
        let id = new_handle()?;
        let mut registry = lock(nodes(), "nodes")?;
        if registry.len() >= 128 {
            return Err(FfiError::new(STATUS_QUOTA_EXCEEDED, "node limit reached"));
        }
        registry.insert(id, Arc::new(Mutex::new(Some(node))));
        write_output(out, id, "node")
    })
}
fn close_node(out: *mut u64, zeroize: bool) -> Result<(), FfiError> {
    let id = take_handle(out, "node")?;
    if id == 0 {
        return Ok(());
    }
    let cell = lock(nodes(), "nodes")?.remove(&id).ok_or_else(closed)?;
    let mut node = lock(&cell, "node")?.take().ok_or_else(closed)?;
    node.results.clear();
    node.writers.clear();
    node.readers.clear();
    let result = if zeroize {
        node.wait(node.running()?.zeroize_embedded(&node.provisioning))?
            .map_err(FfiError::from)
    } else {
        Ok(())
    };
    let shutdown = node.shutdown();
    result.and(shutdown)
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_close(out: *mut u64) -> u32 {
    boundary(|| close_node(out, false))
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_zeroize(out: *mut u64) -> u32 {
    boundary(|| close_node(out, true))
}

#[cfg(test)]
mod tests;
