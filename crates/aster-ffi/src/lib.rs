//! Stable, versioned C ABI for the synchronous Aster node facade.
//!
//! This is the only crate in the workspace permitted to use `unsafe`: each use
//! is confined to checking and copying an FFI pointer at the boundary. Core
//! state, result snapshots, and output allocations are held in synchronized
//! capability registries, so numeric handles can be closed safely while calls
//! from other threads are in flight.

#![allow(unsafe_code)]
// The C header is the canonical API documentation; Rust-visible names here are
// implementation details required only so exported signatures are well formed.
#![allow(missing_docs)]
// Exported C functions must remain callable as ordinary C functions. They
// validate every raw pointer before a narrowly scoped dereference.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![cfg_attr(test, allow(clippy::borrow_as_ptr, clippy::cast_ptr_alignment))]

use aster_mesh::blob::{
    BlobError, BlobId, BlobManifest, BlobMetadata, BlobStoreConfig, FileBlobStore, FinishedBlob,
    MAX_BLOB_CHUNK_SIZE, ReferenceBlobReader, ReferenceBlobService,
};
use aster_mesh::engine::{
    EmissionPolicy, EngineError, Node, NodeConfig, PublishReceipt, PublishRequest, ResolveRequest,
};
use aster_mesh::store::{
    BridgeFilter, PeerSnapshot, SqliteStore, StoreConfig, StoreError, SubscriptionId,
};
use aster_mesh::{
    ApplicationNodeRef, BatchPublicationPolicy, BatchPublishRequest, BatchPublishResult,
    BridgeAuthorizationId, BridgeAuthorizationPolicy, BridgeAuthorizationResult,
    BridgeAuthorizationStatus, BridgeCommitStatus, BridgeEdge, BridgeEnrollment,
    BridgeNarrowingPolicy, BridgeRouteHandle, BridgeRouteResult, BridgeRouteStatus,
    ConflictAnnotation, DEFAULT_SEMANTIC_VERSION, DataClass, Delivery, FinishedBlobBatchItem,
    FinishedBlobBatchRequest, HIGHEST_SUPPORTED_SEMANTIC_VERSION, Item as ApplicationItem,
    PROTOCOL_VERSION, PeerStatus, Priority, ProvisioningBundle, PublishResult, Query,
    REPLICATION_WIRE_VERSION, ReferenceEnvelopeSealer, RekeyRecipient, Scope, ScopeRekeyResult,
    SyncStatus, Topic,
};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::mem::{align_of, size_of};
use std::ops::Deref;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// Current binary interface version.
pub const ABI_VERSION: u32 = 1;
const ID_BYTES: usize = 32;
const DEFAULT_QUERY_LIMIT: usize = 1_024;
const MAX_INPUT_BYTES: usize = 1024 * 1024 * 1024;
const MAX_REKEY_REGISTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REKEY_RECIPIENTS: usize = 128;
const MAX_REKEY_TOPICS_PER_RECIPIENT: usize = 128;
const MAX_BRIDGE_TOPICS: usize = 128;
const MAX_BRIDGE_PAGE: usize = 4_096;
const BRIDGE_PRIORITY_MASK: u8 = 0x0f;
const MIN_BATCH_ITEMS: usize = 2;
const MAX_BATCH_ITEMS: usize = 64;

const BATCH_RETAINED_DUAL: u32 = 0;
const BATCH_ONLY: u32 = 1;

const REKEY_ROUTE_ONLY: u32 = 1;
const REKEY_READ_TOPICS: u32 = 2;

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

impl From<EngineError> for FfiError {
    fn from(error: EngineError) -> Self {
        let status = match &error {
            EngineError::Store(StoreError::NotFound(_)) => STATUS_NOT_FOUND,
            EngineError::Store(StoreError::QuotaExceeded) => STATUS_QUOTA_EXCEEDED,
            EngineError::Store(StoreError::Zeroized) => STATUS_ZEROIZED,
            EngineError::Store(_) => STATUS_STORAGE_ERROR,
            EngineError::Envelope(_)
            | EngineError::Provisioning(_)
            | EngineError::Revoked(_)
            | EngineError::StaleKeyEpoch { .. }
            | EngineError::Expired
            | EngineError::Unauthorized(_) => STATUS_SECURITY_ERROR,
            EngineError::Invalid(_) | EngineError::Merge(_) => STATUS_INVALID_ARGUMENT,
            EngineError::StaleConflict => STATUS_STALE_CONFLICT,
        };
        Self::new(status, error.to_string())
    }
}

impl From<BlobError> for FfiError {
    fn from(error: BlobError) -> Self {
        let status = match &error {
            BlobError::AuthenticationFailed => STATUS_SECURITY_ERROR,
            BlobError::Io(_) | BlobError::Store(_) | BlobError::MissingChunk => {
                STATUS_STORAGE_ERROR
            }
            BlobError::InvalidChunkSize
            | BlobError::InvalidMetadata
            | BlobError::InvalidManifest
            | BlobError::InvalidChunkIndex
            | BlobError::LengthOverflow
            | BlobError::SourceChanged
            | BlobError::WorkLimitZero => STATUS_INVALID_ARGUMENT,
        };
        Self::new(status, error.to_string())
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}
static FALLBACK_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    LAST_ERROR.with(|slot| slot.borrow_mut().clone_from(&message));
    if let Ok(mut fallback) = FALLBACK_ERROR
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
    {
        *fallback = message;
    }
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
#[derive(Clone, Copy)]
struct AbiHeader {
    abi_version: u32,
    struct_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterNode {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterQuery {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterConflicts {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterDeliveries {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterPeers {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBatchResult {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBlobWriter {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBlobReader {
    value: u64,
}

/// Process-local, move-only bridge enrollment capability.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBridgeEnrollment {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBridgeAuthorizations {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterBridgeRoutes {
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBytes {
    data: *const u8,
    len: usize,
}

impl Default for AsterBytes {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterOwnedBuffer {
    abi_version: u32,
    struct_size: u32,
    data: *mut u8,
    len: usize,
}

impl Default for AsterOwnedBuffer {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterNodeOptions {
    abi_version: u32,
    struct_size: u32,
    store_path: AsterBytes,
    provisioning_bundle: AsterBytes,
    max_items: u64,
    max_bytes: u64,
    tombstone_retention_ms: u64,
    superseded_retention_ms: u64,
    priority_cap: u32,
    emission_threshold: u32,
}

impl Default for AsterNodeOptions {
    fn default() -> Self {
        let config = StoreConfig::default();
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            store_path: AsterBytes::default(),
            provisioning_bundle: AsterBytes::default(),
            max_items: config.max_items,
            max_bytes: config.max_bytes,
            tombstone_retention_ms: config.tombstone_retention_ms,
            superseded_retention_ms: config.superseded_retention_ms,
            priority_cap: u32::from(Priority::Flash as u8),
            emission_threshold: u32::from(Priority::Routine as u8),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPublishRequest {
    abi_version: u32,
    struct_size: u32,
    data_class: u32,
    priority: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    logical_key: AsterBytes,
    payload: AsterBytes,
    ttl_ms: u64,
    has_ttl: u8,
    tombstone: u8,
    reserved: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPublishReceipt {
    abi_version: u32,
    struct_size: u32,
    item_id: [u8; ID_BYTES],
    publisher: [u8; ID_BYTES],
    causal_counter: u64,
    event_sequence: u64,
    has_event_sequence: u8,
    effective_priority: u8,
    reserved: [u8; 6],
}

/// One explicit atomic publication request. Every pointed-to item and its
/// borrowed buffers remain valid only until `aster_node_publish_batch` returns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPublishBatchRequest {
    abi_version: u32,
    struct_size: u32,
    items: *const AsterPublishRequest,
    item_count: usize,
    policy: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterItemId {
    abi_version: u32,
    struct_size: u32,
    bytes: [u8; ID_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobPublishOptions {
    abi_version: u32,
    struct_size: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    media_type: AsterBytes,
    schema_id: AsterBytes,
    ttl_ms: u64,
    chunk_size: u32,
    priority: u32,
    has_ttl: u8,
    reserved: [u8; 7],
}

impl Default for AsterBlobPublishOptions {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            media_type: AsterBytes::default(),
            schema_id: AsterBytes::default(),
            ttl_ms: 0,
            chunk_size: MAX_BLOB_CHUNK_SIZE,
            priority: u32::from(Priority::Routine as u8),
            has_ttl: 0,
            reserved: [0; 7],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobFinish {
    abi_version: u32,
    struct_size: u32,
    blob_id: [u8; ID_BYTES],
    receipt: AsterPublishReceipt,
}

/// Finalize and atomically publish 2-64 existing Blob writers. The caller
/// retains each writer capability, and failed publication remains retryable.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobPublishBatchRequest {
    abi_version: u32,
    struct_size: u32,
    writers: *const AsterBlobWriter,
    writer_count: usize,
    policy: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobReadRequest {
    abi_version: u32,
    struct_size: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    blob_id: [u8; ID_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterQueryRequest {
    abi_version: u32,
    struct_size: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    logical_key: AsterBytes,
    data_class: u32,
    include_descendant_scopes: u8,
    include_recoverable_versions: u8,
    include_tombstones: u8,
    reserved: u8,
    limit: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterItem {
    abi_version: u32,
    struct_size: u32,
    item_id: [u8; ID_BYTES],
    publisher: [u8; ID_BYTES],
    data_class: u32,
    priority: u32,
    causal_counter: u64,
    event_sequence: u64,
    has_event_sequence: u8,
    tombstone: u8,
    reserved: [u8; 6],
    topic: AsterOwnedBuffer,
    /// Compatibility alias for `current_scope`.
    scope: AsterOwnedBuffer,
    origin_scope: AsterOwnedBuffer,
    current_scope: AsterOwnedBuffer,
    logical_key: AsterOwnedBuffer,
    payload: AsterOwnedBuffer,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterSubscribeRequest {
    abi_version: u32,
    struct_size: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    data_class: u32,
    include_descendant_scopes: u8,
    reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPollRequest {
    abi_version: u32,
    struct_size: u32,
    subscription: u64,
    limit: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterDelivery {
    abi_version: u32,
    struct_size: u32,
    subscription: u64,
    attempt: u64,
    item: AsterItem,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterAckRequest {
    abi_version: u32,
    struct_size: u32,
    subscription: u64,
    item_id: [u8; ID_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterConflict {
    abi_version: u32,
    struct_size: u32,
    logical_key: AsterOwnedBuffer,
    sibling_ids: AsterOwnedBuffer,
    merge_policy: AsterOwnedBuffer,
    has_merge_policy: u8,
    reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterResolveRequest {
    abi_version: u32,
    struct_size: u32,
    topic: AsterBytes,
    scope: AsterBytes,
    logical_key: AsterBytes,
    expected_sibling_ids: AsterBytes,
    payload: AsterBytes,
    priority: u32,
    reserved0: u32,
    ttl_ms: u64,
    has_ttl: u8,
    reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPeerSnapshot {
    abi_version: u32,
    struct_size: u32,
    peer: [u8; ID_BYTES],
    peer_state: u32,
    sync_state: u32,
    last_change_ms: u64,
    has_last_change: u8,
    has_detail: u8,
    reserved: [u8; 6],
    detail: AsterOwnedBuffer,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPeerRequest {
    abi_version: u32,
    struct_size: u32,
    peer: [u8; ID_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeFilter {
    abi_version: u32,
    struct_size: u32,
    from_scope: AsterBytes,
    to_scope: AsterBytes,
    topic: AsterBytes,
    minimum_priority: u32,
    reserved: u32,
}

/// Bridge-node enrollment request for one exact directed pair of route epochs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeEnrollmentRequest {
    abi_version: u32,
    struct_size: u32,
    source_scope: AsterBytes,
    target_scope: AsterBytes,
    source_route_epoch: u64,
    target_route_epoch: u64,
    reserved: [u8; 8],
}

/// Authority policy. Topics are borrowed only for the duration of enable.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeEnablePolicy {
    abi_version: u32,
    struct_size: u32,
    topics: *const AsterBytes,
    topic_count: usize,
    allowed_priority_mask: u8,
    max_total_hops: u8,
    reserved: [u8; 6],
}

/// Exact authority disable request; no wildcard or descendant matching exists.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeDisableRequest {
    abi_version: u32,
    struct_size: u32,
    bridge_node: [u8; ID_BYTES],
    source_scope: AsterBytes,
    target_scope: AsterBytes,
    reserved: [u8; 8],
}

/// First-hop request. An empty topic array means the full authority topic set.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeItemRequest {
    abi_version: u32,
    struct_size: u32,
    source_item: [u8; ID_BYTES],
    authorization_id: [u8; ID_BYTES],
    topics: *const AsterBytes,
    topic_count: usize,
    allowed_priority_mask: u8,
    reserved: [u8; 7],
}

/// Nested-hop request selected only by an opaque durable route handle.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeExtendRequest {
    abi_version: u32,
    struct_size: u32,
    route_handle: [u8; ID_BYTES],
    authorization_id: [u8; ID_BYTES],
    topics: *const AsterBytes,
    topic_count: usize,
    allowed_priority_mask: u8,
    reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeAuthorizationResult {
    abi_version: u32,
    struct_size: u32,
    id: [u8; ID_BYTES],
    generation: u64,
    control_sequence: u64,
    enabled: u8,
    reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeRouteResult {
    abi_version: u32,
    struct_size: u32,
    handle: [u8; ID_BYTES],
    source_item: [u8; ID_BYTES],
    current_route_epoch: u64,
    commit_status: u32,
    hop_count: u8,
    reserved: [u8; 3],
    current_scope: AsterOwnedBuffer,
}

/// Exact 32-byte status selector. Reserved bytes must remain zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeStatusRequest {
    abi_version: u32,
    struct_size: u32,
    id: [u8; ID_BYTES],
    reserved: [u8; 8],
}

/// Stable exclusive cursor for bounded authorization/route pagination.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgePageRequest {
    abi_version: u32,
    struct_size: u32,
    after: [u8; ID_BYTES],
    limit: u64,
    has_after: u8,
    reserved: [u8; 7],
}

/// Provider-authenticated durable authorization metadata.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeAuthorizationStatus {
    abi_version: u32,
    struct_size: u32,
    id: [u8; ID_BYTES],
    authority: [u8; ID_BYTES],
    bridge_node: [u8; ID_BYTES],
    generation: u64,
    control_sequence: u64,
    source_route_epoch: u64,
    target_route_epoch: u64,
    topic_count: u64,
    allowed_priority_mask: u8,
    max_total_hops: u8,
    applied: u8,
    current: u8,
    enabled: u8,
    usable: u8,
    has_source_route_epoch: u8,
    has_target_route_epoch: u8,
    has_max_total_hops: u8,
    reserved: [u8; 7],
    source_scope: AsterOwnedBuffer,
    target_scope: AsterOwnedBuffer,
    /// Repeated `u16` big-endian byte length followed by UTF-8 topic bytes.
    topics: AsterOwnedBuffer,
}

/// Provider-authenticated durable route metadata.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBridgeRouteStatus {
    abi_version: u32,
    struct_size: u32,
    handle: [u8; ID_BYTES],
    source_item: [u8; ID_BYTES],
    origin_route_epoch: u64,
    current_route_epoch: u64,
    priority: u32,
    hop_count: u8,
    active: u8,
    live: u8,
    reserved: u8,
    origin_scope: AsterOwnedBuffer,
    current_scope: AsterOwnedBuffer,
    topic: AsterOwnedBuffer,
}

/// One caller-selected recipient. Every pointed-to topic and the array itself
/// are borrowed only until `aster_node_rekey_scope` returns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRekeyRecipient {
    abi_version: u32,
    struct_size: u32,
    node_id: [u8; ID_BYTES],
    access: u32,
    reserved: u32,
    topics: *const AsterBytes,
    topic_count: usize,
}

/// Authority-only fresh scope rekey input. Registry bytes remain opaque to the
/// ABI and all input memory is borrowed for this call only.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRekeyRequest {
    abi_version: u32,
    struct_size: u32,
    signed_public_registry: AsterBytes,
    scope: AsterBytes,
    minimum_registry_generation: u64,
    new_epoch: u64,
    recipients: *const AsterRekeyRecipient,
    recipient_count: usize,
}

/// Non-secret durable receipt for an authority scope rekey.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRekeyReceipt {
    abi_version: u32,
    struct_size: u32,
    epoch: u64,
    registry_generation: u64,
    recipient_count: u64,
    control_sequence: u64,
}

#[allow(clippy::cast_possible_truncation)]
const fn struct_size<T>() -> u32 {
    size_of::<T>() as u32
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

fn write_versioned_output<T>(pointer: *mut T, value: T, name: &str) -> Result<(), FfiError> {
    let _ = versioned(pointer.cast_const(), name)?;
    // SAFETY: versioned checked ABI, size, null, and alignment. The caller
    // grants exclusive access to the output for this call.
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

fn rekey_recipients_from_ffi(request: &AsterRekeyRequest) -> Result<Vec<RekeyRecipient>, FfiError> {
    if request.recipient_count == 0 {
        return Err(FfiError::invalid("rekey recipients must not be empty"));
    }
    let recipients = input_array(
        request.recipients,
        request.recipient_count,
        MAX_REKEY_RECIPIENTS,
        "rekey.recipients",
    )?;
    let mut parsed = Vec::with_capacity(recipients.len());
    for (recipient_index, recipient) in recipients.iter().enumerate() {
        let name = format!("rekey.recipients[{recipient_index}]");
        let recipient = versioned(ptr::from_ref(recipient), &name)?;
        if recipient.reserved != 0 {
            return Err(FfiError::invalid(format!("{name}.reserved must be zero")));
        }
        match recipient.access {
            REKEY_ROUTE_ONLY => {
                if recipient.topic_count != 0 {
                    return Err(FfiError::invalid(format!(
                        "{name} route-only access must not include topics"
                    )));
                }
                parsed.push(RekeyRecipient::route_only(recipient.node_id));
            }
            REKEY_READ_TOPICS => {
                if recipient.topic_count == 0 {
                    return Err(FfiError::invalid(format!(
                        "{name} read-topics access requires at least one topic"
                    )));
                }
                let topics = input_array(
                    recipient.topics,
                    recipient.topic_count,
                    MAX_REKEY_TOPICS_PER_RECIPIENT,
                    &format!("{name}.topics"),
                )?;
                let topics = topics
                    .iter()
                    .enumerate()
                    .map(|(topic_index, topic)| {
                        input_topic(*topic, &format!("{name}.topics[{topic_index}]"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                parsed.push(RekeyRecipient::read_topics(recipient.node_id, topics)?);
            }
            _ => {
                return Err(FfiError::invalid(format!(
                    "{name}.access is not a known rekey access mode"
                )));
            }
        }
    }
    Ok(parsed)
}

fn optional_topic(value: AsterBytes) -> Result<Option<Topic>, FfiError> {
    if value.len == 0 {
        Ok(None)
    } else {
        input_topic(value, "query.topic").map(Some)
    }
}

fn optional_scope(value: AsterBytes) -> Result<Option<Scope>, FfiError> {
    if value.len == 0 {
        Ok(None)
    } else {
        input_scope(value, "query.scope").map(Some)
    }
}

fn data_class(value: u32, allow_any: bool) -> Result<Option<DataClass>, FfiError> {
    match value {
        0 => Ok(Some(DataClass::State)),
        1 => Ok(Some(DataClass::Event)),
        2 => Ok(Some(DataClass::Record)),
        3 => Ok(Some(DataClass::Blob)),
        u32::MAX if allow_any => Ok(None),
        _ => Err(FfiError::invalid("unknown data class")),
    }
}

fn required_data_class(value: u32) -> Result<DataClass, FfiError> {
    data_class(value, false)?
        .ok_or_else(|| FfiError::internal("specific data class decoded as wildcard"))
}

fn priority(value: u32, allow_silent: bool) -> Result<Option<Priority>, FfiError> {
    match value {
        0 => Ok(Some(Priority::Routine)),
        1 => Ok(Some(Priority::Priority)),
        2 => Ok(Some(Priority::Immediate)),
        3 => Ok(Some(Priority::Flash)),
        4 if allow_silent => Ok(None),
        _ => Err(FfiError::invalid("unknown priority or emission threshold")),
    }
}

fn required_priority(value: u32) -> Result<Priority, FfiError> {
    priority(value, false)?
        .ok_or_else(|| FfiError::internal("message priority decoded as receive-only"))
}

fn bridge_priorities(mask: u8, name: &str) -> Result<Vec<Priority>, FfiError> {
    if mask == 0 || mask & !BRIDGE_PRIORITY_MASK != 0 {
        return Err(FfiError::invalid(format!(
            "{name} must explicitly set one or more priority bits 0 through 3"
        )));
    }
    let mut values = Vec::with_capacity(4);
    for wire in 0u8..4 {
        if mask & (1u8 << wire) != 0 {
            values.push(required_priority(u32::from(wire))?);
        }
    }
    Ok(values)
}

fn bridge_priority_mask(values: &[Priority]) -> u8 {
    values
        .iter()
        .fold(0, |mask, priority| mask | (1u8 << (*priority as u8)))
}

fn bridge_topics(
    pointer: *const AsterBytes,
    count: usize,
    allow_empty: bool,
    name: &str,
) -> Result<Vec<Topic>, FfiError> {
    if !allow_empty && count == 0 {
        return Err(FfiError::invalid(format!(
            "{name} must contain at least one topic"
        )));
    }
    input_array(pointer, count, MAX_BRIDGE_TOPICS, name)?
        .iter()
        .enumerate()
        .map(|(index, topic)| input_topic(*topic, &format!("{name}[{index}]")))
        .collect()
}

fn bridge_narrowing(
    topics: *const AsterBytes,
    topic_count: usize,
    allowed_priority_mask: u8,
    name: &str,
) -> Result<BridgeNarrowingPolicy, FfiError> {
    BridgeNarrowingPolicy::new(
        bridge_topics(topics, topic_count, true, &format!("{name}.topics"))?,
        bridge_priorities(
            allowed_priority_mask,
            &format!("{name}.allowed_priority_mask"),
        )?,
    )
    .map_err(Into::into)
}

fn boolean(value: u8, name: &str) -> Result<bool, FfiError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FfiError::invalid(format!("{name} must be zero or one"))),
    }
}

fn limit(value: u64, default: usize, name: &str) -> Result<usize, FfiError> {
    if value == 0 {
        return Ok(default);
    }
    usize::try_from(value).map_err(|_| FfiError::invalid(format!("{name} does not fit size_t")))
}

fn bridge_page(
    request: &AsterBridgePageRequest,
    name: &str,
) -> Result<(Option<[u8; ID_BYTES]>, usize), FfiError> {
    if request.reserved != [0; 7] {
        return Err(FfiError::invalid(format!("{name}.reserved must be zero")));
    }
    let has_after = boolean(request.has_after, &format!("{name}.has_after"))?;
    if !has_after && request.after != [0; ID_BYTES] {
        return Err(FfiError::invalid(format!(
            "{name}.after must be zero when has_after is zero"
        )));
    }
    let page_limit = limit(request.limit, 64, &format!("{name}.limit"))?;
    if page_limit == 0 || page_limit > MAX_BRIDGE_PAGE {
        return Err(FfiError::invalid(format!(
            "{name}.limit must be between 1 and {MAX_BRIDGE_PAGE}"
        )));
    }
    Ok((has_after.then_some(request.after), page_limit))
}

fn publish_request_from_ffi(
    request: &AsterPublishRequest,
    name: &str,
) -> Result<PublishRequest, FfiError> {
    if request.reserved != [0; 6] {
        return Err(FfiError::invalid(format!("{name}.reserved must be zero")));
    }
    let class = required_data_class(request.data_class)?;
    if class == DataClass::Blob {
        return Err(FfiError::invalid(
            "Blob data must be published through the streaming Blob writer",
        ));
    }
    Ok(PublishRequest {
        class,
        topic: input_topic(request.topic, &format!("{name}.topic"))?,
        scope: input_scope(request.scope, &format!("{name}.scope"))?,
        priority: required_priority(request.priority)?,
        ttl_ms: boolean(request.has_ttl, &format!("{name}.has_ttl"))?.then_some(request.ttl_ms),
        logical_key: input_bytes(request.logical_key, &format!("{name}.logical_key"))?.to_vec(),
        payload: input_bytes(request.payload, &format!("{name}.payload"))?.to_vec(),
        tombstone: boolean(request.tombstone, &format!("{name}.tombstone"))?,
    })
}

fn batch_policy(value: u32) -> Result<BatchPublicationPolicy, FfiError> {
    match value {
        BATCH_RETAINED_DUAL => Ok(BatchPublicationPolicy::RetainedDual),
        BATCH_ONLY => Ok(BatchPublicationPolicy::BatchOnly),
        _ => Err(FfiError::invalid("batch.policy is unknown")),
    }
}

fn query_from_ffi(request: &AsterQueryRequest) -> Result<Query, FfiError> {
    if request.reserved != 0 {
        return Err(FfiError::invalid("query.reserved must be zero"));
    }
    Ok(Query {
        topic: optional_topic(request.topic)?,
        scope: optional_scope(request.scope)?,
        include_descendant_scopes: boolean(
            request.include_descendant_scopes,
            "query.include_descendant_scopes",
        )?,
        class: data_class(request.data_class, true)?,
        logical_key: if request.logical_key.len == 0 {
            None
        } else {
            Some(input_bytes(request.logical_key, "query.logical_key")?.to_vec())
        },
        include_recoverable_versions: boolean(
            request.include_recoverable_versions,
            "query.include_recoverable_versions",
        )?,
        include_tombstones: boolean(request.include_tombstones, "query.include_tombstones")?,
        limit: limit(request.limit, DEFAULT_QUERY_LIMIT, "query.limit")?,
    })
}

type CoreNode = Node<SqliteStore, ReferenceEnvelopeSealer>;

struct NodeCell {
    node: Mutex<Option<CoreNode>>,
    blob_root: PathBuf,
    blob_config: BlobStoreConfig,
    blob_staging_quota: Arc<BlobStagingQuota>,
    ephemeral_blob_root: bool,
}

struct BlobStagingQuota {
    used_bytes: AtomicU64,
    max_bytes: u64,
}

impl BlobStagingQuota {
    fn reserve(&self, bytes: u64) -> Result<(), FfiError> {
        self.used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            })
            .map(|_| ())
            .map_err(|_| {
                FfiError::new(
                    STATUS_QUOTA_EXCEEDED,
                    "concurrent Blob staging exceeds the configured local byte quota",
                )
            })
    }

    fn release(&self, bytes: u64) {
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct BlobWriterCell {
    owner: u64,
    state: Mutex<Option<BlobWriterState>>,
}

struct BlobWriterState {
    node: AsterNode,
    topic: Topic,
    scope: Scope,
    priority: Priority,
    ttl_ms: Option<u64>,
    chunk_size: u32,
    metadata: BlobMetadata,
    source: Option<File>,
    source_path: PathBuf,
    digest_scratch: Option<File>,
    digest_path: PathBuf,
    source_len: u64,
    max_source_bytes: u64,
    staging_quota: Arc<BlobStagingQuota>,
    reserved_staging_bytes: u64,
    service: Option<ReferenceBlobService>,
    manifest: Option<BlobManifest>,
    finished: Option<AsterBlobFinish>,
}

impl BlobWriterState {
    fn cleanup_staging(&mut self) {
        drop(self.source.take());
        drop(self.digest_scratch.take());
        let _ = fs::remove_file(&self.source_path);
        let _ = fs::remove_file(&self.digest_path);
        if let Some(directory) = self.source_path.parent() {
            let _ = fs::remove_dir(directory);
        }
        self.staging_quota.release(self.reserved_staging_bytes);
        self.reserved_staging_bytes = 0;
    }

    fn finalize_local(&mut self) -> Result<FinishedBlob, FfiError> {
        if self.manifest.is_none() {
            let source = self
                .source
                .as_mut()
                .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer source is closed"))?;
            source
                .sync_all()
                .map_err(|error| FfiError::from(BlobError::Io(error)))?;
            source
                .seek(SeekFrom::Start(0))
                .map_err(|error| FfiError::from(BlobError::Io(error)))?;
            let digest_scratch = self.digest_scratch.as_mut().ok_or_else(|| {
                FfiError::new(STATUS_CLOSED, "Blob writer digest scratch is closed")
            })?;
            digest_scratch
                .set_len(0)
                .map_err(|error| FfiError::from(BlobError::Io(error)))?;
            digest_scratch
                .seek(SeekFrom::Start(0))
                .map_err(|error| FfiError::from(BlobError::Io(error)))?;
            let service = self
                .service
                .as_mut()
                .ok_or_else(|| FfiError::internal("Blob service was not initialized"))?;
            let manifest = service
                .prepare(
                    source,
                    digest_scratch,
                    self.chunk_size,
                    self.metadata.clone(),
                )
                .map_err(FfiError::from)?;
            self.manifest = Some(manifest);
        }

        let manifest = self
            .manifest
            .clone()
            .ok_or_else(|| FfiError::internal("Blob manifest was not prepared"))?;
        let source = self
            .source
            .as_mut()
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer source is closed"))?;
        let service = self
            .service
            .as_mut()
            .ok_or_else(|| FfiError::internal("Blob service was not initialized"))?;
        let progress = service
            .encrypt_some(source, &manifest, u64::MAX)
            .map_err(FfiError::from)?;
        if !progress.complete {
            return Err(FfiError::internal(
                "Blob encryption stopped before every chunk was durable",
            ));
        }
        let finished = service.finish(manifest.id()).map_err(FfiError::from)?;
        if finished.id() != manifest.id() {
            return Err(FfiError::internal(
                "Blob finalization returned a different identifier",
            ));
        }
        Ok(finished)
    }
}

impl Drop for BlobWriterState {
    fn drop(&mut self) {
        self.cleanup_staging();
    }
}

struct BlobReaderCell {
    owner: u64,
    reader: Mutex<Option<ReferenceBlobReader>>,
}

#[derive(Default)]
struct BlobRegistry {
    writers: HashMap<u64, Arc<BlobWriterCell>>,
    readers: HashMap<u64, Arc<BlobReaderCell>>,
}

struct BridgeEnrollmentEntry {
    owner: u64,
    value: BridgeEnrollment,
}

#[derive(Default)]
struct BridgeEnrollmentRegistry {
    values: HashMap<u64, BridgeEnrollmentEntry>,
}

#[derive(Default)]
struct ResultRegistry {
    batch_results: HashMap<u64, ResultEntry<BatchPublishResult>>,
    queries: HashMap<u64, ResultEntry<QuerySnapshot>>,
    conflicts: HashMap<u64, ResultEntry<ConflictSnapshot>>,
    deliveries: HashMap<u64, ResultEntry<DeliverySnapshot>>,
    peers: HashMap<u64, ResultEntry<Vec<PeerSnapshot>>>,
    bridge_authorizations: HashMap<u64, ResultEntry<BridgeAuthorizationSnapshot>>,
    bridge_routes: HashMap<u64, ResultEntry<BridgeRouteSnapshot>>,
}

struct ResultEntry<T> {
    owner: u64,
    value: Arc<T>,
}

struct QuerySnapshot(Vec<ApplicationItem>);

impl Deref for QuerySnapshot {
    type Target = [ApplicationItem];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for QuerySnapshot {
    fn drop(&mut self) {
        for item in &mut self.0 {
            item.logical_key.fill(0);
            item.payload.fill(0);
        }
    }
}

struct ConflictSnapshot(Vec<ConflictAnnotation>);

impl Deref for ConflictSnapshot {
    type Target = [ConflictAnnotation];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ConflictSnapshot {
    fn drop(&mut self) {
        for conflict in &mut self.0 {
            conflict.logical_key.fill(0);
        }
    }
}

struct DeliverySnapshot(Vec<Delivery>);

impl Deref for DeliverySnapshot {
    type Target = [Delivery];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for DeliverySnapshot {
    fn drop(&mut self) {
        for delivery in &mut self.0 {
            delivery.item.logical_key.fill(0);
            delivery.item.payload.fill(0);
        }
    }
}

struct BridgeAuthorizationSnapshot(Vec<BridgeAuthorizationStatus>);

impl Deref for BridgeAuthorizationSnapshot {
    type Target = [BridgeAuthorizationStatus];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct BridgeRouteSnapshot(Vec<BridgeRouteStatus>);

impl Deref for BridgeRouteSnapshot {
    type Target = [BridgeRouteStatus];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static NODES: OnceLock<Mutex<HashMap<u64, Arc<NodeCell>>>> = OnceLock::new();
static RESULTS: OnceLock<Mutex<ResultRegistry>> = OnceLock::new();
static BLOBS: OnceLock<Mutex<BlobRegistry>> = OnceLock::new();
static BRIDGE_ENROLLMENTS: OnceLock<Mutex<BridgeEnrollmentRegistry>> = OnceLock::new();
static ALLOCATIONS: OnceLock<Mutex<HashMap<usize, Box<[u8]>>>> = OnceLock::new();

fn nodes() -> &'static Mutex<HashMap<u64, Arc<NodeCell>>> {
    NODES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn results() -> &'static Mutex<ResultRegistry> {
    RESULTS.get_or_init(|| Mutex::new(ResultRegistry::default()))
}

fn blobs() -> &'static Mutex<BlobRegistry> {
    BLOBS.get_or_init(|| Mutex::new(BlobRegistry::default()))
}

fn bridge_enrollments() -> &'static Mutex<BridgeEnrollmentRegistry> {
    BRIDGE_ENROLLMENTS.get_or_init(|| Mutex::new(BridgeEnrollmentRegistry::default()))
}

fn purge_bridge_enrollments(owner: u64) -> Result<(), FfiError> {
    lock(bridge_enrollments(), "bridge enrollment registry")?
        .values
        .retain(|_, entry| entry.owner != owner);
    Ok(())
}

fn purge_blob_handles(owner: u64) -> Result<(), FfiError> {
    let (writers, readers) = {
        let mut registry = lock(blobs(), "Blob registry")?;
        let writer_handles: Vec<_> = registry
            .writers
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        let reader_handles: Vec<_> = registry
            .readers
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        let writers = writer_handles
            .into_iter()
            .filter_map(|handle| registry.writers.remove(&handle))
            .collect::<Vec<_>>();
        let readers = reader_handles
            .into_iter()
            .filter_map(|handle| registry.readers.remove(&handle))
            .collect::<Vec<_>>();
        (writers, readers)
    };
    // Waiting on each handle lock ensures close/zeroize cannot return while a Blob operation still
    // owns staged plaintext, a historical content grant, or an authenticated reader buffer.
    for writer in writers {
        let mut guard = lock(&writer.state, "Blob writer")?;
        drop(guard.take());
    }
    for reader in readers {
        let mut guard = lock(&reader.reader, "Blob reader")?;
        drop(guard.take());
    }
    Ok(())
}

fn purge_results(owner: u64) -> Result<(), FfiError> {
    let mut registry = lock(results(), "result registry")?;
    registry
        .batch_results
        .retain(|_, entry| entry.owner != owner);
    registry.queries.retain(|_, entry| entry.owner != owner);
    registry.conflicts.retain(|_, entry| entry.owner != owner);
    registry.deliveries.retain(|_, entry| entry.owner != owner);
    registry.peers.retain(|_, entry| entry.owner != owner);
    registry
        .bridge_authorizations
        .retain(|_, entry| entry.owner != owner);
    registry
        .bridge_routes
        .retain(|_, entry| entry.owner != owner);
    Ok(())
}

fn allocations() -> &'static Mutex<HashMap<usize, Box<[u8]>>> {
    ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, FfiError> {
    mutex
        .lock()
        .map_err(|_| FfiError::internal(format!("{name} lock is poisoned")))
}

fn new_handle() -> Result<u64, FfiError> {
    NEXT_HANDLE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| FfiError::internal("process-local handle space exhausted"))
}

fn node_cell(handle: AsterNode) -> Result<Arc<NodeCell>, FfiError> {
    if handle.value == 0 {
        return Err(FfiError::new(STATUS_CLOSED, "node handle is closed"));
    }
    lock(nodes(), "node registry")?
        .get(&handle.value)
        .cloned()
        .ok_or_else(|| FfiError::new(STATUS_CLOSED, "node handle is unknown or closed"))
}

fn blob_writer_cell(handle: AsterBlobWriter) -> Result<Arc<BlobWriterCell>, FfiError> {
    if handle.value == 0 {
        return Err(FfiError::new(STATUS_CLOSED, "Blob writer handle is closed"));
    }
    lock(blobs(), "Blob registry")?
        .writers
        .get(&handle.value)
        .cloned()
        .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer handle is unknown or closed"))
}

fn blob_reader_cell(handle: AsterBlobReader) -> Result<Arc<BlobReaderCell>, FfiError> {
    if handle.value == 0 {
        return Err(FfiError::new(STATUS_CLOSED, "Blob reader handle is closed"));
    }
    lock(blobs(), "Blob registry")?
        .readers
        .get(&handle.value)
        .cloned()
        .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob reader handle is unknown or closed"))
}

fn register_blob_writer(
    owner: AsterNode,
    handle: u64,
    cell: Arc<BlobWriterCell>,
) -> Result<(), FfiError> {
    let node_registry = lock(nodes(), "node registry")?;
    if !node_registry.contains_key(&owner.value) {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "node closed while the Blob writer was opening",
        ));
    }
    lock(blobs(), "Blob registry")?.writers.insert(handle, cell);
    drop(node_registry);
    Ok(())
}

fn register_blob_reader(
    owner: AsterNode,
    handle: u64,
    cell: Arc<BlobReaderCell>,
) -> Result<(), FfiError> {
    let node_registry = lock(nodes(), "node registry")?;
    if !node_registry.contains_key(&owner.value) {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "node closed while the Blob reader was opening",
        ));
    }
    lock(blobs(), "Blob registry")?.readers.insert(handle, cell);
    drop(node_registry);
    Ok(())
}

fn register_bridge_enrollment(
    owner: AsterNode,
    handle: u64,
    value: BridgeEnrollment,
) -> Result<(), FfiError> {
    let node_registry = lock(nodes(), "node registry")?;
    if !node_registry.contains_key(&owner.value) {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "node closed while the bridge enrollment was opening",
        ));
    }
    lock(bridge_enrollments(), "bridge enrollment registry")?
        .values
        .insert(
            handle,
            BridgeEnrollmentEntry {
                owner: owner.value,
                value,
            },
        );
    drop(node_registry);
    Ok(())
}

fn register_bridge_authorization_snapshot(
    owner: AsterNode,
    handle: u64,
    value: Vec<BridgeAuthorizationStatus>,
) -> Result<(), FfiError> {
    let node_registry = lock(nodes(), "node registry")?;
    if !node_registry.contains_key(&owner.value) {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "node closed while the bridge authorization page was opening",
        ));
    }
    lock(results(), "result registry")?
        .bridge_authorizations
        .insert(
            handle,
            ResultEntry {
                owner: owner.value,
                value: Arc::new(BridgeAuthorizationSnapshot(value)),
            },
        );
    drop(node_registry);
    Ok(())
}

fn register_bridge_route_snapshot(
    owner: AsterNode,
    handle: u64,
    value: Vec<BridgeRouteStatus>,
) -> Result<(), FfiError> {
    let node_registry = lock(nodes(), "node registry")?;
    if !node_registry.contains_key(&owner.value) {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "node closed while the bridge route page was opening",
        ));
    }
    lock(results(), "result registry")?.bridge_routes.insert(
        handle,
        ResultEntry {
            owner: owner.value,
            value: Arc::new(BridgeRouteSnapshot(value)),
        },
    );
    drop(node_registry);
    Ok(())
}

fn consume_bridge_enrollment(
    enrollment: *mut AsterBridgeEnrollment,
) -> Result<BridgeEnrollment, FfiError> {
    let handle = take_handle(enrollment, "bridge enrollment")?;
    if handle.value == 0 {
        return Err(FfiError::new(
            STATUS_CLOSED,
            "bridge enrollment handle is closed",
        ));
    }
    lock(bridge_enrollments(), "bridge enrollment registry")?
        .values
        .remove(&handle.value)
        .map(|entry| entry.value)
        .ok_or_else(|| {
            FfiError::new(
                STATUS_CLOSED,
                "bridge enrollment handle is unknown, closed, or already consumed",
            )
        })
}

fn with_node<T>(
    handle: AsterNode,
    operation: impl FnOnce(&mut CoreNode) -> Result<T, EngineError>,
) -> Result<T, FfiError> {
    let cell = node_cell(handle)?;
    let mut guard = lock(&cell.node, "node")?;
    let node = guard
        .as_mut()
        .ok_or_else(|| FfiError::new(STATUS_CLOSED, "node handle is closed"))?;
    operation(node).map_err(Into::into)
}

fn blob_storage(handle: AsterNode) -> Result<(PathBuf, BlobStoreConfig), FfiError> {
    let cell = node_cell(handle)?;
    Ok((cell.blob_root.clone(), cell.blob_config))
}

fn blob_staging_quota(handle: AsterNode) -> Result<Arc<BlobStagingQuota>, FfiError> {
    Ok(Arc::clone(&node_cell(handle)?.blob_staging_quota))
}

fn blob_root_for(store_path: &str, handle: u64) -> (PathBuf, bool) {
    if store_path == ":memory:" {
        return (
            std::env::temp_dir().join(format!("aster-mesh-ffi-{}-{handle}", std::process::id())),
            true,
        );
    }
    let mut value: OsString = Path::new(store_path).as_os_str().to_owned();
    value.push(".aster-blobs");
    (PathBuf::from(value), false)
}

fn blob_staging_root(blob_root: &Path) -> PathBuf {
    let mut value = blob_root.as_os_str().to_owned();
    value.push(".staging");
    PathBuf::from(value)
}

fn create_staging_file(path: &Path) -> Result<File, FfiError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| FfiError::from(BlobError::Io(error)))
}

fn publish_blob_manifest(
    node: &mut CoreNode,
    topic: &Topic,
    scope: &Scope,
    priority: Priority,
    ttl_ms: Option<u64>,
    finished: &FinishedBlob,
) -> Result<PublishReceipt, EngineError> {
    let id = finished.id();
    let manifest_bytes = finished.manifest_bytes();
    if let Some(receipt) = node.find_authenticated_blob_manifest(
        topic,
        scope,
        id,
        manifest_bytes,
        finished.route_commitment(),
    )? {
        return Ok(receipt);
    }
    node.publish_blob_manifest(
        PublishRequest {
            class: DataClass::Blob,
            topic: topic.clone(),
            scope: scope.clone(),
            priority,
            ttl_ms,
            logical_key: id.as_bytes().to_vec(),
            payload: manifest_bytes.to_vec(),
            tombstone: false,
        },
        finished.route_commitment(),
    )
}

fn remove_blob_root(path: &Path) -> Result<(), FfiError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FfiError::from(BlobError::Io(error))),
    }
}

fn owned_buffer(bytes: &[u8]) -> Result<AsterOwnedBuffer, FfiError> {
    if bytes.is_empty() {
        return Ok(AsterOwnedBuffer::default());
    }
    let mut allocation = bytes.to_vec().into_boxed_slice();
    let data = allocation.as_mut_ptr();
    let address = data as usize;
    let replaced = lock(allocations(), "allocation registry")?.insert(address, allocation);
    if replaced.is_some() {
        return Err(FfiError::internal("allocation address collision"));
    }
    Ok(AsterOwnedBuffer {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterOwnedBuffer>(),
        data,
        len: bytes.len(),
    })
}

fn release_buffer(buffer: &mut AsterOwnedBuffer) -> Result<(), FfiError> {
    if buffer.data.is_null() {
        if buffer.len != 0 {
            return Err(FfiError::invalid(
                "owned buffer has null data and nonzero length",
            ));
        }
        *buffer = AsterOwnedBuffer::default();
        return Ok(());
    }
    let mut allocation = lock(allocations(), "allocation registry")?
        .remove(&(buffer.data as usize))
        .ok_or_else(|| FfiError::invalid("owned buffer was already freed or is foreign"))?;
    allocation.fill(0);
    drop(allocation);
    *buffer = AsterOwnedBuffer::default();
    Ok(())
}

fn require_empty_buffer(buffer: &AsterOwnedBuffer, name: &str) -> Result<(), FfiError> {
    if buffer.data.is_null() && buffer.len == 0 {
        Ok(())
    } else {
        Err(FfiError::invalid(format!(
            "{name} must be an empty owned buffer"
        )))
    }
}

fn release_item_buffers(item: &mut AsterItem) -> Result<(), FfiError> {
    release_buffer(&mut item.topic)?;
    release_buffer(&mut item.scope)?;
    release_buffer(&mut item.origin_scope)?;
    release_buffer(&mut item.current_scope)?;
    release_buffer(&mut item.logical_key)?;
    release_buffer(&mut item.payload)
}

fn receipt_to_ffi(receipt: &PublishReceipt) -> AsterPublishReceipt {
    AsterPublishReceipt {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterPublishReceipt>(),
        item_id: receipt.id,
        publisher: receipt.stamp.dot.publisher,
        causal_counter: receipt.stamp.dot.counter,
        event_sequence: receipt.event_sequence.unwrap_or_default(),
        has_event_sequence: u8::from(receipt.event_sequence.is_some()),
        effective_priority: receipt.effective_priority as u8,
        reserved: [0; 6],
    }
}

fn application_receipt_to_ffi(receipt: &PublishResult) -> AsterPublishReceipt {
    AsterPublishReceipt {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterPublishReceipt>(),
        item_id: receipt.id,
        publisher: receipt.publisher,
        causal_counter: receipt.publisher_counter,
        event_sequence: receipt.event_sequence.unwrap_or_default(),
        has_event_sequence: u8::from(receipt.event_sequence.is_some()),
        effective_priority: receipt.effective_priority as u8,
        reserved: [0; 6],
    }
}

fn rekey_receipt_to_ffi(receipt: &ScopeRekeyResult) -> Result<AsterRekeyReceipt, FfiError> {
    Ok(AsterRekeyReceipt {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterRekeyReceipt>(),
        epoch: receipt.epoch,
        registry_generation: receipt.registry_generation,
        recipient_count: u64::try_from(receipt.recipient_count)
            .map_err(|_| FfiError::internal("rekey recipient count does not fit uint64_t"))?,
        control_sequence: receipt.control_sequence,
    })
}

fn bridge_authorization_result_to_ffi(
    result: &BridgeAuthorizationResult,
) -> AsterBridgeAuthorizationResult {
    AsterBridgeAuthorizationResult {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterBridgeAuthorizationResult>(),
        id: result.id.into_bytes(),
        generation: result.generation,
        control_sequence: result.control_sequence,
        enabled: u8::from(result.enabled),
        reserved: [0; 7],
    }
}

fn bridge_commit_status(status: BridgeCommitStatus) -> u32 {
    match status {
        BridgeCommitStatus::Active => 0,
        BridgeCommitStatus::RetainedAlternate => 1,
        BridgeCommitStatus::DuplicateActive => 2,
        BridgeCommitStatus::DuplicateInactive => 3,
    }
}

fn bridge_route_result_to_ffi(
    result: &BridgeRouteResult,
) -> Result<AsterBridgeRouteResult, FfiError> {
    Ok(AsterBridgeRouteResult {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterBridgeRouteResult>(),
        handle: result.handle.into_bytes(),
        source_item: result.source_item,
        current_route_epoch: result.current_route_epoch,
        commit_status: bridge_commit_status(result.status),
        hop_count: result.hop_count,
        reserved: [0; 3],
        current_scope: owned_buffer(result.current_scope.as_str().as_bytes())?,
    })
}

fn encode_bridge_topics(topics: &[Topic]) -> Result<Vec<u8>, FfiError> {
    let mut encoded = Vec::new();
    for topic in topics {
        let bytes = topic.as_str().as_bytes();
        let length = u16::try_from(bytes.len())
            .map_err(|_| FfiError::internal("authenticated bridge topic exceeds uint16"))?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(bytes);
    }
    Ok(encoded)
}

fn bridge_authorization_status_to_ffi(
    status: &BridgeAuthorizationStatus,
) -> Result<AsterBridgeAuthorizationStatus, FfiError> {
    let topics = encode_bridge_topics(&status.topics)?;
    Ok(AsterBridgeAuthorizationStatus {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterBridgeAuthorizationStatus>(),
        id: status.id.into_bytes(),
        authority: status.authority,
        bridge_node: status.bridge_node,
        generation: status.generation,
        control_sequence: status.control_sequence,
        source_route_epoch: status.source_route_epoch.unwrap_or_default(),
        target_route_epoch: status.target_route_epoch.unwrap_or_default(),
        topic_count: u64::try_from(status.topics.len())
            .map_err(|_| FfiError::internal("bridge topic count does not fit uint64_t"))?,
        allowed_priority_mask: bridge_priority_mask(&status.allowed_priorities),
        max_total_hops: status.max_total_hops.unwrap_or_default(),
        applied: u8::from(status.applied),
        current: u8::from(status.current),
        enabled: u8::from(status.enabled),
        usable: u8::from(status.usable),
        has_source_route_epoch: u8::from(status.source_route_epoch.is_some()),
        has_target_route_epoch: u8::from(status.target_route_epoch.is_some()),
        has_max_total_hops: u8::from(status.max_total_hops.is_some()),
        reserved: [0; 7],
        source_scope: owned_buffer(status.source_scope.as_str().as_bytes())?,
        target_scope: owned_buffer(status.target_scope.as_str().as_bytes())?,
        topics: owned_buffer(&topics)?,
    })
}

fn bridge_route_status_to_ffi(
    status: &BridgeRouteStatus,
) -> Result<AsterBridgeRouteStatus, FfiError> {
    Ok(AsterBridgeRouteStatus {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterBridgeRouteStatus>(),
        handle: status.handle.into_bytes(),
        source_item: status.source_item,
        origin_route_epoch: status.origin_route_epoch,
        current_route_epoch: status.current_route_epoch,
        priority: u32::from(status.priority as u8),
        hop_count: status.hop_count,
        active: u8::from(status.active),
        live: u8::from(status.live),
        reserved: 0,
        origin_scope: owned_buffer(status.origin_scope.as_str().as_bytes())?,
        current_scope: owned_buffer(status.current_scope.as_str().as_bytes())?,
        topic: owned_buffer(status.topic.as_str().as_bytes())?,
    })
}

fn delivery_to_ffi(delivery: &Delivery) -> Result<AsterDelivery, FfiError> {
    Ok(AsterDelivery {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterDelivery>(),
        subscription: delivery.subscription.0,
        attempt: delivery.attempt,
        item: item_to_ffi(&delivery.item)?,
    })
}

fn item_to_ffi(item: &ApplicationItem) -> Result<AsterItem, FfiError> {
    Ok(AsterItem {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterItem>(),
        item_id: item.id,
        publisher: item.publisher,
        data_class: u32::from(item.class as u8),
        priority: u32::from(item.priority as u8),
        causal_counter: item.publisher_counter,
        event_sequence: item.event_sequence.unwrap_or_default(),
        has_event_sequence: u8::from(item.event_sequence.is_some()),
        tombstone: u8::from(item.tombstone),
        reserved: [0; 6],
        topic: owned_buffer(item.topic.as_str().as_bytes())?,
        scope: owned_buffer(item.scope.as_str().as_bytes())?,
        origin_scope: owned_buffer(item.origin_scope.as_str().as_bytes())?,
        current_scope: owned_buffer(item.current_scope.as_str().as_bytes())?,
        logical_key: owned_buffer(&item.logical_key)?,
        payload: owned_buffer(&item.payload)?,
    })
}

fn conflict_to_ffi(conflict: &ConflictAnnotation) -> Result<AsterConflict, FfiError> {
    let sibling_ids: Vec<u8> = conflict.siblings.iter().flatten().copied().collect();
    let merge_policy = conflict.merge_policy.as_deref().unwrap_or_default();
    Ok(AsterConflict {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterConflict>(),
        logical_key: owned_buffer(&conflict.logical_key)?,
        sibling_ids: owned_buffer(&sibling_ids)?,
        merge_policy: owned_buffer(merge_policy.as_bytes())?,
        has_merge_policy: u8::from(conflict.merge_policy.is_some()),
        reserved: [0; 7],
    })
}

fn peer_state(value: PeerStatus) -> u32 {
    match value {
        PeerStatus::Offline => 0,
        PeerStatus::Authenticating => 1,
        PeerStatus::Ready => 2,
        PeerStatus::Rejected => 3,
        PeerStatus::Revoked => 4,
    }
}

fn sync_state(value: SyncStatus) -> u32 {
    match value {
        SyncStatus::Idle => 0,
        SyncStatus::Reconciling => 1,
        SyncStatus::Transferring => 2,
        SyncStatus::Converged => 3,
        SyncStatus::Suspended => 4,
    }
}

fn peer_to_ffi(snapshot: &PeerSnapshot) -> Result<AsterPeerSnapshot, FfiError> {
    let detail = snapshot.detail.as_deref().unwrap_or_default();
    Ok(AsterPeerSnapshot {
        abi_version: ABI_VERSION,
        struct_size: struct_size::<AsterPeerSnapshot>(),
        peer: snapshot.node,
        peer_state: peer_state(snapshot.peer),
        sync_state: sync_state(snapshot.sync),
        last_change_ms: snapshot.last_change_ms.unwrap_or_default(),
        has_last_change: u8::from(snapshot.last_change_ms.is_some()),
        has_detail: u8::from(snapshot.detail.is_some()),
        reserved: [0; 6],
        detail: owned_buffer(detail.as_bytes())?,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_abi_version() -> u32 {
    catch_unwind(|| ABI_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_protocol_version() -> u16 {
    catch_unwind(|| PROTOCOL_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_replication_wire_version() -> u16 {
    catch_unwind(|| REPLICATION_WIRE_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_default_semantic_version() -> u16 {
    catch_unwind(|| DEFAULT_SEMANTIC_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_highest_supported_semantic_version() -> u16 {
    catch_unwind(|| HIGHEST_SUPPORTED_SEMANTIC_VERSION).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_options_init(options: *mut AsterNodeOptions) -> u32 {
    boundary(|| write_output(options, AsterNodeOptions::default(), "options"))
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_open(
    options: *const AsterNodeOptions,
    out_node: *mut AsterNode,
) -> u32 {
    boundary(|| {
        let options = *versioned(options, "options")?;
        check_mut_pointer(out_node, "out_node")?;
        let path = input_string(options.store_path, "options.store_path")?;
        if path.is_empty() {
            return Err(FfiError::invalid("options.store_path must not be empty"));
        }
        if path.len() > 16 * 1024 {
            return Err(FfiError::invalid("options.store_path exceeds 16384 bytes"));
        }
        let bundle_bytes = input_bytes(options.provisioning_bundle, "options.provisioning_bundle")?;
        if bundle_bytes.is_empty() {
            return Err(FfiError::invalid("provisioning bundle must not be empty"));
        }
        if bundle_bytes.len() > 16 * 1024 * 1024 {
            return Err(FfiError::invalid("provisioning bundle exceeds 16 MiB"));
        }
        let bundle = ProvisioningBundle::from_bytes(bundle_bytes)
            .map_err(|error| FfiError::new(STATUS_SECURITY_ERROR, error.to_string()))?;
        let sealer = ReferenceEnvelopeSealer::open(bundle)
            .map_err(|error| FfiError::new(STATUS_SECURITY_ERROR, error.to_string()))?;
        let identity = sealer.identity();
        let priority_cap = required_priority(options.priority_cap)?;
        let emission = EmissionPolicy {
            minimum_priority: priority(options.emission_threshold, true)?,
        };
        if options.max_items == 0 || options.max_bytes == 0 {
            return Err(FfiError::invalid("storage limits must be nonzero"));
        }
        let config = NodeConfig {
            store: StoreConfig {
                max_items: options.max_items,
                max_bytes: options.max_bytes,
                tombstone_retention_ms: options.tombstone_retention_ms,
                superseded_retention_ms: options.superseded_retention_ms,
            },
            emission,
            priority_cap,
            ..NodeConfig::default()
        };
        let mut node = Node::open(&path, identity, sealer, config).map_err(FfiError::from)?;
        ApplicationNodeRef::new(&mut node)
            .reauthenticate_bridge_state()
            .map_err(FfiError::from)?;
        let handle = new_handle()?;
        let (blob_root, ephemeral_blob_root) = blob_root_for(&path, handle);
        lock(nodes(), "node registry")?.insert(
            handle,
            Arc::new(NodeCell {
                node: Mutex::new(Some(node)),
                blob_root,
                blob_config: BlobStoreConfig {
                    max_bytes: options.max_bytes,
                    max_chunks: options.max_items,
                },
                blob_staging_quota: Arc::new(BlobStagingQuota {
                    used_bytes: AtomicU64::new(0),
                    max_bytes: options.max_bytes,
                }),
                ephemeral_blob_root,
            }),
        );
        write_output(out_node, AsterNode { value: handle }, "out_node")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_close(node: *mut AsterNode) -> u32 {
    boundary(|| {
        let handle = take_handle(node, "node")?;
        if handle.value == 0 {
            return Ok(());
        }
        let cell = lock(nodes(), "node registry")?
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "node handle is unknown or closed"))?;
        purge_blob_handles(handle.value)?;
        purge_bridge_enrollments(handle.value)?;
        let mut guard = lock(&cell.node, "node")?;
        let _ = guard.take();
        drop(guard);
        if cell.ephemeral_blob_root {
            remove_blob_root(&cell.blob_root)?;
            remove_blob_root(&blob_staging_root(&cell.blob_root))?;
        }
        purge_results(handle.value)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_zeroize(node: *mut AsterNode) -> u32 {
    boundary(|| {
        let handle = take_handle(node, "node")?;
        if handle.value == 0 {
            return Err(FfiError::new(STATUS_CLOSED, "node handle is closed"));
        }
        let cell = lock(nodes(), "node registry")?
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "node handle is unknown or closed"))?;
        let blob_purge = purge_blob_handles(handle.value);
        let bridge_purge = purge_bridge_enrollments(handle.value);
        let mut guard = lock(&cell.node, "node")?;
        let result = match guard.as_mut() {
            Some(active) => active.zeroize().map_err(FfiError::from),
            None => Err(FfiError::new(STATUS_CLOSED, "node handle is closed")),
        };
        let _ = guard.take();
        drop(guard);
        let purge = purge_results(handle.value);
        let remove = remove_blob_root(&cell.blob_root);
        let remove_staging = remove_blob_root(&blob_staging_root(&cell.blob_root));
        result
            .and(blob_purge)
            .and(bridge_purge)
            .and(purge)
            .and(remove)
            .and(remove_staging)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_publish_options_init(options: *mut AsterBlobPublishOptions) -> u32 {
    boundary(|| {
        write_output(
            options,
            AsterBlobPublishOptions::default(),
            "Blob publish options",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_blob_writer_open(
    node: AsterNode,
    options: *const AsterBlobPublishOptions,
    out_writer: *mut AsterBlobWriter,
) -> u32 {
    boundary(|| {
        let options = *versioned(options, "Blob publish options")?;
        check_mut_pointer(out_writer, "out_writer")?;
        if options.reserved != [0; 7] {
            return Err(FfiError::invalid(
                "Blob publish options.reserved must be zero",
            ));
        }
        let topic = input_topic(options.topic, "Blob publish options.topic")?;
        let scope = input_scope(options.scope, "Blob publish options.scope")?;
        let media_type = if options.media_type.len == 0 {
            None
        } else {
            Some(input_string(
                options.media_type,
                "Blob publish options.media_type",
            )?)
        };
        let metadata = BlobMetadata::new(
            media_type,
            input_bytes(options.schema_id, "Blob publish options.schema_id")?.to_vec(),
        )
        .map_err(FfiError::from)?;
        let priority = required_priority(options.priority)?;
        let ttl_ms = if boolean(options.has_ttl, "Blob publish options.has_ttl")? {
            Some(options.ttl_ms)
        } else {
            None
        };
        let (root, config) = blob_storage(node)?;
        let staging_quota = blob_staging_quota(node)?;
        let staging = blob_staging_root(&root);
        fs::create_dir_all(&staging).map_err(|error| FfiError::from(BlobError::Io(error)))?;
        #[cfg(unix)]
        fs::set_permissions(&staging, {
            use std::os::unix::fs::PermissionsExt;
            fs::Permissions::from_mode(0o700)
        })
        .map_err(|error| FfiError::from(BlobError::Io(error)))?;

        let handle = new_handle()?;
        let source_path = staging.join(format!("writer-{handle}.source"));
        let digest_path = staging.join(format!("writer-{handle}.digests"));
        let source = create_staging_file(&source_path)?;
        let digest_scratch = match create_staging_file(&digest_path) {
            Ok(file) => file,
            Err(error) => {
                drop(source);
                let _ = fs::remove_file(&source_path);
                return Err(error);
            }
        };
        let cell = Arc::new(BlobWriterCell {
            owner: node.value,
            state: Mutex::new(Some(BlobWriterState {
                node,
                topic,
                scope,
                priority,
                ttl_ms,
                chunk_size: options.chunk_size,
                metadata,
                source: Some(source),
                source_path,
                digest_scratch: Some(digest_scratch),
                digest_path,
                source_len: 0,
                max_source_bytes: config.max_bytes,
                staging_quota,
                reserved_staging_bytes: 0,
                service: None,
                manifest: None,
                finished: None,
            })),
        });
        register_blob_writer(node, handle, cell)?;
        write_output(out_writer, AsterBlobWriter { value: handle }, "out_writer")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_write(writer: AsterBlobWriter, bytes: AsterBytes) -> u32 {
    boundary(|| {
        let bytes = input_bytes(bytes, "Blob writer bytes")?;
        let cell = blob_writer_cell(writer)?;
        let mut guard = lock(&cell.state, "Blob writer")?;
        let state = guard
            .as_mut()
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is closed"))?;
        if state.manifest.is_some() || state.finished.is_some() {
            return Err(FfiError::invalid(
                "Blob writer cannot accept bytes after finish begins",
            ));
        }
        let added = u64::try_from(bytes.len())
            .map_err(|_| FfiError::invalid("Blob writer length does not fit u64"))?;
        let new_len = state
            .source_len
            .checked_add(added)
            .ok_or_else(|| FfiError::new(STATUS_QUOTA_EXCEEDED, "Blob length overflow"))?;
        if new_len > state.max_source_bytes {
            return Err(FfiError::new(
                STATUS_QUOTA_EXCEEDED,
                "Blob exceeds the configured local byte quota",
            ));
        }
        state.staging_quota.reserve(added)?;
        let source = state
            .source
            .as_mut()
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer source is closed"))?;
        if let Err(error) = source.write_all(bytes) {
            state.staging_quota.release(added);
            drop(state.source.take());
            return Err(FfiError::from(BlobError::Io(error)));
        }
        state.source_len = new_len;
        state.reserved_staging_bytes = state
            .reserved_staging_bytes
            .checked_add(added)
            .ok_or_else(|| FfiError::internal("Blob staging quota accounting overflow"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_finish(
    writer: AsterBlobWriter,
    out_finish: *mut AsterBlobFinish,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_finish.cast_const(), "out_finish")?;
        let cell = blob_writer_cell(writer)?;
        let mut guard = lock(&cell.state, "Blob writer")?;
        let state = guard
            .as_mut()
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is closed"))?;
        if let Some(finished) = state.finished {
            return write_versioned_output(out_finish, finished, "out_finish");
        }
        if state.service.is_none() {
            let (root, config) = blob_storage(state.node)?;
            let scope = state.scope.clone();
            let topic = state.topic.clone();
            let service = with_node(state.node, |active| {
                active.current_blob_service(&scope, &topic, &root, config)
            })?;
            state.service = Some(service);
        }
        let finalized = state.finalize_local()?;
        let id = finalized.id();
        let topic = state.topic.clone();
        let scope = state.scope.clone();
        let priority = state.priority;
        let ttl_ms = state.ttl_ms;
        let receipt = with_node(state.node, |active| {
            publish_blob_manifest(active, &topic, &scope, priority, ttl_ms, &finalized)
        })?;
        let finished = AsterBlobFinish {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBlobFinish>(),
            blob_id: *id.as_bytes(),
            receipt: receipt_to_ffi(&receipt),
        };
        state.finished = Some(finished);
        state.cleanup_staging();
        drop(state.service.take());
        write_versioned_output(out_finish, finished, "out_finish")
    })
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_lines)] // Keep the multi-handle validation and lock lifetime explicit.
pub extern "C" fn aster_node_publish_blob_batch(
    node: AsterNode,
    request: *const AsterBlobPublishBatchRequest,
    out_result: *mut AsterBatchResult,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "Blob batch")?;
        check_mut_pointer(out_result, "out_result")?;
        if request.reserved != 0 {
            return Err(FfiError::invalid("Blob batch.reserved must be zero"));
        }
        if !(MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS).contains(&request.writer_count) {
            return Err(FfiError::invalid(
                "Blob batch.writer_count must be between 2 and 64",
            ));
        }
        let writers = input_array(
            request.writers,
            request.writer_count,
            MAX_BATCH_ITEMS,
            "Blob batch.writers",
        )?;
        let policy = batch_policy(request.policy)?;

        let mut seen = BTreeSet::new();
        let mut entries = Vec::with_capacity(writers.len());
        for (original_index, writer) in writers.iter().copied().enumerate() {
            if !seen.insert(writer.value) {
                return Err(FfiError::invalid(
                    "Blob batch contains a duplicate writer handle",
                ));
            }
            let cell = blob_writer_cell(writer)?;
            if cell.owner != node.value {
                return Err(FfiError::invalid(
                    "every Blob batch writer must belong to the publishing node",
                ));
            }
            entries.push((writer.value, original_index, cell));
        }
        // A deterministic handle order prevents reversed concurrent batches
        // from deadlocking while each writer remains exclusively finalized.
        entries.sort_by_key(|(handle, _, _)| *handle);
        let mut guards = Vec::with_capacity(entries.len());
        for (_, _, cell) in &entries {
            guards.push(lock(&cell.state, "Blob writer")?);
        }
        for guard in &guards {
            let state = guard
                .as_ref()
                .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is closed"))?;
            if state.finished.is_some() {
                return Err(FfiError::invalid(
                    "Blob batch writers must not already be published",
                ));
            }
        }

        let mut batch_items: Vec<Option<FinishedBlobBatchItem>> =
            (0..entries.len()).map(|_| None).collect();
        let mut blob_ids = vec![[0; ID_BYTES]; entries.len()];
        for ((_, original_index, _), guard) in entries.iter().zip(guards.iter_mut()) {
            let state = guard
                .as_mut()
                .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is closed"))?;
            if state.service.is_none() {
                let (root, config) = blob_storage(state.node)?;
                let scope = state.scope.clone();
                let topic = state.topic.clone();
                let service = with_node(state.node, |active| {
                    active.current_blob_service(&scope, &topic, &root, config)
                })?;
                state.service = Some(service);
            }
            let finished = state.finalize_local()?;
            blob_ids[*original_index] = *finished.id().as_bytes();
            batch_items[*original_index] = Some(FinishedBlobBatchItem {
                topic: state.topic.clone(),
                scope: state.scope.clone(),
                priority: state.priority,
                ttl_ms: state.ttl_ms,
                finished,
            });
        }
        let batch_items = batch_items
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                item.ok_or_else(|| {
                    FfiError::internal(format!("Blob batch item {index} was not finalized"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).publish_finished_blob_batch(FinishedBlobBatchRequest {
                items: batch_items,
                policy,
            })
        })?;
        if result.items.len() != entries.len() {
            return Err(FfiError::internal(
                "Blob batch receipt count did not match its writer count",
            ));
        }

        for ((_, original_index, _), guard) in entries.iter().zip(guards.iter_mut()) {
            let state = guard
                .as_mut()
                .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is closed"))?;
            state.finished = Some(AsterBlobFinish {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterBlobFinish>(),
                blob_id: blob_ids[*original_index],
                receipt: application_receipt_to_ffi(&result.items[*original_index]),
            });
            state.cleanup_staging();
            drop(state.service.take());
        }

        let handle = new_handle()?;
        lock(results(), "result registry")?.batch_results.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(result),
            },
        );
        write_output(out_result, AsterBatchResult { value: handle }, "out_result")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_close(writer: *mut AsterBlobWriter) -> u32 {
    boundary(|| {
        let handle = take_handle(writer, "Blob writer")?;
        if handle.value == 0 {
            return Ok(());
        }
        let cell = lock(blobs(), "Blob registry")?
            .writers
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob writer is unknown or closed"))?;
        let mut guard = lock(&cell.state, "Blob writer")?;
        drop(guard.take());
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_blob_reader_open(
    node: AsterNode,
    request: *const AsterBlobReadRequest,
    out_reader: *mut AsterBlobReader,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "Blob read request")?;
        check_mut_pointer(out_reader, "out_reader")?;
        let topic = input_topic(request.topic, "Blob read request.topic")?;
        let scope = input_scope(request.scope, "Blob read request.scope")?;
        let id = BlobId::from_bytes(request.blob_id);
        let (root, config) = blob_storage(node)?;
        let stored_manifest = FileBlobStore::open_with_config(&root, config)
            .map_err(FfiError::from)?
            .load_manifest(id)
            .map_err(FfiError::from)?
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "Blob was not found locally"))?;
        let content_epoch = stored_manifest.content_epoch();
        let mut service = with_node(node, |active| {
            active.blob_service(&scope, &topic, content_epoch, &root, config)
        })?;
        let finished = service.finish(id).map_err(FfiError::from)?;
        let found = with_node(node, |active| {
            active.find_authenticated_blob_manifest(
                &topic,
                &scope,
                id,
                finished.manifest_bytes(),
                finished.route_commitment(),
            )
        })?;
        if found.is_none() {
            return Err(FfiError::new(
                STATUS_NOT_FOUND,
                "authenticated Blob manifest item was not found",
            ));
        }
        let reader = service.reader_for_local(id).map_err(FfiError::from)?;
        let handle = new_handle()?;
        register_blob_reader(
            node,
            handle,
            Arc::new(BlobReaderCell {
                owner: node.value,
                reader: Mutex::new(Some(reader)),
            }),
        )?;
        write_output(out_reader, AsterBlobReader { value: handle }, "out_reader")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_reader_read(
    reader: AsterBlobReader,
    buffer: *mut u8,
    buffer_len: usize,
    out_read: *mut usize,
) -> u32 {
    boundary(|| {
        check_mut_pointer(out_read, "out_read")?;
        if buffer_len == 0 {
            return write_output(out_read, 0, "out_read");
        }
        if buffer_len > MAX_INPUT_BYTES || buffer_len > isize::MAX as usize {
            return Err(FfiError::invalid("Blob reader buffer length is too large"));
        }
        if buffer.is_null() {
            return Err(FfiError::invalid(
                "Blob reader buffer must not be null when length is nonzero",
            ));
        }
        // SAFETY: null and representable length were checked. The ABI requires exclusive writable
        // access to this caller-owned output buffer for the duration of this call.
        let output = unsafe { slice::from_raw_parts_mut(buffer, buffer_len) };
        let cell = blob_reader_cell(reader)?;
        let mut guard = lock(&cell.reader, "Blob reader")?;
        let active = guard
            .as_mut()
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob reader is closed"))?;
        let count = active.read_some(output).map_err(FfiError::from)?;
        write_output(out_read, count, "out_read")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_reader_close(reader: *mut AsterBlobReader) -> u32 {
    boundary(|| {
        let handle = take_handle(reader, "Blob reader")?;
        if handle.value == 0 {
            return Ok(());
        }
        let cell = lock(blobs(), "Blob registry")?
            .readers
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "Blob reader is unknown or closed"))?;
        let mut guard = lock(&cell.reader, "Blob reader")?;
        drop(guard.take());
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_publish(
    node: AsterNode,
    request: *const AsterPublishRequest,
    out_receipt: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "publish request")?;
        let _ = versioned(out_receipt.cast_const(), "out_receipt")?;
        let publish = publish_request_from_ffi(&request, "publish")?;
        let receipt = with_node(node, |active| active.publish(publish))?;
        write_versioned_output(out_receipt, receipt_to_ffi(&receipt), "out_receipt")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_publish_batch(
    node: AsterNode,
    request: *const AsterPublishBatchRequest,
    out_result: *mut AsterBatchResult,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "batch")?;
        check_mut_pointer(out_result, "out_result")?;
        if request.reserved != 0 {
            return Err(FfiError::invalid("batch.reserved must be zero"));
        }
        if !(MIN_BATCH_ITEMS..=MAX_BATCH_ITEMS).contains(&request.item_count) {
            return Err(FfiError::invalid(
                "batch.item_count must be between 2 and 64",
            ));
        }
        let items = input_array(
            request.items,
            request.item_count,
            MAX_BATCH_ITEMS,
            "batch.items",
        )?;
        let mut parsed = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let name = format!("batch.items[{index}]");
            let item = versioned(ptr::from_ref(item), &name)?;
            parsed.push(publish_request_from_ffi(item, &name)?);
        }
        let policy = batch_policy(request.policy)?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).publish_batch(BatchPublishRequest {
                items: parsed,
                policy,
            })
        })?;
        let handle = new_handle()?;
        lock(results(), "result registry")?.batch_results.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(result),
            },
        );
        write_output(out_result, AsterBatchResult { value: handle }, "out_result")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_batch_result_len(result: AsterBatchResult, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .batch_results
            .get(&result.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "batch result handle is closed"))?;
        write_output(out_len, snapshot.items.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_batch_result_get(
    result: AsterBatchResult,
    index: usize,
    out_receipt: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_receipt.cast_const(), "out_receipt")?;
        let snapshot = lock(results(), "result registry")?
            .batch_results
            .get(&result.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "batch result handle is closed"))?;
        let receipt = snapshot
            .items
            .get(index)
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "batch result index is out of range"))?;
        write_versioned_output(
            out_receipt,
            application_receipt_to_ffi(receipt),
            "out_receipt",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_batch_result_evicted_len(
    result: AsterBatchResult,
    out_len: *mut usize,
) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .batch_results
            .get(&result.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "batch result handle is closed"))?;
        write_output(out_len, snapshot.evicted.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_batch_result_evicted_get(
    result: AsterBatchResult,
    index: usize,
    out_item_id: *mut AsterItemId,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_item_id.cast_const(), "out_item_id")?;
        let snapshot = lock(results(), "result registry")?
            .batch_results
            .get(&result.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "batch result handle is closed"))?;
        let item_id = snapshot.evicted.get(index).ok_or_else(|| {
            FfiError::new(STATUS_NOT_FOUND, "batch eviction index is out of range")
        })?;
        write_versioned_output(
            out_item_id,
            AsterItemId {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterItemId>(),
                bytes: *item_id,
            },
            "out_item_id",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_batch_result_close(result: *mut AsterBatchResult) -> u32 {
    boundary(|| {
        let handle = take_handle(result, "batch result")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .batch_results
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "batch result handle is closed"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_rekey_scope(
    node: AsterNode,
    request: *const AsterRekeyRequest,
    out_receipt: *mut AsterRekeyReceipt,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "rekey request")?;
        let _ = versioned(out_receipt.cast_const(), "out_receipt")?;
        let signed_public_registry = input_bytes(
            request.signed_public_registry,
            "rekey.signed_public_registry",
        )?;
        if signed_public_registry.is_empty()
            || signed_public_registry.len() > MAX_REKEY_REGISTRY_BYTES
        {
            return Err(FfiError::invalid(
                "rekey signed public registry must be between 1 byte and 16 MiB",
            ));
        }
        let scope = input_scope(request.scope, "rekey.scope")?;
        if request.new_epoch == 0 {
            return Err(FfiError::invalid("rekey.new_epoch must be nonzero"));
        }
        let recipients = rekey_recipients_from_ffi(&request)?;
        let receipt = with_node(node, move |active| {
            ApplicationNodeRef::new(active).rekey_scope(
                signed_public_registry,
                request.minimum_registry_generation,
                scope,
                request.new_epoch,
                recipients,
            )
        })?;
        write_versioned_output(out_receipt, rekey_receipt_to_ffi(&receipt)?, "out_receipt")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_query(
    node: AsterNode,
    request: *const AsterQueryRequest,
    out_query: *mut AsterQuery,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "query request")?;
        check_mut_pointer(out_query, "out_query")?;
        let query = query_from_ffi(request)?;
        let items = with_node(node, |active| ApplicationNodeRef::new(active).query(query))?;
        let handle = new_handle()?;
        lock(results(), "result registry")?.queries.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(QuerySnapshot(items)),
            },
        );
        write_output(out_query, AsterQuery { value: handle }, "out_query")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_query_len(query: AsterQuery, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .queries
            .get(&query.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "query handle is closed"))?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_query_get(
    query: AsterQuery,
    index: usize,
    out_item: *mut AsterItem,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_item.cast_const(), "out_item")?;
        let snapshot = lock(results(), "result registry")?
            .queries
            .get(&query.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "query handle is closed"))?;
        let item = snapshot
            .get(index)
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "query index is out of range"))?;
        write_versioned_output(out_item, item_to_ffi(item)?, "out_item")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_query_close(query: *mut AsterQuery) -> u32 {
    boundary(|| {
        let handle = take_handle(query, "query")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .queries
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "query handle is closed"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_item_free(item: *mut AsterItem) -> u32 {
    boundary(|| {
        let item = versioned_mut(item, "item")?;
        release_item_buffers(item)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_subscribe(
    node: AsterNode,
    request: *const AsterSubscribeRequest,
    out_subscription: *mut u64,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "subscribe request")?;
        check_mut_pointer(out_subscription, "out_subscription")?;
        if request.reserved != [0; 3] {
            return Err(FfiError::invalid("subscribe.reserved must be zero"));
        }
        let topic = input_topic(request.topic, "subscribe.topic")?;
        let scope = input_scope(request.scope, "subscribe.scope")?;
        let include_descendant_scopes = boolean(
            request.include_descendant_scopes,
            "subscribe.include_descendant_scopes",
        )?;
        let class = data_class(request.data_class, true)?;
        let subscription = with_node(node, |active| {
            ApplicationNodeRef::new(active).subscribe(
                topic,
                scope,
                class,
                include_descendant_scopes,
            )
        })?;
        write_output(out_subscription, subscription.0, "out_subscription")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_poll(
    node: AsterNode,
    request: *const AsterPollRequest,
    out_deliveries: *mut AsterDeliveries,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "poll request")?;
        check_mut_pointer(out_deliveries, "out_deliveries")?;
        if request.subscription == 0 {
            return Err(FfiError::invalid("subscription must be nonzero"));
        }
        let poll_limit = limit(request.limit, 64, "poll.limit")?;
        let deliveries = with_node(node, |active| {
            ApplicationNodeRef::new(active).poll(SubscriptionId(request.subscription), poll_limit)
        })?;
        let handle = new_handle()?;
        lock(results(), "result registry")?.deliveries.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(DeliverySnapshot(deliveries)),
            },
        );
        write_output(
            out_deliveries,
            AsterDeliveries { value: handle },
            "out_deliveries",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_deliveries_len(deliveries: AsterDeliveries, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .deliveries
            .get(&deliveries.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "deliveries handle is closed"))?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_deliveries_get(
    deliveries: AsterDeliveries,
    index: usize,
    out_delivery: *mut AsterDelivery,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_delivery.cast_const(), "out_delivery")?;
        let snapshot = lock(results(), "result registry")?
            .deliveries
            .get(&deliveries.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "deliveries handle is closed"))?;
        let delivery = snapshot
            .get(index)
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "delivery index is out of range"))?;
        write_versioned_output(out_delivery, delivery_to_ffi(delivery)?, "out_delivery")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_deliveries_close(deliveries: *mut AsterDeliveries) -> u32 {
    boundary(|| {
        let handle = take_handle(deliveries, "deliveries")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .deliveries
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "deliveries handle is closed"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_delivery_free(delivery: *mut AsterDelivery) -> u32 {
    boundary(|| {
        let delivery = versioned_mut(delivery, "delivery")?;
        release_item_buffers(&mut delivery.item)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_acknowledge(node: AsterNode, request: *const AsterAckRequest) -> u32 {
    boundary(|| {
        let request = versioned(request, "acknowledgement request")?;
        if request.subscription == 0 {
            return Err(FfiError::invalid("subscription must be nonzero"));
        }
        with_node(node, |active| {
            ApplicationNodeRef::new(active)
                .acknowledge(SubscriptionId(request.subscription), request.item_id)
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_conflicts(
    node: AsterNode,
    request: *const AsterQueryRequest,
    out_conflicts: *mut AsterConflicts,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "conflict query")?;
        check_mut_pointer(out_conflicts, "out_conflicts")?;
        let query = query_from_ffi(request)?;
        let conflicts = with_node(node, |active| {
            ApplicationNodeRef::new(active).conflicts(query)
        })?;
        let handle = new_handle()?;
        lock(results(), "result registry")?.conflicts.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(ConflictSnapshot(conflicts)),
            },
        );
        write_output(
            out_conflicts,
            AsterConflicts { value: handle },
            "out_conflicts",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_conflicts_len(conflicts: AsterConflicts, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .conflicts
            .get(&conflicts.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "conflicts handle is closed"))?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_conflicts_get(
    conflicts: AsterConflicts,
    index: usize,
    out_conflict: *mut AsterConflict,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_conflict.cast_const(), "out_conflict")?;
        let snapshot = lock(results(), "result registry")?
            .conflicts
            .get(&conflicts.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "conflicts handle is closed"))?;
        let conflict = snapshot
            .get(index)
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "conflict index is out of range"))?;
        write_versioned_output(out_conflict, conflict_to_ffi(conflict)?, "out_conflict")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_conflicts_close(conflicts: *mut AsterConflicts) -> u32 {
    boundary(|| {
        let handle = take_handle(conflicts, "conflicts")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .conflicts
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "conflicts handle is closed"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_conflict_free(conflict: *mut AsterConflict) -> u32 {
    boundary(|| {
        let conflict = versioned_mut(conflict, "conflict")?;
        release_buffer(&mut conflict.logical_key)?;
        release_buffer(&mut conflict.sibling_ids)?;
        release_buffer(&mut conflict.merge_policy)?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_resolve(
    node: AsterNode,
    request: *const AsterResolveRequest,
    out_receipt: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let request = *versioned(request, "resolve request")?;
        let _ = versioned(out_receipt.cast_const(), "out_receipt")?;
        if request.reserved0 != 0 || request.reserved != [0; 7] {
            return Err(FfiError::invalid("resolve reserved fields must be zero"));
        }
        let sibling_bytes =
            input_bytes(request.expected_sibling_ids, "resolve.expected_sibling_ids")?;
        if sibling_bytes.is_empty() || sibling_bytes.len() % ID_BYTES != 0 {
            return Err(FfiError::invalid(
                "expected sibling identifiers must be a non-empty multiple of 32 bytes",
            ));
        }
        let siblings = sibling_bytes
            .chunks_exact(ID_BYTES)
            .map(|chunk| {
                <[u8; ID_BYTES]>::try_from(chunk)
                    .map_err(|_| FfiError::internal("exact sibling chunk had wrong length"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resolve = ResolveRequest {
            topic: input_topic(request.topic, "resolve.topic")?,
            scope: input_scope(request.scope, "resolve.scope")?,
            logical_key: input_bytes(request.logical_key, "resolve.logical_key")?.to_vec(),
            expected_siblings: siblings,
            payload: input_bytes(request.payload, "resolve.payload")?.to_vec(),
            priority: required_priority(request.priority)?,
            ttl_ms: if boolean(request.has_ttl, "resolve.has_ttl")? {
                Some(request.ttl_ms)
            } else {
                None
            },
        };
        let receipt = with_node(node, |active| {
            ApplicationNodeRef::new(active).resolve(resolve)
        })?;
        write_versioned_output(
            out_receipt,
            application_receipt_to_ffi(&receipt),
            "out_receipt",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_set_emission(node: AsterNode, threshold: u32) -> u32 {
    boundary(|| {
        let policy = EmissionPolicy {
            minimum_priority: priority(threshold, true)?,
        };
        with_node(node, |active| {
            active.set_emission_policy(policy);
            Ok(())
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_get_emission(node: AsterNode, out_threshold: *mut u32) -> u32 {
    boundary(|| {
        check_mut_pointer(out_threshold, "out_threshold")?;
        let policy = with_node(node, |active| Ok(active.emission_policy()))?;
        let value = policy
            .minimum_priority
            .map_or(4, |minimum| u32::from(minimum as u8));
        write_output(out_threshold, value, "out_threshold")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_peer_status(
    node: AsterNode,
    request: *const AsterPeerRequest,
    out_snapshot: *mut AsterPeerSnapshot,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "peer request")?;
        let _ = versioned(out_snapshot.cast_const(), "out_snapshot")?;
        let snapshot = with_node(node, |active| active.peer_status(request.peer))?
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "peer status is not known"))?;
        write_versioned_output(out_snapshot, peer_to_ffi(&snapshot)?, "out_snapshot")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_peers(node: AsterNode, out_peers: *mut AsterPeers) -> u32 {
    boundary(|| {
        check_mut_pointer(out_peers, "out_peers")?;
        let peers = with_node(node, CoreNode::peers)?;
        let handle = new_handle()?;
        lock(results(), "result registry")?.peers.insert(
            handle,
            ResultEntry {
                owner: node.value,
                value: Arc::new(peers),
            },
        );
        write_output(out_peers, AsterPeers { value: handle }, "out_peers")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_peers_len(peers: AsterPeers, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .peers
            .get(&peers.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "peers handle is closed"))?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_peers_get(
    peers: AsterPeers,
    index: usize,
    out_snapshot: *mut AsterPeerSnapshot,
) -> u32 {
    boundary(|| {
        let _ = versioned(out_snapshot.cast_const(), "out_snapshot")?;
        let snapshot = lock(results(), "result registry")?
            .peers
            .get(&peers.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "peers handle is closed"))?;
        let peer = snapshot
            .get(index)
            .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "peer index is out of range"))?;
        write_versioned_output(out_snapshot, peer_to_ffi(peer)?, "out_snapshot")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_peers_close(peers: *mut AsterPeers) -> u32 {
    boundary(|| {
        let handle = take_handle(peers, "peers")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .peers
            .remove(&handle.value)
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "peers handle is closed"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_peer_snapshot_free(snapshot: *mut AsterPeerSnapshot) -> u32 {
    boundary(|| {
        let snapshot = versioned_mut(snapshot, "peer snapshot")?;
        release_buffer(&mut snapshot.detail)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_enrollment_create(
    node: AsterNode,
    request: *const AsterBridgeEnrollmentRequest,
    out_enrollment: *mut AsterBridgeEnrollment,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge enrollment request")?;
        check_mut_pointer(out_enrollment, "out_enrollment")?;
        if request.reserved != [0; 8] {
            return Err(FfiError::invalid(
                "bridge enrollment request.reserved must be zero",
            ));
        }
        if request.source_route_epoch == 0 || request.target_route_epoch == 0 {
            return Err(FfiError::invalid(
                "bridge enrollment route epochs must be nonzero",
            ));
        }
        let source_scope = input_scope(
            request.source_scope,
            "bridge enrollment request.source_scope",
        )?;
        let target_scope = input_scope(
            request.target_scope,
            "bridge enrollment request.target_scope",
        )?;
        if source_scope == target_scope {
            return Err(FfiError::invalid(
                "bridge enrollment source and target scopes must differ",
            ));
        }
        let enrollment = with_node(node, |active| {
            ApplicationNodeRef::new(active).create_bridge_enrollment(
                source_scope,
                request.source_route_epoch,
                target_scope,
                request.target_route_epoch,
            )
        })?;
        let handle = new_handle()?;
        register_bridge_enrollment(node, handle, enrollment)?;
        write_output(
            out_enrollment,
            AsterBridgeEnrollment { value: handle },
            "out_enrollment",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_enrollment_close(enrollment: *mut AsterBridgeEnrollment) -> u32 {
    boundary(|| {
        let handle = take_handle(enrollment, "bridge enrollment")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(bridge_enrollments(), "bridge enrollment registry")?
            .values
            .remove(&handle.value)
            .map(|_| ())
            .ok_or_else(|| {
                FfiError::new(
                    STATUS_CLOSED,
                    "bridge enrollment handle is unknown, closed, or already consumed",
                )
            })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_enable(
    node: AsterNode,
    enrollment: *mut AsterBridgeEnrollment,
    policy: *const AsterBridgeEnablePolicy,
    out_result: *mut AsterBridgeAuthorizationResult,
) -> u32 {
    boundary(|| {
        let policy = versioned(policy, "bridge enable policy")?;
        let _ = versioned(out_result.cast_const(), "out_result")?;
        if policy.reserved != [0; 6] {
            return Err(FfiError::invalid(
                "bridge enable policy.reserved must be zero",
            ));
        }
        let policy = BridgeAuthorizationPolicy::new(
            bridge_topics(
                policy.topics,
                policy.topic_count,
                false,
                "bridge enable policy.topics",
            )?,
            bridge_priorities(
                policy.allowed_priority_mask,
                "bridge enable policy.allowed_priority_mask",
            )?,
            policy.max_total_hops,
        )
        .map_err(FfiError::from)?;
        // Validate the authority capability before invalidating the move-only
        // enrollment. Once the core enable operation starts, success or error
        // consumes the enrollment exactly as the Rust API does.
        let _ = node_cell(node)?;
        let enrollment = consume_bridge_enrollment(enrollment)?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).enable_bridge(enrollment, policy)
        })?;
        write_versioned_output(
            out_result,
            bridge_authorization_result_to_ffi(&result),
            "out_result",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_disable(
    node: AsterNode,
    request: *const AsterBridgeDisableRequest,
    out_result: *mut AsterBridgeAuthorizationResult,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge disable request")?;
        let _ = versioned(out_result.cast_const(), "out_result")?;
        if request.reserved != [0; 8] {
            return Err(FfiError::invalid(
                "bridge disable request.reserved must be zero",
            ));
        }
        let edge = BridgeEdge::new(
            request.bridge_node,
            input_scope(request.source_scope, "bridge disable request.source_scope")?,
            input_scope(request.target_scope, "bridge disable request.target_scope")?,
        )
        .map_err(FfiError::from)?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).disable_bridge(edge)
        })?;
        write_versioned_output(
            out_result,
            bridge_authorization_result_to_ffi(&result),
            "out_result",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_item(
    node: AsterNode,
    request: *const AsterBridgeItemRequest,
    out_result: *mut AsterBridgeRouteResult,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge item request")?;
        let output = versioned(out_result.cast_const(), "out_result")?;
        require_empty_buffer(&output.current_scope, "out_result.current_scope")?;
        if request.reserved != [0; 7] {
            return Err(FfiError::invalid(
                "bridge item request.reserved must be zero",
            ));
        }
        let narrowing = bridge_narrowing(
            request.topics,
            request.topic_count,
            request.allowed_priority_mask,
            "bridge item request",
        )?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).bridge_item(
                request.source_item,
                BridgeAuthorizationId::from_bytes(request.authorization_id),
                narrowing,
            )
        })?;
        write_versioned_output(
            out_result,
            bridge_route_result_to_ffi(&result)?,
            "out_result",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_extend(
    node: AsterNode,
    request: *const AsterBridgeExtendRequest,
    out_result: *mut AsterBridgeRouteResult,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge extend request")?;
        let output = versioned(out_result.cast_const(), "out_result")?;
        require_empty_buffer(&output.current_scope, "out_result.current_scope")?;
        if request.reserved != [0; 7] {
            return Err(FfiError::invalid(
                "bridge extend request.reserved must be zero",
            ));
        }
        let narrowing = bridge_narrowing(
            request.topics,
            request.topic_count,
            request.allowed_priority_mask,
            "bridge extend request",
        )?;
        let result = with_node(node, |active| {
            ApplicationNodeRef::new(active).extend_bridge_route(
                BridgeRouteHandle::from_bytes(request.route_handle),
                BridgeAuthorizationId::from_bytes(request.authorization_id),
                narrowing,
            )
        })?;
        write_versioned_output(
            out_result,
            bridge_route_result_to_ffi(&result)?,
            "out_result",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_route_result_free(result: *mut AsterBridgeRouteResult) -> u32 {
    boundary(|| {
        let result = versioned_mut(result, "bridge route result")?;
        release_buffer(&mut result.current_scope)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_authorization_status(
    node: AsterNode,
    request: *const AsterBridgeStatusRequest,
    out_status: *mut AsterBridgeAuthorizationStatus,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge authorization status request")?;
        let output = versioned(out_status.cast_const(), "out_status")?;
        if request.reserved != [0; 8] {
            return Err(FfiError::invalid(
                "bridge authorization status request.reserved must be zero",
            ));
        }
        require_empty_buffer(&output.source_scope, "out_status.source_scope")?;
        require_empty_buffer(&output.target_scope, "out_status.target_scope")?;
        require_empty_buffer(&output.topics, "out_status.topics")?;
        let status = with_node(node, |active| {
            ApplicationNodeRef::new(active)
                .bridge_authorization_status(BridgeAuthorizationId::from_bytes(request.id))
        })?
        .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "bridge authorization was not found"))?;
        write_versioned_output(
            out_status,
            bridge_authorization_status_to_ffi(&status)?,
            "out_status",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_authorizations(
    node: AsterNode,
    request: *const AsterBridgePageRequest,
    out_authorizations: *mut AsterBridgeAuthorizations,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge authorization page request")?;
        check_mut_pointer(out_authorizations, "out_authorizations")?;
        let (after, page_limit) = bridge_page(request, "bridge authorization page request")?;
        let values = with_node(node, |active| {
            ApplicationNodeRef::new(active)
                .bridge_authorizations(after.map(BridgeAuthorizationId::from_bytes), page_limit)
        })?;
        let handle = new_handle()?;
        register_bridge_authorization_snapshot(node, handle, values)?;
        write_output(
            out_authorizations,
            AsterBridgeAuthorizations { value: handle },
            "out_authorizations",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_authorizations_len(
    authorizations: AsterBridgeAuthorizations,
    out_len: *mut usize,
) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .bridge_authorizations
            .get(&authorizations.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| {
                FfiError::new(STATUS_CLOSED, "bridge authorization page handle is closed")
            })?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_authorizations_get(
    authorizations: AsterBridgeAuthorizations,
    index: usize,
    out_status: *mut AsterBridgeAuthorizationStatus,
) -> u32 {
    boundary(|| {
        let output = versioned(out_status.cast_const(), "out_status")?;
        require_empty_buffer(&output.source_scope, "out_status.source_scope")?;
        require_empty_buffer(&output.target_scope, "out_status.target_scope")?;
        require_empty_buffer(&output.topics, "out_status.topics")?;
        let snapshot = lock(results(), "result registry")?
            .bridge_authorizations
            .get(&authorizations.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| {
                FfiError::new(STATUS_CLOSED, "bridge authorization page handle is closed")
            })?;
        let status = snapshot.get(index).ok_or_else(|| {
            FfiError::new(
                STATUS_NOT_FOUND,
                "bridge authorization page index is out of range",
            )
        })?;
        write_versioned_output(
            out_status,
            bridge_authorization_status_to_ffi(status)?,
            "out_status",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_authorizations_close(
    authorizations: *mut AsterBridgeAuthorizations,
) -> u32 {
    boundary(|| {
        let handle = take_handle(authorizations, "bridge authorization page")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .bridge_authorizations
            .remove(&handle.value)
            .map(|_| ())
            .ok_or_else(|| {
                FfiError::new(STATUS_CLOSED, "bridge authorization page handle is closed")
            })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_authorization_status_free(
    status: *mut AsterBridgeAuthorizationStatus,
) -> u32 {
    boundary(|| {
        let status = versioned_mut(status, "bridge authorization status")?;
        release_buffer(&mut status.source_scope)?;
        release_buffer(&mut status.target_scope)?;
        release_buffer(&mut status.topics)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_route_status(
    node: AsterNode,
    request: *const AsterBridgeStatusRequest,
    out_status: *mut AsterBridgeRouteStatus,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge route status request")?;
        let output = versioned(out_status.cast_const(), "out_status")?;
        if request.reserved != [0; 8] {
            return Err(FfiError::invalid(
                "bridge route status request.reserved must be zero",
            ));
        }
        require_empty_buffer(&output.origin_scope, "out_status.origin_scope")?;
        require_empty_buffer(&output.current_scope, "out_status.current_scope")?;
        require_empty_buffer(&output.topic, "out_status.topic")?;
        let status = with_node(node, |active| {
            ApplicationNodeRef::new(active)
                .bridge_route_status(BridgeRouteHandle::from_bytes(request.id))
        })?
        .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "bridge route was not found"))?;
        write_versioned_output(
            out_status,
            bridge_route_status_to_ffi(&status)?,
            "out_status",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_bridge_routes(
    node: AsterNode,
    request: *const AsterBridgePageRequest,
    out_routes: *mut AsterBridgeRoutes,
) -> u32 {
    boundary(|| {
        let request = versioned(request, "bridge route page request")?;
        check_mut_pointer(out_routes, "out_routes")?;
        let (after, page_limit) = bridge_page(request, "bridge route page request")?;
        let values = with_node(node, |active| {
            ApplicationNodeRef::new(active)
                .bridge_routes(after.map(BridgeRouteHandle::from_bytes), page_limit)
        })?;
        let handle = new_handle()?;
        register_bridge_route_snapshot(node, handle, values)?;
        write_output(
            out_routes,
            AsterBridgeRoutes { value: handle },
            "out_routes",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_routes_len(routes: AsterBridgeRoutes, out_len: *mut usize) -> u32 {
    boundary(|| {
        check_mut_pointer(out_len, "out_len")?;
        let snapshot = lock(results(), "result registry")?
            .bridge_routes
            .get(&routes.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "bridge route page handle is closed"))?;
        write_output(out_len, snapshot.len(), "out_len")
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_routes_get(
    routes: AsterBridgeRoutes,
    index: usize,
    out_status: *mut AsterBridgeRouteStatus,
) -> u32 {
    boundary(|| {
        let output = versioned(out_status.cast_const(), "out_status")?;
        require_empty_buffer(&output.origin_scope, "out_status.origin_scope")?;
        require_empty_buffer(&output.current_scope, "out_status.current_scope")?;
        require_empty_buffer(&output.topic, "out_status.topic")?;
        let snapshot = lock(results(), "result registry")?
            .bridge_routes
            .get(&routes.value)
            .map(|entry| Arc::clone(&entry.value))
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "bridge route page handle is closed"))?;
        let status = snapshot.get(index).ok_or_else(|| {
            FfiError::new(STATUS_NOT_FOUND, "bridge route page index is out of range")
        })?;
        write_versioned_output(
            out_status,
            bridge_route_status_to_ffi(status)?,
            "out_status",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_routes_close(routes: *mut AsterBridgeRoutes) -> u32 {
    boundary(|| {
        let handle = take_handle(routes, "bridge route page")?;
        if handle.value == 0 {
            return Ok(());
        }
        lock(results(), "result registry")?
            .bridge_routes
            .remove(&handle.value)
            .map(|_| ())
            .ok_or_else(|| FfiError::new(STATUS_CLOSED, "bridge route page handle is closed"))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_bridge_route_status_free(status: *mut AsterBridgeRouteStatus) -> u32 {
    boundary(|| {
        let status = versioned_mut(status, "bridge route status")?;
        release_buffer(&mut status.origin_scope)?;
        release_buffer(&mut status.current_scope)?;
        release_buffer(&mut status.topic)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_set_bridge_filters(
    node: AsterNode,
    filters: *const AsterBridgeFilter,
    filter_count: usize,
) -> u32 {
    boundary(|| {
        if filter_count > 4_096 {
            return Err(FfiError::invalid("bridge filter count exceeds 4096"));
        }
        let filter_slice = if filter_count == 0 {
            &[][..]
        } else {
            check_pointer(filters, "filters")?;
            // SAFETY: pointer alignment/null and a conservative count bound are
            // checked; the caller keeps the array readable for this call only.
            unsafe { slice::from_raw_parts(filters, filter_count) }
        };
        let mut parsed = Vec::with_capacity(filter_slice.len());
        for (index, filter) in filter_slice.iter().enumerate() {
            let name = format!("filters[{index}]");
            let filter = versioned(ptr::from_ref(filter), &name)?;
            if filter.reserved != 0 {
                return Err(FfiError::invalid(format!(
                    "filters[{index}].reserved must be zero"
                )));
            }
            let mut topics = BTreeSet::new();
            if filter.topic.len != 0 {
                topics.insert(input_topic(filter.topic, "bridge.topic")?);
            }
            parsed.push(BridgeFilter {
                from_scope: input_scope(filter.from_scope, "bridge.from_scope")?,
                to_scope: input_scope(filter.to_scope, "bridge.to_scope")?,
                topics,
                minimum_priority: required_priority(filter.minimum_priority)?,
            });
        }
        with_node(node, |active| active.set_bridge_filters(&parsed))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_last_error(out_error: *mut AsterOwnedBuffer) -> u32 {
    boundary_preserve_error(|| {
        let message = LAST_ERROR.with(|slot| slot.borrow().clone());
        let message = if message.is_empty() {
            FALLBACK_ERROR
                .get_or_init(|| Mutex::new(String::new()))
                .lock()
                .map_err(|_| FfiError::internal("fallback error lock is poisoned"))?
                .clone()
        } else {
            message
        };
        let output = versioned_mut(out_error, "out_error")?;
        if !output.data.is_null() || output.len != 0 {
            return Err(FfiError::invalid("out_error must be an empty owned buffer"));
        }
        *output = owned_buffer(message.as_bytes())?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_buffer_free(buffer: *mut AsterOwnedBuffer) -> u32 {
    boundary(|| {
        let buffer = versioned_mut(buffer, "buffer")?;
        release_buffer(buffer)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::sync::{InterestFilter, InventoryPurpose};
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use std::sync::Barrier;
    use std::thread;

    const TEST_BUNDLE: &[u8] =
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");

    #[test]
    fn version_surfaces_distinguish_wire_from_semantics() {
        assert_eq!(aster_protocol_version(), 1);
        assert_eq!(aster_replication_wire_version(), 1);
        assert_eq!(aster_default_semantic_version(), 9);
        assert_eq!(aster_highest_supported_semantic_version(), 9);
    }

    #[test]
    fn format_three_fixture_opens_and_legacy_format_two_is_rejected() {
        assert_eq!(&TEST_BUNDLE[..8], b"ASTRPB03");
        let mut node = open_memory_with_bundle(TEST_BUNDLE);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);

        // Preserve the exact format-3 body while presenting the legacy tag.
        // The production parser must fail closed; the FFI adds no compatibility
        // path for the former root-seed-bearing bundle format.
        let mut legacy = TEST_BUNDLE.to_vec();
        legacy[..8].copy_from_slice(b"ASTRPB02");
        let options = AsterNodeOptions {
            store_path: bytes(b":memory:"),
            provisioning_bundle: bytes(&legacy),
            ..AsterNodeOptions::default()
        };
        let mut rejected = AsterNode::default();
        assert_eq!(
            aster_node_open(&options, &mut rejected),
            STATUS_SECURITY_ERROR
        );
        assert_eq!(rejected.value, 0);
    }

    fn versioned<T>() -> (u32, u32) {
        (ABI_VERSION, struct_size::<T>())
    }

    fn bytes(value: &[u8]) -> AsterBytes {
        AsterBytes {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn open_memory_with_bundle(bundle: &[u8]) -> AsterNode {
        let mut options = AsterNodeOptions::default();
        let path = b":memory:";
        options.store_path = bytes(path);
        options.provisioning_bundle = bytes(bundle);
        let mut node = AsterNode::default();
        assert_eq!(
            aster_node_open(&options, &mut node),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        node
    }

    fn open_memory() -> AsterNode {
        open_memory_with_bundle(TEST_BUNDLE)
    }

    fn bundle_identity(bundle: &[u8]) -> [u8; ID_BYTES] {
        ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(bundle).expect("parse test provisioning bundle"),
        )
        .expect("open test provisioning bundle")
        .identity()
    }

    fn open_path_with_bundle(path: &Path, bundle: &[u8]) -> AsterNode {
        let mut options = AsterNodeOptions::default();
        let path = path.to_str().expect("test path is UTF-8").as_bytes();
        options.store_path = bytes(path);
        options.provisioning_bundle = bytes(bundle);
        let mut node = AsterNode::default();
        assert_eq!(
            aster_node_open(&options, &mut node),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        node
    }

    fn open_path(path: &Path) -> AsterNode {
        open_path_with_bundle(path, TEST_BUNDLE)
    }

    fn open_blob_writer(node: AsterNode) -> AsterBlobWriter {
        let options = AsterBlobPublishOptions {
            topic: bytes(b"imagery.blob"),
            scope: bytes(b"mission/team/alpha"),
            media_type: bytes(b"application/octet-stream"),
            schema_id: bytes(b"test/blob/v1"),
            chunk_size: 4096,
            ..AsterBlobPublishOptions::default()
        };
        let mut writer = AsterBlobWriter::default();
        assert_eq!(
            aster_node_blob_writer_open(node, &options, &mut writer),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        writer
    }

    fn write_blob(writer: AsterBlobWriter, payload: &[u8]) {
        for chunk in payload.chunks(3001) {
            assert_eq!(aster_blob_writer_write(writer, bytes(chunk)), STATUS_OK);
        }
    }

    fn empty_blob_finish() -> AsterBlobFinish {
        AsterBlobFinish {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBlobFinish>(),
            blob_id: [0; ID_BYTES],
            receipt: AsterPublishReceipt {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishReceipt>(),
                item_id: [0; ID_BYTES],
                publisher: [0; ID_BYTES],
                causal_counter: 0,
                event_sequence: 0,
                has_event_sequence: 0,
                effective_priority: 0,
                reserved: [0; 6],
            },
        }
    }

    fn empty_item() -> AsterItem {
        AsterItem {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterItem>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            data_class: 0,
            priority: 0,
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            tombstone: 0,
            reserved: [0; 6],
            topic: AsterOwnedBuffer::default(),
            scope: AsterOwnedBuffer::default(),
            origin_scope: AsterOwnedBuffer::default(),
            current_scope: AsterOwnedBuffer::default(),
            logical_key: AsterOwnedBuffer::default(),
            payload: AsterOwnedBuffer::default(),
        }
    }

    fn owned_contents(buffer: &AsterOwnedBuffer, name: &str) -> Vec<u8> {
        input_bytes(
            AsterBytes {
                data: buffer.data.cast_const(),
                len: buffer.len,
            },
            name,
        )
        .unwrap_or_else(|error| panic!("read {name}: {error:?}"))
        .to_vec()
    }

    fn publish(node: AsterNode, payload: &[u8]) -> AsterPublishReceipt {
        let topic = b"position.current";
        let scope = b"mission/team/alpha";
        let key = b"unit-7";
        let (abi_version, request_size) = versioned::<AsterPublishRequest>();
        let request = AsterPublishRequest {
            abi_version,
            struct_size: request_size,
            data_class: 0,
            priority: 2,
            topic: bytes(topic),
            scope: bytes(scope),
            logical_key: bytes(key),
            payload: bytes(payload),
            ttl_ms: 60_000,
            has_ttl: 1,
            tombstone: 0,
            reserved: [0; 6],
        };
        let mut receipt = AsterPublishReceipt {
            abi_version,
            struct_size: struct_size::<AsterPublishReceipt>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            effective_priority: 0,
            reserved: [0; 6],
        };
        assert_eq!(aster_node_publish(node, &request, &mut receipt), STATUS_OK);
        receipt
    }

    fn publish_named(
        node: AsterNode,
        topic: &[u8],
        scope: &[u8],
        logical_key: &[u8],
        payload: &[u8],
    ) -> AsterPublishReceipt {
        let request = AsterPublishRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishRequest>(),
            data_class: 0,
            priority: 2,
            topic: bytes(topic),
            scope: bytes(scope),
            logical_key: bytes(logical_key),
            payload: bytes(payload),
            ttl_ms: 0,
            has_ttl: 0,
            tombstone: 0,
            reserved: [0; 6],
        };
        let mut receipt = AsterPublishReceipt {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishReceipt>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            effective_priority: 0,
            reserved: [0; 6],
        };
        assert_eq!(
            aster_node_publish(node, &request, &mut receipt),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        receipt
    }

    fn create_bridge_enrollment(
        node: AsterNode,
        source_scope: &[u8],
        source_epoch: u64,
        target_scope: &[u8],
        target_epoch: u64,
    ) -> AsterBridgeEnrollment {
        let request = AsterBridgeEnrollmentRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeEnrollmentRequest>(),
            source_scope: bytes(source_scope),
            target_scope: bytes(target_scope),
            source_route_epoch: source_epoch,
            target_route_epoch: target_epoch,
            reserved: [0; 8],
        };
        let mut enrollment = AsterBridgeEnrollment::default();
        assert_eq!(
            aster_node_bridge_enrollment_create(node, &request, &mut enrollment),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_ne!(enrollment.value, 0);
        enrollment
    }

    fn enable_bridge_enrollment(
        node: AsterNode,
        enrollment: &mut AsterBridgeEnrollment,
        topic: &[u8],
    ) -> AsterBridgeAuthorizationResult {
        let topics = [bytes(topic)];
        let policy = AsterBridgeEnablePolicy {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeEnablePolicy>(),
            topics: topics.as_ptr(),
            topic_count: topics.len(),
            allowed_priority_mask: (1u8 << (Priority::Immediate as u8))
                | (1u8 << (Priority::Flash as u8)),
            max_total_hops: 8,
            reserved: [0; 6],
        };
        let mut result = AsterBridgeAuthorizationResult {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeAuthorizationResult>(),
            id: [0; ID_BYTES],
            generation: 0,
            control_sequence: 0,
            enabled: 0,
            reserved: [0; 7],
        };
        assert_eq!(
            aster_node_bridge_enable(node, enrollment, &policy, &mut result),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(enrollment.value, 0);
        assert_eq!(result.enabled, 1);
        result
    }

    #[test]
    fn offline_publish_query_and_free() {
        let mut node = open_memory();
        let receipt = publish(node, b"north\0binary");
        assert_ne!(receipt.item_id, [0; ID_BYTES]);

        let (abi_version, request_size) = versioned::<AsterQueryRequest>();
        let query_request = AsterQueryRequest {
            abi_version,
            struct_size: request_size,
            topic: bytes(b"position.current"),
            scope: bytes(b"mission/team/alpha"),
            logical_key: AsterBytes::default(),
            data_class: u32::MAX,
            include_descendant_scopes: 0,
            include_recoverable_versions: 0,
            include_tombstones: 0,
            reserved: 0,
            limit: 10,
        };
        let mut query = AsterQuery::default();
        assert_eq!(
            aster_node_query(node, &query_request, &mut query),
            STATUS_OK
        );
        let mut len = 0;
        assert_eq!(aster_query_len(query, &mut len), STATUS_OK);
        assert_eq!(len, 1);
        let mut item = AsterItem {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterItem>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            data_class: 0,
            priority: 0,
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            tombstone: 0,
            reserved: [0; 6],
            topic: AsterOwnedBuffer::default(),
            scope: AsterOwnedBuffer::default(),
            origin_scope: AsterOwnedBuffer::default(),
            current_scope: AsterOwnedBuffer::default(),
            logical_key: AsterOwnedBuffer::default(),
            payload: AsterOwnedBuffer::default(),
        };
        assert_eq!(aster_query_get(query, 0, &mut item), STATUS_OK);
        assert_eq!(item.payload.len, 12);
        assert_eq!(item.scope.len, b"mission/team/alpha".len());
        assert_eq!(item.origin_scope.len, item.scope.len);
        assert_eq!(item.current_scope.len, item.scope.len);
        assert_eq!(aster_item_free(&mut item), STATUS_OK);
        assert_eq!(aster_query_close(&mut query), STATUS_OK);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
        assert_eq!(node.value, 0);
    }

    #[test]
    fn explicit_batch_is_ordered_atomic_and_exposes_stable_metadata() {
        let mut node = open_memory();
        let first_payload = b"first";
        let second_payload = b"second";
        let items = [
            AsterPublishRequest {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishRequest>(),
                data_class: 1,
                priority: 2,
                topic: bytes(b"position.current"),
                scope: bytes(b"mission/team/alpha"),
                logical_key: AsterBytes::default(),
                payload: bytes(first_payload),
                ttl_ms: 0,
                has_ttl: 0,
                tombstone: 0,
                reserved: [0; 6],
            },
            AsterPublishRequest {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishRequest>(),
                data_class: 1,
                priority: 2,
                topic: bytes(b"position.current"),
                scope: bytes(b"mission/team/alpha"),
                logical_key: AsterBytes::default(),
                payload: bytes(second_payload),
                ttl_ms: 0,
                has_ttl: 0,
                tombstone: 0,
                reserved: [0; 6],
            },
        ];
        let request = AsterPublishBatchRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishBatchRequest>(),
            items: items.as_ptr(),
            item_count: items.len(),
            policy: BATCH_ONLY,
            reserved: 0,
        };
        let mut result = AsterBatchResult::default();
        assert_eq!(
            aster_node_publish_batch(node, &request, &mut result),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_ne!(result.value, 0);

        let mut len = 0;
        assert_eq!(aster_batch_result_len(result, &mut len), STATUS_OK);
        assert_eq!(len, 2);
        let mut receipts = Vec::new();
        for index in 0..len {
            let mut output = AsterPublishReceipt {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishReceipt>(),
                item_id: [0; ID_BYTES],
                publisher: [0; ID_BYTES],
                causal_counter: 0,
                event_sequence: 0,
                has_event_sequence: 0,
                effective_priority: 0,
                reserved: [0; 6],
            };
            assert_eq!(
                aster_batch_result_get(result, index, &mut output),
                STATUS_OK
            );
            receipts.push(output);
        }
        assert_eq!(receipts[0].causal_counter, 1);
        assert_eq!(receipts[1].causal_counter, 2);
        assert_eq!(receipts[0].event_sequence, 1);
        assert_eq!(receipts[1].event_sequence, 2);
        assert_eq!(receipts[0].has_event_sequence, 1);
        assert_eq!(receipts[1].has_event_sequence, 1);
        assert_ne!(receipts[0].item_id, receipts[1].item_id);

        let mut evicted_len = usize::MAX;
        assert_eq!(
            aster_batch_result_evicted_len(result, &mut evicted_len),
            STATUS_OK
        );
        assert_eq!(evicted_len, 0);
        let mut missing = AsterItemId {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterItemId>(),
            bytes: [0; ID_BYTES],
        };
        assert_eq!(
            aster_batch_result_evicted_get(result, 0, &mut missing),
            STATUS_NOT_FOUND
        );
        assert_eq!(aster_batch_result_close(&mut result), STATUS_OK);
        assert_eq!(result.value, 0);
        assert_eq!(aster_batch_result_len(result, &mut len), STATUS_CLOSED);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    fn rejected_batch_consumes_no_publisher_counter() {
        let mut node = open_memory();
        let items = [
            AsterPublishRequest {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishRequest>(),
                data_class: 0,
                priority: 2,
                topic: bytes(b"position.current"),
                scope: bytes(b"mission/team/alpha"),
                logical_key: bytes(b"unit-1"),
                payload: bytes(b"first"),
                ttl_ms: 0,
                has_ttl: 0,
                tombstone: 0,
                reserved: [0; 6],
            },
            AsterPublishRequest {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishRequest>(),
                data_class: 0,
                priority: 2,
                topic: bytes(b"position.history"),
                scope: bytes(b"mission/team/alpha"),
                logical_key: bytes(b"unit-2"),
                payload: bytes(b"second"),
                ttl_ms: 0,
                has_ttl: 0,
                tombstone: 0,
                reserved: [0; 6],
            },
        ];
        let request = AsterPublishBatchRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishBatchRequest>(),
            items: items.as_ptr(),
            item_count: items.len(),
            policy: BATCH_RETAINED_DUAL,
            reserved: 0,
        };
        let mut result = AsterBatchResult::default();
        assert_eq!(
            aster_node_publish_batch(node, &request, &mut result),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result.value, 0);
        assert_eq!(publish(node, b"after rejection").causal_counter, 1);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    fn finalized_blob_writers_publish_as_one_ordered_batch() {
        let mut node = open_memory();
        let mut first_writer = open_blob_writer(node);
        let mut second_writer = open_blob_writer(node);
        write_blob(first_writer, b"first finalized Blob");
        write_blob(second_writer, b"second finalized Blob");

        let writer_handles = [first_writer, second_writer];
        let request = AsterBlobPublishBatchRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBlobPublishBatchRequest>(),
            writers: writer_handles.as_ptr(),
            writer_count: writer_handles.len(),
            policy: BATCH_RETAINED_DUAL,
            reserved: 0,
        };
        let mut result = AsterBatchResult::default();
        assert_eq!(
            aster_node_publish_blob_batch(node, &request, &mut result),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        let mut len = 0;
        assert_eq!(aster_batch_result_len(result, &mut len), STATUS_OK);
        assert_eq!(len, 2);
        let mut receipts = Vec::new();
        for index in 0..len {
            let mut output = AsterPublishReceipt {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterPublishReceipt>(),
                item_id: [0; ID_BYTES],
                publisher: [0; ID_BYTES],
                causal_counter: 0,
                event_sequence: 0,
                has_event_sequence: 0,
                effective_priority: 0,
                reserved: [0; 6],
            };
            assert_eq!(
                aster_batch_result_get(result, index, &mut output),
                STATUS_OK
            );
            receipts.push(output);
        }
        assert_eq!(receipts[0].causal_counter, 1);
        assert_eq!(receipts[1].causal_counter, 2);
        assert_eq!(receipts[0].has_event_sequence, 0);
        assert_eq!(receipts[1].has_event_sequence, 0);
        assert_eq!(aster_batch_result_close(&mut result), STATUS_OK);

        let mut first = empty_blob_finish();
        let mut second = empty_blob_finish();
        assert_eq!(
            aster_blob_writer_finish(first_writer, &mut first),
            STATUS_OK
        );
        assert_eq!(
            aster_blob_writer_finish(second_writer, &mut second),
            STATUS_OK
        );
        assert_eq!(first.receipt.item_id, receipts[0].item_id);
        assert_eq!(second.receipt.item_id, receipts[1].item_id);
        assert_ne!(first.blob_id, [0; ID_BYTES]);
        assert_ne!(second.blob_id, [0; ID_BYTES]);
        assert_ne!(first.blob_id, second.blob_id);

        assert_eq!(aster_blob_writer_close(&mut first_writer), STATUS_OK);
        assert_eq!(aster_blob_writer_close(&mut second_writer), STATUS_OK);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bridge_capabilities_are_opaque_consumed_bounded_and_restart_safe() {
        let alpha = Scope::new("mission/alpha").expect("alpha scope");
        let bravo = Scope::new("mission/bravo").expect("bravo scope");
        let charlie = Scope::new("mission/charlie").expect("charlie scope");
        let topic = Topic::new("ops").expect("bridge topic");
        let accesses = [
            ProvisioningAccess::member(alpha.clone(), vec![7], vec![topic.clone()])
                .expect("alpha access"),
            ProvisioningAccess::member(bravo.clone(), vec![9], vec![topic.clone()])
                .expect("bravo access"),
            ProvisioningAccess::member(charlie.clone(), vec![11], vec![topic.clone()])
                .expect("charlie access"),
        ];
        let mut provisioner =
            ReferenceProvisioner::from_seed([0xb3; 32]).expect("bridge provisioner");
        let bundle = provisioner
            .issue_control_authority(1, &accesses)
            .expect("issue bridge authority")
            .to_bytes()
            .expect("encode bridge authority bundle");
        let authority_id = bundle_identity(&bundle);
        let sequence = new_handle().expect("test handle sequence");
        let directory = std::env::temp_dir().join(format!(
            "aster-ffi-bridge-api-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create bridge test directory");
        let database = directory.join("mesh.db");
        let mut node = open_path_with_bundle(&database, &bundle);

        // Enrollment commits the bridge credential's provisioned route
        // commitments. The adapter-only fixture then activates those exact
        // provisioned epochs; this setup operation is not part of the C ABI.
        let mut first_enrollment = create_bridge_enrollment(
            node,
            alpha.as_str().as_bytes(),
            7,
            bravo.as_str().as_bytes(),
            9,
        );
        let mut second_enrollment = create_bridge_enrollment(
            node,
            bravo.as_str().as_bytes(),
            9,
            charlie.as_str().as_bytes(),
            11,
        );
        let mut rejected_enrollment = create_bridge_enrollment(
            node,
            alpha.as_str().as_bytes(),
            7,
            bravo.as_str().as_bytes(),
            9,
        );
        let mut purged_enrollment = create_bridge_enrollment(
            node,
            alpha.as_str().as_bytes(),
            7,
            bravo.as_str().as_bytes(),
            9,
        );

        for (scope, epoch) in [(&alpha, 7), (&bravo, 9), (&charlie, 11)] {
            with_node(node, |active| active.publish_scope_epoch(scope, epoch))
                .unwrap_or_else(|error| panic!("activate test epoch: {error:?}"));
        }

        let filters = [
            AsterBridgeFilter {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterBridgeFilter>(),
                from_scope: bytes(alpha.as_str().as_bytes()),
                to_scope: bytes(bravo.as_str().as_bytes()),
                topic: bytes(topic.as_str().as_bytes()),
                minimum_priority: u32::from(Priority::Routine as u8),
                reserved: 0,
            },
            AsterBridgeFilter {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterBridgeFilter>(),
                from_scope: bytes(bravo.as_str().as_bytes()),
                to_scope: bytes(charlie.as_str().as_bytes()),
                topic: bytes(topic.as_str().as_bytes()),
                minimum_priority: u32::from(Priority::Routine as u8),
                reserved: 0,
            },
        ];
        assert_eq!(
            aster_node_set_bridge_filters(node, filters.as_ptr(), filters.len()),
            STATUS_OK
        );

        // ABI validation occurs before move consumption, so callers can fix a
        // malformed policy or close the still-live enrollment.
        let topic_views = [bytes(topic.as_str().as_bytes())];
        let invalid_policy = AsterBridgeEnablePolicy {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeEnablePolicy>(),
            topics: topic_views.as_ptr(),
            topic_count: topic_views.len(),
            allowed_priority_mask: 0,
            max_total_hops: 8,
            reserved: [0; 6],
        };
        let mut invalid_output = AsterBridgeAuthorizationResult {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeAuthorizationResult>(),
            id: [0; ID_BYTES],
            generation: 0,
            control_sequence: 0,
            enabled: 0,
            reserved: [0; 7],
        };
        assert_eq!(
            aster_node_bridge_enable(
                node,
                &mut first_enrollment,
                &invalid_policy,
                &mut invalid_output,
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_ne!(first_enrollment.value, 0);
        let first_authorization =
            enable_bridge_enrollment(node, &mut first_enrollment, topic.as_str().as_bytes());
        assert_eq!(first_authorization.control_sequence, 1);
        assert_eq!(
            aster_bridge_enrollment_close(&mut first_enrollment),
            STATUS_OK,
            "closing an already-consumed zero handle is idempotent"
        );

        let second_authorization =
            enable_bridge_enrollment(node, &mut second_enrollment, topic.as_str().as_bytes());
        assert_eq!(second_authorization.control_sequence, 2);

        let subscribe_request = AsterSubscribeRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterSubscribeRequest>(),
            topic: bytes(topic.as_str().as_bytes()),
            scope: bytes(charlie.as_str().as_bytes()),
            data_class: u32::MAX,
            include_descendant_scopes: 0,
            reserved: [0; 3],
        };
        let mut bridge_subscription = 0;
        assert_eq!(
            aster_node_subscribe(node, &subscribe_request, &mut bridge_subscription),
            STATUS_OK
        );
        assert_ne!(bridge_subscription, 0);

        let source = publish_named(
            node,
            topic.as_str().as_bytes(),
            alpha.as_str().as_bytes(),
            b"bridge-api-source",
            b"payload never exposed by administration",
        );
        let narrowing_topics = [bytes(topic.as_str().as_bytes())];
        let first_request = AsterBridgeItemRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeItemRequest>(),
            source_item: source.item_id,
            authorization_id: first_authorization.id,
            topics: narrowing_topics.as_ptr(),
            topic_count: narrowing_topics.len(),
            allowed_priority_mask: 1u8 << (Priority::Immediate as u8),
            reserved: [0; 7],
        };
        let mut first_route = AsterBridgeRouteResult {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeRouteResult>(),
            handle: [0; ID_BYTES],
            source_item: [0; ID_BYTES],
            current_route_epoch: 0,
            commit_status: u32::MAX,
            hop_count: 0,
            reserved: [0; 3],
            current_scope: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_item(node, &first_request, &mut first_route),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(first_route.source_item, source.item_id);
        assert_eq!(first_route.current_route_epoch, 9);
        assert_eq!(first_route.hop_count, 1);
        assert_eq!(first_route.commit_status, 0);
        assert_eq!(
            input_bytes(
                AsterBytes {
                    data: first_route.current_scope.data.cast_const(),
                    len: first_route.current_scope.len,
                },
                "test first route scope",
            )
            .expect("first route scope"),
            bravo.as_str().as_bytes()
        );
        let first_route_handle = first_route.handle;
        assert_eq!(aster_bridge_route_result_free(&mut first_route), STATUS_OK);

        let extend_request = AsterBridgeExtendRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeExtendRequest>(),
            route_handle: first_route_handle,
            authorization_id: second_authorization.id,
            topics: narrowing_topics.as_ptr(),
            topic_count: narrowing_topics.len(),
            allowed_priority_mask: 1u8 << (Priority::Immediate as u8),
            reserved: [0; 7],
        };
        let mut nested_route = AsterBridgeRouteResult {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeRouteResult>(),
            handle: [0; ID_BYTES],
            source_item: [0; ID_BYTES],
            current_route_epoch: 0,
            commit_status: u32::MAX,
            hop_count: 0,
            reserved: [0; 3],
            current_scope: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_extend(node, &extend_request, &mut nested_route),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(nested_route.source_item, source.item_id);
        assert_eq!(nested_route.current_route_epoch, 11);
        assert_eq!(nested_route.hop_count, 2);
        assert_eq!(nested_route.commit_status, 0);
        let nested_handle = nested_route.handle;
        assert_eq!(aster_bridge_route_result_free(&mut nested_route), STATUS_OK);

        // The ordinary application view resolves the authenticated nested
        // route without exposing a sealed envelope or route key. Scope is the
        // compatibility alias for current_scope; origin_scope remains stable.
        let query_request = AsterQueryRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterQueryRequest>(),
            topic: bytes(topic.as_str().as_bytes()),
            scope: bytes(charlie.as_str().as_bytes()),
            logical_key: AsterBytes::default(),
            data_class: u32::MAX,
            include_descendant_scopes: 0,
            include_recoverable_versions: 0,
            include_tombstones: 0,
            reserved: 0,
            limit: 8,
        };
        let mut projection = AsterQuery::default();
        assert_eq!(
            aster_node_query(node, &query_request, &mut projection),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        let mut projection_count = 0;
        assert_eq!(
            aster_query_len(projection, &mut projection_count),
            STATUS_OK
        );
        assert_eq!(projection_count, 1);
        let mut projected = empty_item();
        assert_eq!(aster_query_get(projection, 0, &mut projected), STATUS_OK);
        assert_eq!(projected.item_id, source.item_id);
        assert_eq!(
            owned_contents(&projected.origin_scope, "projected origin scope"),
            alpha.as_str().as_bytes()
        );
        assert_eq!(
            owned_contents(&projected.current_scope, "projected current scope"),
            charlie.as_str().as_bytes()
        );
        assert_eq!(
            owned_contents(&projected.scope, "projected compatibility scope"),
            charlie.as_str().as_bytes()
        );
        assert_eq!(
            owned_contents(&projected.payload, "projected payload"),
            b"payload never exposed by administration"
        );
        assert_eq!(aster_item_free(&mut projected), STATUS_OK);
        assert_eq!(aster_query_close(&mut projection), STATUS_OK);

        let poll_request = AsterPollRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPollRequest>(),
            subscription: bridge_subscription,
            limit: 8,
        };
        let mut deliveries = AsterDeliveries::default();
        assert_eq!(
            aster_node_poll(node, &poll_request, &mut deliveries),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        let mut delivery_count = 0;
        assert_eq!(
            aster_deliveries_len(deliveries, &mut delivery_count),
            STATUS_OK
        );
        assert_eq!(delivery_count, 1);
        let mut delivery = AsterDelivery {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterDelivery>(),
            subscription: 0,
            attempt: 0,
            item: empty_item(),
        };
        assert_eq!(
            aster_deliveries_get(deliveries, 0, &mut delivery),
            STATUS_OK
        );
        assert_eq!(delivery.subscription, bridge_subscription);
        assert_eq!(delivery.item.item_id, source.item_id);
        assert_eq!(
            owned_contents(&delivery.item.origin_scope, "delivery origin scope"),
            alpha.as_str().as_bytes()
        );
        assert_eq!(
            owned_contents(&delivery.item.current_scope, "delivery current scope"),
            charlie.as_str().as_bytes()
        );
        let acknowledgement = AsterAckRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterAckRequest>(),
            subscription: bridge_subscription,
            item_id: delivery.item.item_id,
        };
        assert_eq!(aster_node_acknowledge(node, &acknowledgement), STATUS_OK);
        assert_eq!(aster_delivery_free(&mut delivery), STATUS_OK);
        assert_eq!(aster_deliveries_close(&mut deliveries), STATUS_OK);

        let status_request = AsterBridgeStatusRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeStatusRequest>(),
            id: first_authorization.id,
            reserved: [0; 8],
        };
        let mut authorization_status = AsterBridgeAuthorizationStatus {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeAuthorizationStatus>(),
            id: [0; ID_BYTES],
            authority: [0; ID_BYTES],
            bridge_node: [0; ID_BYTES],
            generation: 0,
            control_sequence: 0,
            source_route_epoch: 0,
            target_route_epoch: 0,
            topic_count: 0,
            allowed_priority_mask: 0,
            max_total_hops: 0,
            applied: 0,
            current: 0,
            enabled: 0,
            usable: 0,
            has_source_route_epoch: 0,
            has_target_route_epoch: 0,
            has_max_total_hops: 0,
            reserved: [0; 7],
            source_scope: AsterOwnedBuffer::default(),
            target_scope: AsterOwnedBuffer::default(),
            topics: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_authorization_status(
                node,
                &status_request,
                &mut authorization_status,
            ),
            STATUS_OK
        );
        assert_eq!(authorization_status.id, first_authorization.id);
        assert_ne!(authorization_status.authority, [0; ID_BYTES]);
        assert_eq!(authorization_status.bridge_node, authority_id);
        assert_eq!(authorization_status.enabled, 1);
        assert_eq!(authorization_status.current, 1);
        assert_eq!(authorization_status.usable, 1);
        assert_eq!(authorization_status.source_route_epoch, 7);
        assert_eq!(authorization_status.target_route_epoch, 9);
        assert_eq!(authorization_status.topic_count, 1);
        assert_eq!(authorization_status.allowed_priority_mask, 0b1100);
        assert_eq!(authorization_status.max_total_hops, 8);
        assert_eq!(
            input_bytes(
                AsterBytes {
                    data: authorization_status.topics.data.cast_const(),
                    len: authorization_status.topics.len,
                },
                "test authorization topics",
            )
            .expect("authorization topics"),
            b"\0\x03ops"
        );
        assert_eq!(
            aster_bridge_authorization_status_free(&mut authorization_status),
            STATUS_OK
        );

        let page_request = AsterBridgePageRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgePageRequest>(),
            after: [0; ID_BYTES],
            limit: 8,
            has_after: 0,
            reserved: [0; 7],
        };
        let mut authorizations = AsterBridgeAuthorizations::default();
        assert_eq!(
            aster_node_bridge_authorizations(node, &page_request, &mut authorizations),
            STATUS_OK
        );
        let mut count = 0;
        assert_eq!(
            aster_bridge_authorizations_len(authorizations, &mut count),
            STATUS_OK
        );
        assert_eq!(count, 2);
        assert_eq!(
            aster_bridge_authorizations_close(&mut authorizations),
            STATUS_OK
        );

        let route_status_request = AsterBridgeStatusRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeStatusRequest>(),
            id: nested_handle,
            reserved: [0; 8],
        };
        let mut route_status = AsterBridgeRouteStatus {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeRouteStatus>(),
            handle: [0; ID_BYTES],
            source_item: [0; ID_BYTES],
            origin_route_epoch: 0,
            current_route_epoch: 0,
            priority: 0,
            hop_count: 0,
            active: 0,
            live: 0,
            reserved: 0,
            origin_scope: AsterOwnedBuffer::default(),
            current_scope: AsterOwnedBuffer::default(),
            topic: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_route_status(node, &route_status_request, &mut route_status),
            STATUS_OK
        );
        assert_eq!(route_status.handle, nested_handle);
        assert_eq!(route_status.source_item, source.item_id);
        assert_eq!(route_status.origin_route_epoch, 7);
        assert_eq!(route_status.current_route_epoch, 11);
        assert_eq!(route_status.priority, u32::from(Priority::Immediate as u8));
        assert_eq!(route_status.hop_count, 2);
        assert_eq!(route_status.active, 1);
        assert_eq!(route_status.live, 1);
        assert_eq!(aster_bridge_route_status_free(&mut route_status), STATUS_OK);

        let mut routes = AsterBridgeRoutes::default();
        assert_eq!(
            aster_node_bridge_routes(node, &page_request, &mut routes),
            STATUS_OK
        );
        assert_eq!(aster_bridge_routes_len(routes, &mut count), STATUS_OK);
        assert_eq!(count, 2);
        assert_eq!(aster_bridge_routes_close(&mut routes), STATUS_OK);

        // Once native authority processing starts, an error consumes the
        // enrollment. The wrong node never receives enrollment bytes.
        let mut wrong_node = open_memory();
        let valid_policy = AsterBridgeEnablePolicy {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeEnablePolicy>(),
            topics: topic_views.as_ptr(),
            topic_count: topic_views.len(),
            allowed_priority_mask: 1u8 << (Priority::Immediate as u8),
            max_total_hops: 8,
            reserved: [0; 6],
        };
        let rejected_status = aster_node_bridge_enable(
            wrong_node,
            &mut rejected_enrollment,
            &valid_policy,
            &mut invalid_output,
        );
        assert_ne!(rejected_status, STATUS_OK);
        assert_eq!(rejected_enrollment.value, 0);
        assert_eq!(aster_node_close(&mut wrong_node), STATUS_OK);

        // One unused enrollment proves owner-close purge semantics while the
        // durable 32-byte IDs/handles remain sufficient after process reopen.
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
        assert_eq!(
            aster_bridge_enrollment_close(&mut purged_enrollment),
            STATUS_CLOSED
        );
        assert_eq!(purged_enrollment.value, 0);

        node = open_path_with_bundle(&database, &bundle);
        authorization_status = AsterBridgeAuthorizationStatus {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeAuthorizationStatus>(),
            id: [0; ID_BYTES],
            authority: [0; ID_BYTES],
            bridge_node: [0; ID_BYTES],
            generation: 0,
            control_sequence: 0,
            source_route_epoch: 0,
            target_route_epoch: 0,
            topic_count: 0,
            allowed_priority_mask: 0,
            max_total_hops: 0,
            applied: 0,
            current: 0,
            enabled: 0,
            usable: 0,
            has_source_route_epoch: 0,
            has_target_route_epoch: 0,
            has_max_total_hops: 0,
            reserved: [0; 7],
            source_scope: AsterOwnedBuffer::default(),
            target_scope: AsterOwnedBuffer::default(),
            topics: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_authorization_status(
                node,
                &status_request,
                &mut authorization_status,
            ),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(authorization_status.usable, 1);
        assert_eq!(
            aster_bridge_authorization_status_free(&mut authorization_status),
            STATUS_OK
        );
        route_status = AsterBridgeRouteStatus {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeRouteStatus>(),
            handle: [0; ID_BYTES],
            source_item: [0; ID_BYTES],
            origin_route_epoch: 0,
            current_route_epoch: 0,
            priority: 0,
            hop_count: 0,
            active: 0,
            live: 0,
            reserved: 0,
            origin_scope: AsterOwnedBuffer::default(),
            current_scope: AsterOwnedBuffer::default(),
            topic: AsterOwnedBuffer::default(),
        };
        assert_eq!(
            aster_node_bridge_route_status(node, &route_status_request, &mut route_status),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(route_status.live, 1);
        assert_eq!(aster_bridge_route_status_free(&mut route_status), STATUS_OK);

        let disable_request = AsterBridgeDisableRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBridgeDisableRequest>(),
            bridge_node: authority_id,
            source_scope: bytes(alpha.as_str().as_bytes()),
            target_scope: bytes(bravo.as_str().as_bytes()),
            reserved: [0; 8],
        };
        let mut disable_result = invalid_output;
        assert_eq!(
            aster_node_bridge_disable(node, &disable_request, &mut disable_result),
            STATUS_OK
        );
        assert_eq!(disable_result.enabled, 0);
        assert_eq!(
            disable_result.generation,
            first_authorization.generation + 1
        );

        assert_eq!(aster_node_close(&mut node), STATUS_OK);
        fs::remove_dir_all(&directory).expect("remove bridge test directory");
    }

    #[test]
    // This one integration scenario intentionally keeps the authority, restart,
    // rollback, wrong-authority, and exclusion lifecycle visible in one flow.
    #[allow(clippy::too_many_lines)]
    fn rekey_boundary_rejects_rollback_and_wrong_authority_and_preserves_exclusion() {
        let scope = Scope::new("mission/team/alpha").expect("test scope");
        let topic = Topic::new("position.current").expect("test topic");
        let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()])
            .expect("test provisioning access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0xa1; 32]).expect("test provisioner");
        let included_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .expect("issue included node")
            .to_bytes()
            .expect("encode included bundle");
        let included_id = bundle_identity(&included_bundle);
        let authority_bundle = provisioner
            .issue_control_authority(2, std::slice::from_ref(&access))
            .expect("issue authority node")
            .to_bytes()
            .expect("encode authority bundle");
        let authority_id = bundle_identity(&authority_bundle);
        let stale_registry = provisioner
            .export_rekey_registry()
            .expect("export generation-two registry");
        let captured_bundle = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .expect("issue captured node")
            .to_bytes()
            .expect("encode captured bundle");
        let captured_id = bundle_identity(&captured_bundle);
        let registry = provisioner
            .export_rekey_registry()
            .expect("export generation-three registry");

        let mut other =
            ReferenceProvisioner::from_seed([0xa2; 32]).expect("other test provisioner");
        other
            .issue_control_authority(1, std::slice::from_ref(&access))
            .expect("issue other authority");
        let wrong_authority_registry = other
            .export_rekey_registry()
            .expect("export wrong-authority registry");

        let topic_views = [bytes(topic.as_str().as_bytes())];
        let recipients = [
            AsterRekeyRecipient {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterRekeyRecipient>(),
                node_id: authority_id,
                access: REKEY_READ_TOPICS,
                reserved: 0,
                topics: topic_views.as_ptr(),
                topic_count: topic_views.len(),
            },
            AsterRekeyRecipient {
                abi_version: ABI_VERSION,
                struct_size: struct_size::<AsterRekeyRecipient>(),
                node_id: included_id,
                access: REKEY_ROUTE_ONLY,
                reserved: 0,
                topics: ptr::null(),
                topic_count: 0,
            },
        ];
        let mut request = AsterRekeyRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterRekeyRequest>(),
            signed_public_registry: bytes(&stale_registry),
            scope: bytes(scope.as_str().as_bytes()),
            minimum_registry_generation: 3,
            new_epoch: 1,
            recipients: recipients.as_ptr(),
            recipient_count: recipients.len(),
        };
        let mut receipt = AsterRekeyReceipt {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterRekeyReceipt>(),
            epoch: 0,
            registry_generation: 0,
            recipient_count: 0,
            control_sequence: 0,
        };
        let mut node = open_memory_with_bundle(&authority_bundle);
        let mut invalid_recipients = recipients;
        invalid_recipients[1].topics = topic_views.as_ptr();
        invalid_recipients[1].topic_count = topic_views.len();
        request.recipients = invalid_recipients.as_ptr();
        assert_eq!(
            aster_node_rekey_scope(node, &request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        request.recipients = recipients.as_ptr();
        request.recipient_count = MAX_REKEY_RECIPIENTS + 1;
        assert_eq!(
            aster_node_rekey_scope(node, &request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        request.recipient_count = recipients.len();
        assert_eq!(
            aster_node_rekey_scope(node, &request, &mut receipt),
            STATUS_SECURITY_ERROR
        );
        request.signed_public_registry = bytes(&wrong_authority_registry);
        request.minimum_registry_generation = 1;
        assert_eq!(
            aster_node_rekey_scope(node, &request, &mut receipt),
            STATUS_SECURITY_ERROR
        );
        request.signed_public_registry = bytes(&registry);
        request.minimum_registry_generation = 3;
        assert_eq!(
            aster_node_rekey_scope(node, &request, &mut receipt),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(receipt.epoch, 1);
        assert_eq!(receipt.registry_generation, 3);
        assert_eq!(receipt.recipient_count, 2);
        assert_eq!(receipt.control_sequence, 1);

        let _published = publish(node, b"fresh boundary data");
        let filter = InterestFilter {
            topics: vec![topic.as_str().to_owned()],
            scopes: vec![scope.as_str().to_owned()],
            min_priority: Priority::Routine as u8,
        };
        let included_inventory = with_node(node, |active| {
            active.authorized_envelopes(included_id, &[], &filter, InventoryPurpose::ServePeer)
        })
        .expect("included inventory");
        assert!(included_inventory.iter().any(|entry| !entry.control));
        let captured_inventory = with_node(node, |active| {
            active.authorized_envelopes(captured_id, &[], &filter, InventoryPurpose::ServePeer)
        })
        .expect("captured inventory");
        assert!(captured_inventory.iter().all(|entry| entry.control));
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    fn blob_streaming_finish_recovers_across_both_persistence_boundaries() {
        let sequence = new_handle().expect("test handle sequence");
        let directory = std::env::temp_dir().join(format!(
            "aster-ffi-blob-recovery-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create test directory");
        let database = directory.join("mesh.db");
        let payload = b"streamed\0blob-data".repeat(1700);

        // Crash boundary one: encrypted chunks and canonical manifest are durable, but the
        // authenticated Blob item has not yet committed to SQLite.
        let mut node = open_path(&database);
        let writer = open_blob_writer(node);
        write_blob(writer, &payload);
        let writer_cell = blob_writer_cell(writer).expect("writer cell");
        let mut writer_guard = lock(&writer_cell.state, "test writer").expect("writer lock");
        let state = writer_guard.as_mut().expect("writer state");
        let (root, config) = blob_storage(node).expect("Blob storage config");
        let scope = state.scope.clone();
        let topic = state.topic.clone();
        state.service = Some(
            with_node(node, |active| {
                active.current_blob_service(&scope, &topic, &root, config)
            })
            .expect("authorized Blob service"),
        );
        let finalized = state.finalize_local().expect("local finalize");
        let finalized_id = finalized.id();
        assert!(
            with_node(node, |active| active.find_authenticated_blob_manifest(
                &topic,
                &scope,
                finalized_id,
                finalized.manifest_bytes(),
                finalized.route_commitment(),
            ))
            .expect("query before publish")
            .is_none()
        );
        drop(writer_guard);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);

        // Replaying the same source resumes/deduplicates the finalized file store and commits the
        // missing manifest item exactly once.
        node = open_path(&database);
        let mut writer = open_blob_writer(node);
        write_blob(writer, &payload);
        let mut first = empty_blob_finish();
        assert_eq!(
            aster_blob_writer_finish(writer, &mut first),
            STATUS_OK,
            "{}",
            LAST_ERROR.with(|slot| slot.borrow().clone())
        );
        assert_eq!(first.blob_id, *finalized_id.as_bytes());
        assert_eq!(aster_blob_writer_close(&mut writer), STATUS_OK);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);

        // Crash boundary two: after SQLite commit, a full replay finds and returns the existing
        // semantic Blob item instead of publishing a duplicate.
        node = open_path(&database);
        writer = open_blob_writer(node);
        write_blob(writer, &payload);
        let mut second = empty_blob_finish();
        assert_eq!(aster_blob_writer_finish(writer, &mut second), STATUS_OK);
        assert_eq!(second.blob_id, first.blob_id);
        assert_eq!(second.receipt.item_id, first.receipt.item_id);
        assert_eq!(aster_blob_writer_close(&mut writer), STATUS_OK);

        let request = AsterBlobReadRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterBlobReadRequest>(),
            topic: bytes(b"imagery.blob"),
            scope: bytes(b"mission/team/alpha"),
            blob_id: second.blob_id,
        };
        let mut reader = AsterBlobReader::default();
        assert_eq!(
            aster_node_blob_reader_open(node, &request, &mut reader),
            STATUS_OK
        );
        let mut restored = Vec::new();
        let mut transfer = [0u8; 2111];
        loop {
            let mut count = 0;
            assert_eq!(
                aster_blob_reader_read(reader, transfer.as_mut_ptr(), transfer.len(), &mut count),
                STATUS_OK
            );
            if count == 0 {
                break;
            }
            restored.extend_from_slice(&transfer[..count]);
        }
        assert_eq!(restored, payload);
        assert_eq!(aster_blob_reader_close(&mut reader), STATUS_OK);
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
        fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn rejects_bad_abi_enum_utf8_and_lengths() {
        let mut node = open_memory();
        let (abi_version, request_size) = versioned::<AsterPublishRequest>();
        let bad_utf8 = [0xff];
        let request = AsterPublishRequest {
            abi_version,
            struct_size: request_size,
            data_class: 99,
            priority: 0,
            topic: bytes(&bad_utf8),
            scope: bytes(b"scope"),
            logical_key: bytes(b"key"),
            payload: AsterBytes::default(),
            ttl_ms: 0,
            has_ttl: 0,
            tombstone: 0,
            reserved: [0; 6],
        };
        let mut receipt = AsterPublishReceipt {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishReceipt>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            effective_priority: 0,
            reserved: [0; 6],
        };
        assert_eq!(
            aster_node_publish(node, &request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        let mut blob_request = request;
        blob_request.data_class = 3;
        blob_request.topic = bytes(b"document.attachment");
        assert_eq!(
            aster_node_publish(node, &blob_request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        let mut wrong_abi = request;
        wrong_abi.abi_version = ABI_VERSION + 1;
        assert_eq!(
            aster_node_publish(node, &wrong_abi, &mut receipt),
            STATUS_ABI_MISMATCH
        );
        let mut utf8_request = request;
        utf8_request.data_class = 0;
        assert_eq!(
            aster_node_publish(node, &utf8_request, &mut receipt),
            STATUS_INVALID_UTF8
        );
        let mut null_request = request;
        null_request.data_class = 0;
        null_request.topic = AsterBytes {
            data: ptr::null(),
            len: 1,
        };
        assert_eq!(
            aster_node_publish(node, &null_request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    fn repeated_open_close_and_zeroize_invalidate_handles() {
        for byte in 10..30 {
            let mut node = open_memory();
            publish(node, b"value");
            if byte % 2 == 0 {
                assert_eq!(aster_node_zeroize(&mut node), STATUS_OK);
            } else {
                assert_eq!(aster_node_close(&mut node), STATUS_OK);
            }
            assert_eq!(node.value, 0);
            assert_eq!(
                aster_node_get_emission(node, ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
        }
    }

    #[test]
    fn contains_panics_and_rejects_misalignment_and_oversize() {
        assert_eq!(
            boundary(|| -> Result<(), FfiError> { panic!("contained test panic") }),
            STATUS_PANIC
        );

        let mut node = open_memory();
        let mut receipt = AsterPublishReceipt {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishReceipt>(),
            item_id: [0; ID_BYTES],
            publisher: [0; ID_BYTES],
            causal_counter: 0,
            event_sequence: 0,
            has_event_sequence: 0,
            effective_priority: 0,
            reserved: [0; 6],
        };
        let mut storage =
            vec![0u8; size_of::<AsterPublishRequest>() + align_of::<AsterPublishRequest>()];
        let base = storage.as_mut_ptr() as usize;
        let alignment = align_of::<AsterPublishRequest>();
        let aligned = (alignment - (base % alignment)) % alignment;
        let misaligned = storage[aligned + 1..]
            .as_ptr()
            .cast::<AsterPublishRequest>();
        assert_eq!(
            aster_node_publish(node, misaligned, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );

        let mut request = AsterPublishRequest {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<AsterPublishRequest>(),
            data_class: 0,
            priority: 0,
            topic: AsterBytes {
                data: ptr::NonNull::<u8>::dangling().as_ptr(),
                len: MAX_INPUT_BYTES + 1,
            },
            scope: bytes(b"scope"),
            logical_key: bytes(b"key"),
            payload: AsterBytes::default(),
            ttl_ms: 0,
            has_ttl: 0,
            tombstone: 0,
            reserved: [0; 6],
        };
        assert_eq!(
            aster_node_publish(node, &request, &mut receipt),
            STATUS_INVALID_ARGUMENT
        );
        request.topic = bytes(b"position.current");
        receipt.abi_version += 1;
        assert_eq!(
            aster_node_publish(node, &request, &mut receipt),
            STATUS_ABI_MISMATCH
        );
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
    }

    #[test]
    fn close_is_safe_with_concurrent_calls() {
        let mut node = open_memory();
        let barrier = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let copied = node;
                thread::spawn(move || {
                    barrier.wait();
                    let mut threshold = 0;
                    aster_node_get_emission(copied, &mut threshold)
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(aster_node_close(&mut node), STATUS_OK);
        for worker in workers {
            let status = worker.join().unwrap();
            assert!(matches!(status, STATUS_OK | STATUS_CLOSED));
        }
    }
}
