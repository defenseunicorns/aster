//! ABI v2 layouts. Keep synchronized with `bindings/c/aster_mesh.h`.
use super::{ABI_VERSION, struct_size};
pub type AsterHandle = u64;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBytes {
    pub data: *const u8,
    pub len: usize,
}

impl Default for AsterBytes {
    fn default() -> Self {
        Self {
            data: std::ptr::null(),
            len: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterOwnedBuffer {
    pub abi_version: u32,
    pub struct_size: u32,
    pub allocation: u64,
    pub data: *mut u8,
    pub len: usize,
}

impl Default for AsterOwnedBuffer {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            allocation: Default::default(),
            data: std::ptr::null_mut(),
            len: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterNodeOptions {
    pub abi_version: u32,
    pub struct_size: u32,
    pub state_path: AsterBytes,
    pub provisioning_path: AsterBytes,
    pub max_items: u64,
    pub max_bytes: u64,
    pub max_blob_bytes: u64,
    pub max_blob_chunks: u64,
    pub max_blob_variants: u64,
    pub emission_threshold: u32,
}

impl Default for AsterNodeOptions {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            state_path: AsterBytes::default(),
            provisioning_path: AsterBytes::default(),
            max_items: Default::default(),
            max_bytes: Default::default(),
            max_blob_bytes: Default::default(),
            max_blob_chunks: Default::default(),
            max_blob_variants: Default::default(),
            emission_threshold: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterClient {
    pub client_id: AsterBytes,
    pub session: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRecoveryRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub client: AsterClient,
    pub claim_nonce: AsterBytes,
}

impl Default for AsterRecoveryRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            client: AsterClient::default(),
            claim_nonce: AsterBytes::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRecovery {
    pub abi_version: u32,
    pub struct_size: u32,
    pub session: u64,
    pub allocated_through: u64,
    pub snapshot_revision: u64,
    pub results: AsterHandle,
}

impl Default for AsterRecovery {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            session: Default::default(),
            allocated_through: Default::default(),
            snapshot_revision: Default::default(),
            results: AsterHandle::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterCompleteRecoveryRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub client: AsterClient,
    pub snapshot_revision: u64,
}

impl Default for AsterCompleteRecoveryRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            client: AsterClient::default(),
            snapshot_revision: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterEventResultRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub client: AsterClient,
    pub sequence: u64,
}

impl Default for AsterEventResultRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            client: AsterClient::default(),
            sequence: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPublishRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub data_class: u32,
    pub priority: u32,
    pub operation_key: AsterBytes,
    pub client: AsterClient,
    pub sequence: u64,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub logical_key: AsterBytes,
    pub payload: AsterBytes,
    pub predecessor: [u8; 32],
    pub has_predecessor: u8,
    pub tombstone: u8,
    pub has_ttl: u8,
    pub ttl_ms: u64,
}

impl Default for AsterPublishRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            data_class: Default::default(),
            priority: Default::default(),
            operation_key: AsterBytes::default(),
            client: AsterClient::default(),
            sequence: Default::default(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            logical_key: AsterBytes::default(),
            payload: AsterBytes::default(),
            predecessor: [0; 32],
            has_predecessor: Default::default(),
            tombstone: Default::default(),
            has_ttl: Default::default(),
            ttl_ms: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPublishReceipt {
    pub abi_version: u32,
    pub struct_size: u32,
    pub item_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub publisher: [u8; 32],
    pub publisher_counter: u64,
    pub sequence: u64,
    pub acceptance_marker: u64,
    pub total_len: u64,
    pub ttl_ms: u64,
    pub has_ttl: u8,
    pub inserted: u8,
    pub content_retired: u8,
}

impl Default for AsterPublishReceipt {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            item_id: [0; 32],
            blob_id: [0; 32],
            publisher: [0; 32],
            publisher_counter: Default::default(),
            sequence: Default::default(),
            acceptance_marker: Default::default(),
            total_len: Default::default(),
            ttl_ms: Default::default(),
            has_ttl: Default::default(),
            inserted: Default::default(),
            content_retired: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterQueryRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub data_class: u32,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub logical_key: AsterBytes,
    pub include_descendant_scopes: u8,
    pub include_recoverable_versions: u8,
    pub after_acceptance_marker: u64,
    pub before_acceptance_marker: u64,
    pub limit: u64,
}

impl Default for AsterQueryRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            data_class: Default::default(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            logical_key: AsterBytes::default(),
            include_descendant_scopes: Default::default(),
            include_recoverable_versions: Default::default(),
            after_acceptance_marker: Default::default(),
            before_acceptance_marker: Default::default(),
            limit: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterResultInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub len: u64,
    pub scanned_through: u64,
    pub has_more: u8,
}

impl Default for AsterResultInfo {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            len: Default::default(),
            scanned_through: Default::default(),
            has_more: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterEntry {
    pub abi_version: u32,
    pub struct_size: u32,
    pub item_count: u64,
    pub id: [u8; 32],
    pub attempt: u64,
    pub kind: u32,
    pub retirement_reason: u32,
    pub retirement_generation: u64,
    pub has_guard: u8,
    pub topic: AsterOwnedBuffer,
    pub scope: AsterOwnedBuffer,
    pub logical_key: AsterOwnedBuffer,
    pub sibling_ids: AsterOwnedBuffer,
    pub token: AsterOwnedBuffer,
}

impl Default for AsterEntry {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            item_count: Default::default(),
            id: [0; 32],
            attempt: Default::default(),
            kind: Default::default(),
            retirement_reason: Default::default(),
            retirement_generation: Default::default(),
            has_guard: Default::default(),
            topic: AsterOwnedBuffer::default(),
            scope: AsterOwnedBuffer::default(),
            logical_key: AsterOwnedBuffer::default(),
            sibling_ids: AsterOwnedBuffer::default(),
            token: AsterOwnedBuffer::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterItem {
    pub abi_version: u32,
    pub struct_size: u32,
    pub id: [u8; 32],
    pub blob_id: [u8; 32],
    pub publisher: [u8; 32],
    pub publisher_counter: u64,
    pub data_class: u32,
    pub priority: u32,
    pub disposition: u32,
    pub event_sequence: u64,
    pub acceptance_marker: u64,
    pub total_len: u64,
    pub ttl_ms: u64,
    pub has_ttl: u8,
    pub tombstone: u8,
    pub topic: AsterOwnedBuffer,
    pub scope: AsterOwnedBuffer,
    pub logical_key: AsterOwnedBuffer,
    pub payload: AsterOwnedBuffer,
    pub media_type: AsterOwnedBuffer,
    pub schema_id: AsterOwnedBuffer,
}

impl Default for AsterItem {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            id: [0; 32],
            blob_id: [0; 32],
            publisher: [0; 32],
            publisher_counter: Default::default(),
            data_class: Default::default(),
            priority: Default::default(),
            disposition: Default::default(),
            event_sequence: Default::default(),
            acceptance_marker: Default::default(),
            total_len: Default::default(),
            ttl_ms: Default::default(),
            has_ttl: Default::default(),
            tombstone: Default::default(),
            topic: AsterOwnedBuffer::default(),
            scope: AsterOwnedBuffer::default(),
            logical_key: AsterOwnedBuffer::default(),
            payload: AsterOwnedBuffer::default(),
            media_type: AsterOwnedBuffer::default(),
            schema_id: AsterOwnedBuffer::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterSubscribeRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub data_class: u32,
    pub client: AsterClient,
    pub operation_key: AsterBytes,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub include_descendant_scopes: u8,
}

impl Default for AsterSubscribeRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            data_class: Default::default(),
            client: AsterClient::default(),
            operation_key: AsterBytes::default(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            include_descendant_scopes: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AsterSubscription {
    pub id: [u8; 32],
    pub data_class: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPollRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub subscription: AsterSubscription,
    pub client: AsterClient,
    pub delivery_limit: u64,
    pub scan_limit: u64,
}

impl Default for AsterPollRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            subscription: AsterSubscription::default(),
            client: AsterClient::default(),
            delivery_limit: Default::default(),
            scan_limit: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterAckRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub subscription: AsterSubscription,
    pub client: AsterClient,
    pub id: [u8; 32],
    pub token: AsterBytes,
}

impl Default for AsterAckRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            subscription: AsterSubscription::default(),
            client: AsterClient::default(),
            id: [0; 32],
            token: AsterBytes::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterUnsubscribeRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub subscription: AsterSubscription,
    pub client: AsterClient,
}

impl Default for AsterUnsubscribeRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            subscription: AsterSubscription::default(),
            client: AsterClient::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterResolveRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub guard: AsterHandle,
    pub entry: u64,
    pub operation_key: AsterBytes,
    pub payload: AsterBytes,
    pub priority: u32,
    pub tombstone: u8,
}

impl Default for AsterResolveRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            guard: AsterHandle::default(),
            entry: Default::default(),
            operation_key: AsterBytes::default(),
            payload: AsterBytes::default(),
            priority: Default::default(),
            tombstone: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobPublishOptions {
    pub abi_version: u32,
    pub struct_size: u32,
    pub operation_key: AsterBytes,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub media_type: AsterBytes,
    pub schema_id: AsterBytes,
    pub priority: u32,
    pub total_len: u64,
    pub ttl_ms: u64,
    pub has_ttl: u8,
}

impl Default for AsterBlobPublishOptions {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            operation_key: AsterBytes::default(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            media_type: AsterBytes::default(),
            schema_id: AsterBytes::default(),
            priority: Default::default(),
            total_len: Default::default(),
            ttl_ms: Default::default(),
            has_ttl: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobWriterInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub writer: AsterHandle,
    pub durable_offset: u64,
}

impl Default for AsterBlobWriterInfo {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            writer: AsterHandle::default(),
            durable_offset: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobReadRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub blob_id: [u8; 32],
}

impl Default for AsterBlobReadRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            topic: AsterBytes::default(),
            scope: AsterBytes::default(),
            blob_id: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPeerSnapshot {
    pub abi_version: u32,
    pub struct_size: u32,
    pub peer: [u8; 32],
    pub contacts: u64,
    pub authorization: u32,
    pub last_contact: u32,
}

impl Default for AsterPeerSnapshot {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            peer: [0; 32],
            contacts: Default::default(),
            authorization: Default::default(),
            last_contact: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPeerRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub peer: [u8; 32],
}

impl Default for AsterPeerRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            peer: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterDeliveryStatus {
    pub abi_version: u32,
    pub struct_size: u32,
    pub subscriptions: u64,
    pub pending_deliveries: u64,
    pub acknowledged_deliveries: u64,
    pub delivery_cursors: u64,
    pub selector_generation: u64,
}

impl Default for AsterDeliveryStatus {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            subscriptions: Default::default(),
            pending_deliveries: Default::default(),
            acknowledged_deliveries: Default::default(),
            delivery_cursors: Default::default(),
            selector_generation: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRekeyRecipient {
    pub node_id: [u8; 32],
    pub topics: *const AsterBytes,
    pub topic_count: usize,
}

impl Default for AsterRekeyRecipient {
    fn default() -> Self {
        Self {
            node_id: [0; 32],
            topics: std::ptr::null(),
            topic_count: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterRekeyRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub signed_public_registry: AsterBytes,
    pub minimum_registry_generation: u64,
    pub scope: AsterBytes,
    pub epoch: u64,
    pub recipients: *const AsterRekeyRecipient,
    pub recipient_count: usize,
}

impl Default for AsterRekeyRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            signed_public_registry: AsterBytes::default(),
            minimum_registry_generation: Default::default(),
            scope: AsterBytes::default(),
            epoch: Default::default(),
            recipients: std::ptr::null(),
            recipient_count: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterControlReceipt {
    pub abi_version: u32,
    pub struct_size: u32,
    pub transfer_id: [u8; 32],
    pub sequence: u64,
    pub activated: u64,
    pub emitted: u8,
}

impl Default for AsterControlReceipt {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: struct_size::<Self>(),
            transfer_id: [0; 32],
            sequence: Default::default(),
            activated: Default::default(),
            emitted: Default::default(),
        }
    }
}
