//! ABI v2 layouts. Keep synchronized with `bindings/c/aster_mesh.h`.
use super::{ABI_VERSION, struct_size};
// Initialize each field through its typed Default, including nested ABI headers.
macro_rules! abi_default {
    ($name:ident { $($field:ident),* $(,)? }) => {
        impl Default for $name {
            fn default() -> Self {
                Self {
                    abi_version: ABI_VERSION,
                    struct_size: struct_size::<Self>(),
                    $($field: Default::default(),)*
                }
            }
        }
    };
}

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

abi_default!(AsterOwnedBuffer {
    allocation,
    data,
    len,
});

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

abi_default!(AsterNodeOptions {
    state_path,
    provisioning_path,
    max_items,
    max_bytes,
    max_blob_bytes,
    max_blob_chunks,
    max_blob_variants,
    emission_threshold,
});

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

abi_default!(AsterRecoveryRequest {
    client,
    claim_nonce,
});

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

abi_default!(AsterRecovery {
    session,
    allocated_through,
    snapshot_revision,
    results,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterCompleteRecoveryRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub client: AsterClient,
    pub snapshot_revision: u64,
}

abi_default!(AsterCompleteRecoveryRequest {
    client,
    snapshot_revision,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterEventResultRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub client: AsterClient,
    pub sequence: u64,
}

abi_default!(AsterEventResultRequest { client, sequence });

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

abi_default!(AsterPublishRequest {
    data_class,
    priority,
    operation_key,
    client,
    sequence,
    topic,
    scope,
    logical_key,
    payload,
    predecessor,
    has_predecessor,
    tombstone,
    has_ttl,
    ttl_ms,
});

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

abi_default!(AsterPublishReceipt {
    item_id,
    blob_id,
    publisher,
    publisher_counter,
    sequence,
    acceptance_marker,
    total_len,
    ttl_ms,
    has_ttl,
    inserted,
    content_retired,
});

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

abi_default!(AsterQueryRequest {
    data_class,
    topic,
    scope,
    logical_key,
    include_descendant_scopes,
    include_recoverable_versions,
    after_acceptance_marker,
    before_acceptance_marker,
    limit,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterResultInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub len: u64,
    pub scanned_through: u64,
    pub has_more: u8,
}

abi_default!(AsterResultInfo {
    len,
    scanned_through,
    has_more,
});

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

abi_default!(AsterEntry {
    item_count,
    id,
    attempt,
    kind,
    retirement_reason,
    retirement_generation,
    has_guard,
    topic,
    scope,
    logical_key,
    sibling_ids,
    token,
});

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

abi_default!(AsterItem {
    id,
    blob_id,
    publisher,
    publisher_counter,
    data_class,
    priority,
    disposition,
    event_sequence,
    acceptance_marker,
    total_len,
    ttl_ms,
    has_ttl,
    tombstone,
    topic,
    scope,
    logical_key,
    payload,
    media_type,
    schema_id,
});

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

abi_default!(AsterSubscribeRequest {
    data_class,
    client,
    operation_key,
    topic,
    scope,
    include_descendant_scopes,
});

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

abi_default!(AsterPollRequest {
    subscription,
    client,
    delivery_limit,
    scan_limit,
});

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

abi_default!(AsterAckRequest {
    subscription,
    client,
    id,
    token,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterUnsubscribeRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub subscription: AsterSubscription,
    pub client: AsterClient,
}

abi_default!(AsterUnsubscribeRequest {
    subscription,
    client,
});

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

abi_default!(AsterResolveRequest {
    guard,
    entry,
    operation_key,
    payload,
    priority,
    tombstone,
});

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

abi_default!(AsterBlobPublishOptions {
    operation_key,
    topic,
    scope,
    media_type,
    schema_id,
    priority,
    total_len,
    ttl_ms,
    has_ttl,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobWriterInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub writer: AsterHandle,
    pub durable_offset: u64,
}

abi_default!(AsterBlobWriterInfo {
    writer,
    durable_offset,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterBlobReadRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub topic: AsterBytes,
    pub scope: AsterBytes,
    pub blob_id: [u8; 32],
}

abi_default!(AsterBlobReadRequest {
    topic,
    scope,
    blob_id,
});

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

abi_default!(AsterPeerSnapshot {
    peer,
    contacts,
    authorization,
    last_contact,
});

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsterPeerRequest {
    pub abi_version: u32,
    pub struct_size: u32,
    pub peer: [u8; 32],
}

abi_default!(AsterPeerRequest { peer });

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

abi_default!(AsterDeliveryStatus {
    subscriptions,
    pending_deliveries,
    acknowledged_deliveries,
    delivery_cursors,
    selector_generation,
});

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

abi_default!(AsterRekeyRequest {
    signed_public_registry,
    minimum_registry_generation,
    scope,
    epoch,
    recipients,
    recipient_count,
});

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

abi_default!(AsterControlReceipt {
    transfer_id,
    sequence,
    activated,
    emitted,
});
