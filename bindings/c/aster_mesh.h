/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ASTER_MESH_H
#define ASTER_MESH_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define ASTER_ABI_VERSION 2u
#define ASTER_BLOB_SEGMENT_BYTES 1048576u
#define ASTER_BLOB_READ_PAGE_BYTES 524288u
#define ASTER_STATE 0u
#define ASTER_EVENT 1u
#define ASTER_RECORD 2u
#define ASTER_BLOB 3u
#define ASTER_RECEIVE_ONLY 4u
#define ASTER_ROUTINE 0u
#define ASTER_PRIORITY 1u
#define ASTER_IMMEDIATE 2u
#define ASTER_FLASH 3u
#define ASTER_OK 0u
#define ASTER_INVALID_ARGUMENT 1u
#define ASTER_ABI_MISMATCH 2u
#define ASTER_INVALID_UTF8 3u
#define ASTER_NOT_FOUND 4u
#define ASTER_CLOSED 5u
#define ASTER_STATE_UNAVAILABLE 6u
#define ASTER_QUOTA_EXCEEDED 7u
#define ASTER_CONFLICT 8u
#define ASTER_SECURITY_ERROR 9u
#define ASTER_STORAGE_ERROR 10u
#define ASTER_UNSUPPORTED 11u
#define ASTER_EXPIRED_OR_RETIRED 12u
#define ASTER_SESSION_FENCED 13u
#define ASTER_SEQUENCE_GAP 14u
#define ASTER_SEQUENCE_RETIRED 15u
#define ASTER_RECOVERY_REQUIRED 16u
#define ASTER_POLICY_UNSETTLED 17u
#define ASTER_PANIC 254u
#define ASTER_INTERNAL_ERROR 255u
typedef uint64_t AsterHandle;
typedef struct AsterBytes {
    const uint8_t * data;
    size_t len;
} AsterBytes;

typedef struct AsterOwnedBuffer {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t allocation;
    uint8_t * data;
    size_t len;
} AsterOwnedBuffer;

typedef struct AsterNodeOptions {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterBytes state_path;
    AsterBytes provisioning_path;
    uint64_t max_items;
    uint64_t max_bytes;
    uint64_t max_blob_bytes;
    uint64_t max_blob_chunks;
    uint64_t max_blob_variants;
    uint32_t emission_threshold;
} AsterNodeOptions;

typedef struct AsterClient {
    AsterBytes client_id;
    uint64_t session;
} AsterClient;

typedef struct AsterRecoveryRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterClient client;
    AsterBytes claim_nonce;
} AsterRecoveryRequest;

typedef struct AsterRecovery {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t session;
    uint64_t allocated_through;
    uint64_t snapshot_revision;
    AsterHandle results;
} AsterRecovery;

typedef struct AsterCompleteRecoveryRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterClient client;
    uint64_t snapshot_revision;
} AsterCompleteRecoveryRequest;

typedef struct AsterEventResultRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterClient client;
    uint64_t sequence;
} AsterEventResultRequest;

typedef struct AsterPublishRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t data_class;
    uint32_t priority;
    AsterBytes operation_key;
    AsterClient client;
    uint64_t sequence;
    AsterBytes topic;
    AsterBytes scope;
    AsterBytes logical_key;
    AsterBytes payload;
    uint8_t predecessor[32];
    uint8_t has_predecessor;
    uint8_t tombstone;
    uint8_t has_ttl;
    uint64_t ttl_ms;
} AsterPublishRequest;

typedef struct AsterPublishReceipt {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t item_id[32];
    uint8_t blob_id[32];
    uint8_t publisher[32];
    uint64_t publisher_counter;
    uint64_t sequence;
    uint64_t acceptance_marker;
    uint64_t total_len;
    uint64_t ttl_ms;
    uint8_t has_ttl;
    uint8_t inserted;
    uint8_t content_retired;
} AsterPublishReceipt;

typedef struct AsterQueryRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t data_class;
    AsterBytes topic;
    AsterBytes scope;
    AsterBytes logical_key;
    uint8_t include_descendant_scopes;
    uint8_t include_recoverable_versions;
    uint64_t after_acceptance_marker;
    uint64_t before_acceptance_marker;
    uint64_t limit;
} AsterQueryRequest;

typedef struct AsterResultInfo {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t len;
    uint64_t scanned_through;
    uint8_t has_more;
} AsterResultInfo;

typedef struct AsterEntry {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t item_count;
    uint8_t id[32];
    uint64_t attempt;
    uint32_t kind;
    uint32_t retirement_reason;
    uint64_t retirement_generation;
    uint8_t has_guard;
    AsterOwnedBuffer topic;
    AsterOwnedBuffer scope;
    AsterOwnedBuffer logical_key;
    AsterOwnedBuffer sibling_ids;
    AsterOwnedBuffer token;
} AsterEntry;

typedef struct AsterItem {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t id[32];
    uint8_t blob_id[32];
    uint8_t publisher[32];
    uint64_t publisher_counter;
    uint32_t data_class;
    uint32_t priority;
    uint32_t disposition;
    uint64_t event_sequence;
    uint64_t acceptance_marker;
    uint64_t total_len;
    uint64_t ttl_ms;
    uint8_t has_ttl;
    uint8_t tombstone;
    AsterOwnedBuffer topic;
    AsterOwnedBuffer scope;
    AsterOwnedBuffer logical_key;
    AsterOwnedBuffer payload;
    AsterOwnedBuffer media_type;
    AsterOwnedBuffer schema_id;
} AsterItem;

typedef struct AsterSubscribeRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t data_class;
    AsterClient client;
    AsterBytes operation_key;
    AsterBytes topic;
    AsterBytes scope;
    uint8_t include_descendant_scopes;
} AsterSubscribeRequest;

typedef struct AsterSubscription {
    uint8_t id[32];
    uint32_t data_class;
} AsterSubscription;

typedef struct AsterPollRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterSubscription subscription;
    AsterClient client;
    uint64_t delivery_limit;
    uint64_t scan_limit;
} AsterPollRequest;

typedef struct AsterAckRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterSubscription subscription;
    AsterClient client;
    uint8_t id[32];
    AsterBytes token;
} AsterAckRequest;

typedef struct AsterUnsubscribeRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterSubscription subscription;
    AsterClient client;
} AsterUnsubscribeRequest;

typedef struct AsterResolveRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterHandle guard;
    uint64_t entry;
    AsterBytes operation_key;
    AsterBytes payload;
    uint32_t priority;
    uint8_t tombstone;
} AsterResolveRequest;

typedef struct AsterBlobPublishOptions {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterBytes operation_key;
    AsterBytes topic;
    AsterBytes scope;
    AsterBytes media_type;
    AsterBytes schema_id;
    uint32_t priority;
    uint64_t total_len;
    uint64_t ttl_ms;
    uint8_t has_ttl;
} AsterBlobPublishOptions;

typedef struct AsterBlobWriterInfo {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterHandle writer;
    uint64_t durable_offset;
} AsterBlobWriterInfo;

typedef struct AsterBlobReadRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterBytes topic;
    AsterBytes scope;
    uint8_t blob_id[32];
} AsterBlobReadRequest;

typedef struct AsterPeerSnapshot {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t peer[32];
    uint64_t contacts;
    uint32_t authorization;
    uint32_t last_contact;
} AsterPeerSnapshot;

typedef struct AsterPeerRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t peer[32];
} AsterPeerRequest;

typedef struct AsterDeliveryStatus {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t subscriptions;
    uint64_t pending_deliveries;
    uint64_t acknowledged_deliveries;
    uint64_t delivery_cursors;
    uint64_t selector_generation;
} AsterDeliveryStatus;

typedef struct AsterRekeyRecipient {
    uint8_t node_id[32];
    const AsterBytes * topics;
    size_t topic_count;
} AsterRekeyRecipient;

typedef struct AsterRekeyRequest {
    uint32_t abi_version;
    uint32_t struct_size;
    AsterBytes signed_public_registry;
    uint64_t minimum_registry_generation;
    AsterBytes scope;
    uint64_t epoch;
    const AsterRekeyRecipient * recipients;
    size_t recipient_count;
} AsterRekeyRequest;

typedef struct AsterControlReceipt {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t transfer_id[32];
    uint64_t sequence;
    uint64_t activated;
    uint8_t emitted;
} AsterControlReceipt;

/* Exported operations. See README.md for contracts and ownership. */
uint32_t aster_abi_version(void);
uint16_t aster_protocol_version(void);
uint16_t aster_replication_wire_version(void);
uint16_t aster_default_semantic_version(void);
uint16_t aster_highest_supported_semantic_version(void);
uint32_t aster_last_error(AsterOwnedBuffer *out);
uint32_t aster_buffer_free(AsterOwnedBuffer *out);
uint32_t aster_node_options_init(AsterNodeOptions *out);
uint32_t aster_node_open(const AsterNodeOptions *options, uint64_t *out);
uint32_t aster_node_close(uint64_t *out);
uint32_t aster_node_zeroize(uint64_t *out);
uint32_t aster_node_begin_recovery(uint64_t node, const AsterRecoveryRequest *request, AsterRecovery *out);
uint32_t aster_node_complete_recovery(uint64_t node, const AsterCompleteRecoveryRequest *request);
uint32_t aster_node_acknowledge_publication(uint64_t node, const AsterEventResultRequest *r);
uint32_t aster_node_abandon_publication(uint64_t node, const AsterEventResultRequest *r);
uint32_t aster_node_publish(uint64_t node, const AsterPublishRequest *request, AsterPublishReceipt *out);
uint32_t aster_node_query(uint64_t node, const AsterQueryRequest *request, uint64_t *out);
uint32_t aster_node_conflicts(uint64_t node, const AsterQueryRequest *r, uint64_t *out);
uint32_t aster_node_resolve(uint64_t node, const AsterResolveRequest *request, AsterPublishReceipt *out);
uint32_t aster_node_subscribe(uint64_t node, const AsterSubscribeRequest *request, AsterSubscription *out);
uint32_t aster_node_poll(uint64_t node, const AsterPollRequest *request, uint64_t *out);
uint32_t aster_node_acknowledge(uint64_t node, const AsterAckRequest *request);
uint32_t aster_node_unsubscribe(uint64_t node, const AsterUnsubscribeRequest *request);
uint32_t aster_node_delivery_status(uint64_t node, uint32_t data_class, AsterDeliveryStatus *out);
uint32_t aster_node_blob_writer_open(uint64_t node, const AsterBlobPublishOptions *options, AsterBlobWriterInfo *out);
/* Nonempty writes must fit within the current 1 MiB segment. */
uint32_t aster_blob_writer_write(uint64_t node, uint64_t writer, uint64_t offset, AsterBytes bytes);
uint32_t aster_blob_writer_finish(uint64_t node, uint64_t writer, AsterPublishReceipt *out);
uint32_t aster_blob_writer_close(uint64_t node, uint64_t *out);
uint32_t aster_node_blob_reader_open(uint64_t node, const AsterBlobReadRequest *request, uint64_t *out);
uint32_t aster_blob_reader_read(uint64_t node, uint64_t reader, uint64_t max_bytes, AsterOwnedBuffer *out);
uint32_t aster_blob_reader_close(uint64_t node, uint64_t *out);
uint32_t aster_result_info(uint64_t node, uint64_t result, AsterResultInfo *out);
uint32_t aster_result_entry(uint64_t node, uint64_t result, uint64_t entry, AsterEntry *out);
uint32_t aster_result_item(uint64_t node, uint64_t result, uint64_t entry, uint64_t item, AsterItem *out);
uint32_t aster_result_receipt(uint64_t node, uint64_t result, uint64_t item, AsterPublishReceipt *out);
uint32_t aster_result_peer(uint64_t node, uint64_t result, uint64_t item, AsterPeerSnapshot *out);
uint32_t aster_result_close(uint64_t node, uint64_t *out);
uint32_t aster_item_free(AsterItem *out);
uint32_t aster_entry_free(AsterEntry *out);
uint32_t aster_node_set_emission(uint64_t node, uint32_t threshold);
uint32_t aster_node_get_emission(uint64_t node, uint32_t *out);
uint32_t aster_node_peers(uint64_t node, uint64_t *out);
uint32_t aster_node_peer_status(uint64_t node, const AsterPeerRequest *request, AsterPeerSnapshot *out);
uint32_t aster_node_rekey_scope(uint64_t node, const AsterRekeyRequest *request, AsterControlReceipt *out);
#ifdef __cplusplus
}
#endif
#endif
