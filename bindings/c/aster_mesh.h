#ifndef ASTER_MESH_H
#define ASTER_MESH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(ASTER_MESH_BUILDING)
#    define ASTER_API __declspec(dllexport)
#  else
#    define ASTER_API __declspec(dllimport)
#  endif
#else
#  define ASTER_API __attribute__((visibility("default")))
#endif

#define ASTER_ABI_VERSION 1u
#define ASTER_REPLICATION_WIRE_VERSION 1u
#define ASTER_DEFAULT_SEMANTIC_VERSION 9u
#define ASTER_HIGHEST_SUPPORTED_SEMANTIC_VERSION 9u
#define ASTER_ID_BYTES 32u
#define ASTER_BATCH_MIN_ITEMS 2u
#define ASTER_BATCH_MAX_ITEMS 64u
#define ASTER_DATA_CLASS_ANY UINT32_MAX
/* Initialize every versioned input/output before its call. */
#ifdef __cplusplus
#  define ASTER_STRUCT_INIT(type)                                                     \
    []() {                                                                           \
        type value{};                                                                \
        value.abi_version = ASTER_ABI_VERSION;                                        \
        value.struct_size = static_cast<uint32_t>(sizeof(type));                      \
        return value;                                                                \
    }()
#else
#  define ASTER_STRUCT_INIT(type)                                                     \
    { .abi_version = ASTER_ABI_VERSION, .struct_size = (uint32_t)sizeof(type) }
#endif

typedef uint32_t aster_status_t;
enum {
    ASTER_OK = 0,
    ASTER_INVALID_ARGUMENT = 1,
    ASTER_ABI_MISMATCH = 2,
    ASTER_INVALID_UTF8 = 3,
    ASTER_NOT_FOUND = 4,
    ASTER_CLOSED = 5,
    ASTER_ZEROIZED = 6,
    ASTER_QUOTA_EXCEEDED = 7,
    ASTER_STALE_CONFLICT = 8,
    ASTER_SECURITY_ERROR = 9,
    ASTER_STORAGE_ERROR = 10,
    ASTER_PANIC = 254,
    ASTER_INTERNAL_ERROR = 255
};

typedef uint32_t aster_data_class_t;
enum {
    ASTER_STATE = 0,
    ASTER_EVENT = 1,
    ASTER_RECORD = 2,
    ASTER_BLOB = 3
};

typedef uint32_t aster_priority_t;
enum {
    ASTER_ROUTINE = 0,
    ASTER_PRIORITY = 1,
    ASTER_IMMEDIATE = 2,
    ASTER_FLASH = 3,
    ASTER_RECEIVE_ONLY = 4
};

typedef uint32_t aster_batch_policy_t;
enum {
    /* Retained state and record items are also published individually. */
    ASTER_BATCH_RETAINED_DUAL = 0,
    /* Every item is visible only through the atomic batch. */
    ASTER_BATCH_ONLY = 1
};

/* Bridge policies use an explicit nonzero subset of these four bits. */
typedef uint8_t aster_priority_mask_t;
enum {
    ASTER_PRIORITY_MASK_ROUTINE = 1u << ASTER_ROUTINE,
    ASTER_PRIORITY_MASK_PRIORITY = 1u << ASTER_PRIORITY,
    ASTER_PRIORITY_MASK_IMMEDIATE = 1u << ASTER_IMMEDIATE,
    ASTER_PRIORITY_MASK_FLASH = 1u << ASTER_FLASH,
    ASTER_PRIORITY_MASK_ALL = 0x0fu
};

typedef uint32_t aster_bridge_commit_status_t;
enum {
    ASTER_BRIDGE_ACTIVE = 0,
    ASTER_BRIDGE_RETAINED_ALTERNATE = 1,
    ASTER_BRIDGE_DUPLICATE_ACTIVE = 2,
    ASTER_BRIDGE_DUPLICATE_INACTIVE = 3
};

typedef uint32_t aster_peer_state_t;
enum {
    ASTER_PEER_OFFLINE = 0,
    ASTER_PEER_AUTHENTICATING = 1,
    ASTER_PEER_READY = 2,
    ASTER_PEER_REJECTED = 3,
    ASTER_PEER_REVOKED = 4
};

typedef uint32_t aster_sync_state_t;
enum {
    ASTER_SYNC_IDLE = 0,
    ASTER_SYNC_RECONCILING = 1,
    ASTER_SYNC_TRANSFERRING = 2,
    ASTER_SYNC_CONVERGED = 3,
    ASTER_SYNC_SUSPENDED = 4
};

typedef uint32_t aster_rekey_access_t;
enum {
    /* Zero is deliberately invalid so every recipient mode is explicit. */
    ASTER_REKEY_ROUTE_ONLY = 1,
    ASTER_REKEY_READ_TOPICS = 2
};

/* Handles are process-local capabilities. Zero is always invalid. */
typedef struct { uint64_t value; } aster_node_t;
typedef struct { uint64_t value; } aster_batch_result_t;
typedef struct { uint64_t value; } aster_query_t;
typedef struct { uint64_t value; } aster_conflicts_t;
typedef struct { uint64_t value; } aster_deliveries_t;
typedef struct { uint64_t value; } aster_peers_t;
typedef struct { uint64_t value; } aster_blob_writer_t;
typedef struct { uint64_t value; } aster_blob_reader_t;
typedef struct { uint64_t value; } aster_bridge_enrollment_t;
typedef struct { uint64_t value; } aster_bridge_authorizations_t;
typedef struct { uint64_t value; } aster_bridge_routes_t;

/* Caller-owned input, valid only for the duration of one call. */
typedef struct {
    const uint8_t *data;
    size_t len;
} aster_bytes_t;

/* Library-owned bytes. Release with aster_buffer_free or the enclosing free. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t *data;
    size_t len;
} aster_owned_buffer_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t store_path;          /* UTF-8 path; ":memory:" is supported. */
    /* Canonical unprotected inner bundle containing secrets; compatibility/test only.
     * Its internal format is not part of the ABI. */
    aster_bytes_t provisioning_bundle;
    uint64_t max_items;
    uint64_t max_bytes;
    uint64_t tombstone_retention_ms;
    uint64_t superseded_retention_ms;
    aster_priority_t priority_cap;
    aster_priority_t emission_threshold;
} aster_node_options_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_data_class_t data_class;
    aster_priority_t priority;
    aster_bytes_t topic;
    aster_bytes_t scope;
    aster_bytes_t logical_key;
    aster_bytes_t payload;
    uint64_t ttl_ms;
    uint8_t has_ttl;
    uint8_t tombstone;
    uint8_t reserved[6];
} aster_publish_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t item_id[ASTER_ID_BYTES];
    uint8_t publisher[ASTER_ID_BYTES];
    uint64_t causal_counter;
    uint64_t event_sequence;
    uint8_t has_event_sequence;
    uint8_t effective_priority;
    uint8_t reserved[6];
} aster_publish_receipt_t;

/* A bounded, ordered atomic publication of 2-64 items. The array and every
 * borrowed buffer in it remain valid only until aster_node_publish_batch
 * returns. Blob items are finalized through the streaming Blob API instead. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    const aster_publish_request_t *items;
    size_t item_count;
    aster_batch_policy_t policy;
    uint32_t reserved;
} aster_publish_batch_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t bytes[ASTER_ID_BYTES];
} aster_item_id_t;

/* Initialize with aster_blob_publish_options_init before setting fields. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t topic;
    aster_bytes_t scope;
    /* Optional UTF-8 media type and opaque schema identifier. */
    aster_bytes_t media_type;
    aster_bytes_t schema_id;
    uint64_t ttl_ms;
    uint32_t chunk_size; /* 4-64 KiB; initialized to 64 KiB. */
    aster_priority_t priority;
    uint8_t has_ttl;
    uint8_t reserved[7];
} aster_blob_publish_options_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t blob_id[ASTER_ID_BYTES];
    aster_publish_receipt_t receipt;
} aster_blob_finish_t;

/* Finalize and atomically publish 2-64 existing writers. Writers must be
 * distinct, belong to node, and not already be published. They remain open
 * and retryable; after success their ordinary finish returns the same result. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    const aster_blob_writer_t *writers;
    size_t writer_count;
    aster_batch_policy_t policy;
    uint32_t reserved;
} aster_blob_publish_batch_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t topic;
    aster_bytes_t scope;
    uint8_t blob_id[ASTER_ID_BYTES];
} aster_blob_read_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t topic;       /* Empty means any topic. */
    aster_bytes_t scope;       /* Empty means any scope. */
    aster_bytes_t logical_key; /* Empty means any logical key. */
    aster_data_class_t data_class; /* ASTER_DATA_CLASS_ANY means any class. */
    uint8_t include_descendant_scopes;
    uint8_t include_recoverable_versions;
    uint8_t include_tombstones;
    uint8_t reserved;
    uint64_t limit;            /* Zero selects the implementation default. */
} aster_query_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t item_id[ASTER_ID_BYTES];
    uint8_t publisher[ASTER_ID_BYTES];
    aster_data_class_t data_class;
    aster_priority_t priority;
    uint64_t causal_counter;
    uint64_t event_sequence;
    uint8_t has_event_sequence;
    uint8_t tombstone;
    uint8_t reserved[6];
    aster_owned_buffer_t topic;
    aster_owned_buffer_t scope;         /* Compatibility alias for current_scope. */
    aster_owned_buffer_t origin_scope;  /* Source scope authenticated end-to-end. */
    aster_owned_buffer_t current_scope; /* Scope in which this projection is visible. */
    aster_owned_buffer_t logical_key;
    aster_owned_buffer_t payload;
} aster_item_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t topic;
    aster_bytes_t scope;
    aster_data_class_t data_class; /* ASTER_DATA_CLASS_ANY means any class. */
    uint8_t include_descendant_scopes;
    uint8_t reserved[3];
} aster_subscribe_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t subscription;
    uint64_t limit;
} aster_poll_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t subscription;
    uint64_t attempt;
    aster_item_t item;
} aster_delivery_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t subscription;
    uint8_t item_id[ASTER_ID_BYTES];
} aster_ack_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_owned_buffer_t logical_key;
    /* Canonical concatenation of 32-byte sibling item identifiers. */
    aster_owned_buffer_t sibling_ids;
    aster_owned_buffer_t merge_policy;
    uint8_t has_merge_policy;
    uint8_t reserved[7];
} aster_conflict_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t topic;
    aster_bytes_t scope;
    aster_bytes_t logical_key;
    aster_bytes_t expected_sibling_ids; /* N * ASTER_ID_BYTES bytes. */
    aster_bytes_t payload;
    aster_priority_t priority;
    uint32_t reserved0;
    uint64_t ttl_ms;
    uint8_t has_ttl;
    uint8_t reserved[7];
} aster_resolve_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t peer[ASTER_ID_BYTES];
    aster_peer_state_t peer_state;
    aster_sync_state_t sync_state;
    uint64_t last_change_ms;
    uint8_t has_last_change;
    uint8_t has_detail;
    uint8_t reserved[6];
    aster_owned_buffer_t detail;
} aster_peer_snapshot_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t peer[ASTER_ID_BYTES];
} aster_peer_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t from_scope;
    aster_bytes_t to_scope;
    /* Empty topic grants all topics for the scope pair. */
    aster_bytes_t topic;
    aster_priority_t minimum_priority;
    uint32_t reserved;
} aster_bridge_filter_t;

/* Bridge-node operation for one exact directed edge and exact nonzero epochs. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t source_scope;
    aster_bytes_t target_scope;
    uint64_t source_route_epoch;
    uint64_t target_route_epoch;
    uint8_t reserved[8];
} aster_bridge_enrollment_request_t;

/* Topics are borrowed for one call, bounded to 1-128 entries, and canonicalized
 * by the library. The priority mask must explicitly select bits 0 through 3. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    const aster_bytes_t *topics;
    size_t topic_count;
    aster_priority_mask_t allowed_priority_mask;
    uint8_t max_total_hops; /* 1-8 */
    uint8_t reserved[6];
} aster_bridge_enable_policy_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t bridge_node[ASTER_ID_BYTES];
    aster_bytes_t source_scope;
    aster_bytes_t target_scope;
    uint8_t reserved[8];
} aster_bridge_disable_request_t;

/* Empty topics mean all topics still allowed by the signed authorization;
 * priorities remain explicit and nonempty. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t source_item[ASTER_ID_BYTES];
    uint8_t authorization_id[ASTER_ID_BYTES];
    const aster_bytes_t *topics;
    size_t topic_count;
    aster_priority_mask_t allowed_priority_mask;
    uint8_t reserved[7];
} aster_bridge_item_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t route_handle[ASTER_ID_BYTES];
    uint8_t authorization_id[ASTER_ID_BYTES];
    const aster_bytes_t *topics;
    size_t topic_count;
    aster_priority_mask_t allowed_priority_mask;
    uint8_t reserved[7];
} aster_bridge_extend_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t id[ASTER_ID_BYTES];
    uint64_t generation;
    uint64_t control_sequence;
    uint8_t enabled;
    uint8_t reserved[7];
} aster_bridge_authorization_result_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t handle[ASTER_ID_BYTES];
    uint8_t source_item[ASTER_ID_BYTES];
    uint64_t current_route_epoch;
    aster_bridge_commit_status_t commit_status;
    uint8_t hop_count;
    uint8_t reserved[3];
    aster_owned_buffer_t current_scope;
} aster_bridge_route_result_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t id[ASTER_ID_BYTES];
    uint8_t reserved[8];
} aster_bridge_status_request_t;

/* `after` is an exclusive durable 32-byte cursor when has_after is one. A
 * zero limit selects the default; every returned page is capped at 4096. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t after[ASTER_ID_BYTES];
    uint64_t limit;
    uint8_t has_after;
    uint8_t reserved[7];
} aster_bridge_page_request_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t id[ASTER_ID_BYTES];
    uint8_t authority[ASTER_ID_BYTES];
    uint8_t bridge_node[ASTER_ID_BYTES];
    uint64_t generation;
    uint64_t control_sequence;
    uint64_t source_route_epoch;
    uint64_t target_route_epoch;
    uint64_t topic_count;
    aster_priority_mask_t allowed_priority_mask;
    uint8_t max_total_hops;
    uint8_t applied;
    uint8_t current;
    uint8_t enabled;
    uint8_t usable;
    uint8_t has_source_route_epoch;
    uint8_t has_target_route_epoch;
    uint8_t has_max_total_hops;
    uint8_t reserved[7];
    aster_owned_buffer_t source_scope;
    aster_owned_buffer_t target_scope;
    /* topic_count repetitions of u16 big-endian byte length + UTF-8 bytes. */
    aster_owned_buffer_t topics;
} aster_bridge_authorization_status_t;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t handle[ASTER_ID_BYTES];
    uint8_t source_item[ASTER_ID_BYTES];
    uint64_t origin_route_epoch;
    uint64_t current_route_epoch;
    aster_priority_t priority;
    uint8_t hop_count;
    uint8_t active;
    uint8_t live;
    uint8_t reserved;
    aster_owned_buffer_t origin_scope;
    aster_owned_buffer_t current_scope;
    aster_owned_buffer_t topic;
} aster_bridge_route_status_t;

/* One bounded recipient. The topics array and every topic slice are borrowed
 * only until aster_node_rekey_scope returns. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t node_id[ASTER_ID_BYTES];
    aster_rekey_access_t access;
    uint32_t reserved;
    const aster_bytes_t *topics;
    size_t topic_count;
} aster_rekey_recipient_t;

/* Authority-only fresh scope rekey. The signed registry is opaque public data;
 * callers enforce rollback protection with minimum_registry_generation. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    aster_bytes_t signed_public_registry;
    aster_bytes_t scope;
    uint64_t minimum_registry_generation;
    uint64_t new_epoch;
    const aster_rekey_recipient_t *recipients;
    size_t recipient_count;
} aster_rekey_request_t;

/* Non-secret receipt for the durably chained control publication. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t epoch;
    uint64_t registry_generation;
    uint64_t recipient_count;
    uint64_t control_sequence;
} aster_rekey_receipt_t;

ASTER_API uint32_t aster_abi_version(void);
/* Legacy alias for aster_replication_wire_version; not a session semantic version. */
ASTER_API uint16_t aster_protocol_version(void);
ASTER_API uint16_t aster_replication_wire_version(void);
ASTER_API uint16_t aster_default_semantic_version(void);
ASTER_API uint16_t aster_highest_supported_semantic_version(void);

ASTER_API aster_status_t aster_node_options_init(aster_node_options_t *options);
ASTER_API aster_status_t aster_node_open(const aster_node_options_t *options,
                                          aster_node_t *out_node);
ASTER_API aster_status_t aster_node_close(aster_node_t *node);
/* Zeroization always invalidates *node, including when destruction reports an error. */
ASTER_API aster_status_t aster_node_zeroize(aster_node_t *node);

ASTER_API aster_status_t aster_node_publish(aster_node_t node,
                                             const aster_publish_request_t *request,
                                             aster_publish_receipt_t *out_receipt);
ASTER_API aster_status_t aster_node_publish_batch(
    aster_node_t node, const aster_publish_batch_request_t *request,
    aster_batch_result_t *out_result);
ASTER_API aster_status_t aster_batch_result_len(
    aster_batch_result_t result, size_t *out_len);
ASTER_API aster_status_t aster_batch_result_get(
    aster_batch_result_t result, size_t index,
    aster_publish_receipt_t *out_receipt);
ASTER_API aster_status_t aster_batch_result_evicted_len(
    aster_batch_result_t result, size_t *out_len);
ASTER_API aster_status_t aster_batch_result_evicted_get(
    aster_batch_result_t result, size_t index, aster_item_id_t *out_item_id);
ASTER_API aster_status_t aster_batch_result_close(aster_batch_result_t *result);
ASTER_API aster_status_t aster_node_rekey_scope(
    aster_node_t node, const aster_rekey_request_t *request,
    aster_rekey_receipt_t *out_receipt);
/* Generic publish rejects ASTER_BLOB; use this bounded streaming API instead. */
ASTER_API aster_status_t aster_blob_publish_options_init(
    aster_blob_publish_options_t *options);
ASTER_API aster_status_t aster_node_blob_writer_open(
    aster_node_t node, const aster_blob_publish_options_t *options,
    aster_blob_writer_t *out_writer);
/* Writes all bytes on ASTER_OK. finish is idempotent and may be safely retried. */
ASTER_API aster_status_t aster_blob_writer_write(aster_blob_writer_t writer,
                                                  aster_bytes_t bytes);
ASTER_API aster_status_t aster_blob_writer_finish(aster_blob_writer_t writer,
                                                   aster_blob_finish_t *out_finish);
ASTER_API aster_status_t aster_node_publish_blob_batch(
    aster_node_t node, const aster_blob_publish_batch_request_t *request,
    aster_batch_result_t *out_result);
ASTER_API aster_status_t aster_blob_writer_close(aster_blob_writer_t *writer);
ASTER_API aster_status_t aster_node_blob_reader_open(
    aster_node_t node, const aster_blob_read_request_t *request,
    aster_blob_reader_t *out_reader);
/* Returns zero in out_read only after the complete plaintext digest verifies. */
ASTER_API aster_status_t aster_blob_reader_read(aster_blob_reader_t reader,
                                                 uint8_t *buffer, size_t buffer_len,
                                                 size_t *out_read);
ASTER_API aster_status_t aster_blob_reader_close(aster_blob_reader_t *reader);
ASTER_API aster_status_t aster_node_query(aster_node_t node,
                                           const aster_query_request_t *request,
                                           aster_query_t *out_query);
ASTER_API aster_status_t aster_query_len(aster_query_t query, size_t *out_len);
ASTER_API aster_status_t aster_query_get(aster_query_t query, size_t index,
                                          aster_item_t *out_item);
ASTER_API aster_status_t aster_query_close(aster_query_t *query);
ASTER_API aster_status_t aster_item_free(aster_item_t *item);

ASTER_API aster_status_t aster_node_subscribe(aster_node_t node,
                                               const aster_subscribe_request_t *request,
                                               uint64_t *out_subscription);
ASTER_API aster_status_t aster_node_poll(aster_node_t node,
                                          const aster_poll_request_t *request,
                                          aster_deliveries_t *out_deliveries);
ASTER_API aster_status_t aster_deliveries_len(aster_deliveries_t deliveries,
                                               size_t *out_len);
ASTER_API aster_status_t aster_deliveries_get(aster_deliveries_t deliveries, size_t index,
                                               aster_delivery_t *out_delivery);
ASTER_API aster_status_t aster_deliveries_close(aster_deliveries_t *deliveries);
ASTER_API aster_status_t aster_delivery_free(aster_delivery_t *delivery);
ASTER_API aster_status_t aster_node_acknowledge(aster_node_t node,
                                                 const aster_ack_request_t *request);

ASTER_API aster_status_t aster_node_conflicts(aster_node_t node,
                                               const aster_query_request_t *request,
                                               aster_conflicts_t *out_conflicts);
ASTER_API aster_status_t aster_conflicts_len(aster_conflicts_t conflicts,
                                              size_t *out_len);
ASTER_API aster_status_t aster_conflicts_get(aster_conflicts_t conflicts, size_t index,
                                              aster_conflict_t *out_conflict);
ASTER_API aster_status_t aster_conflicts_close(aster_conflicts_t *conflicts);
ASTER_API aster_status_t aster_conflict_free(aster_conflict_t *conflict);
ASTER_API aster_status_t aster_node_resolve(aster_node_t node,
                                             const aster_resolve_request_t *request,
                                             aster_publish_receipt_t *out_receipt);

ASTER_API aster_status_t aster_node_set_emission(aster_node_t node,
                                                  aster_priority_t threshold);
ASTER_API aster_status_t aster_node_get_emission(aster_node_t node,
                                                  aster_priority_t *out_threshold);
ASTER_API aster_status_t aster_node_peer_status(aster_node_t node,
                                                 const aster_peer_request_t *request,
                                                 aster_peer_snapshot_t *out_snapshot);
ASTER_API aster_status_t aster_node_peers(aster_node_t node, aster_peers_t *out_peers);
ASTER_API aster_status_t aster_peers_len(aster_peers_t peers, size_t *out_len);
ASTER_API aster_status_t aster_peers_get(aster_peers_t peers, size_t index,
                                          aster_peer_snapshot_t *out_snapshot);
ASTER_API aster_status_t aster_peers_close(aster_peers_t *peers);
ASTER_API aster_status_t aster_peer_snapshot_free(aster_peer_snapshot_t *snapshot);

/* Enrollment is a process-local move-only capability. Enable consumes and
 * zeros *enrollment once native authority processing begins, including error
 * returns. Close drops an unused enrollment and is idempotent for zero. */
ASTER_API aster_status_t aster_node_bridge_enrollment_create(
    aster_node_t node, const aster_bridge_enrollment_request_t *request,
    aster_bridge_enrollment_t *out_enrollment);
ASTER_API aster_status_t aster_bridge_enrollment_close(
    aster_bridge_enrollment_t *enrollment);
ASTER_API aster_status_t aster_node_bridge_enable(
    aster_node_t node, aster_bridge_enrollment_t *enrollment,
    const aster_bridge_enable_policy_t *policy,
    aster_bridge_authorization_result_t *out_result);
ASTER_API aster_status_t aster_node_bridge_disable(
    aster_node_t node, const aster_bridge_disable_request_t *request,
    aster_bridge_authorization_result_t *out_result);
ASTER_API aster_status_t aster_node_bridge_item(
    aster_node_t node, const aster_bridge_item_request_t *request,
    aster_bridge_route_result_t *out_result);
ASTER_API aster_status_t aster_node_bridge_extend(
    aster_node_t node, const aster_bridge_extend_request_t *request,
    aster_bridge_route_result_t *out_result);
ASTER_API aster_status_t aster_bridge_route_result_free(
    aster_bridge_route_result_t *result);

ASTER_API aster_status_t aster_node_bridge_authorization_status(
    aster_node_t node, const aster_bridge_status_request_t *request,
    aster_bridge_authorization_status_t *out_status);
ASTER_API aster_status_t aster_node_bridge_authorizations(
    aster_node_t node, const aster_bridge_page_request_t *request,
    aster_bridge_authorizations_t *out_authorizations);
ASTER_API aster_status_t aster_bridge_authorizations_len(
    aster_bridge_authorizations_t authorizations, size_t *out_len);
ASTER_API aster_status_t aster_bridge_authorizations_get(
    aster_bridge_authorizations_t authorizations, size_t index,
    aster_bridge_authorization_status_t *out_status);
ASTER_API aster_status_t aster_bridge_authorizations_close(
    aster_bridge_authorizations_t *authorizations);
ASTER_API aster_status_t aster_bridge_authorization_status_free(
    aster_bridge_authorization_status_t *status);

ASTER_API aster_status_t aster_node_bridge_route_status(
    aster_node_t node, const aster_bridge_status_request_t *request,
    aster_bridge_route_status_t *out_status);
ASTER_API aster_status_t aster_node_bridge_routes(
    aster_node_t node, const aster_bridge_page_request_t *request,
    aster_bridge_routes_t *out_routes);
ASTER_API aster_status_t aster_bridge_routes_len(
    aster_bridge_routes_t routes, size_t *out_len);
ASTER_API aster_status_t aster_bridge_routes_get(
    aster_bridge_routes_t routes, size_t index,
    aster_bridge_route_status_t *out_status);
ASTER_API aster_status_t aster_bridge_routes_close(aster_bridge_routes_t *routes);
ASTER_API aster_status_t aster_bridge_route_status_free(
    aster_bridge_route_status_t *status);

/* Local policy can only narrow a signed authorization. The legacy one-topic
 * form is retained for ABI v1 compatibility. */
ASTER_API aster_status_t aster_node_set_bridge_filters(aster_node_t node,
                                                        const aster_bridge_filter_t *filters,
                                                        size_t filter_count);

/* Copies the calling thread's most recent diagnostic; never includes key material. */
ASTER_API aster_status_t aster_last_error(aster_owned_buffer_t *out_error);
ASTER_API aster_status_t aster_buffer_free(aster_owned_buffer_t *buffer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ASTER_MESH_H */
