#include "aster_mesh.h"

_Static_assert(ASTER_ID_BYTES == 32u, "Aster identifiers must remain fixed width");
_Static_assert(ASTER_BATCH_MIN_ITEMS == 2u && ASTER_BATCH_MAX_ITEMS == 64u,
               "batch bounds changed");
_Static_assert(ASTER_ABI_VERSION == 1u, "smoke test targets ABI version 1");
_Static_assert(ASTER_REPLICATION_WIRE_VERSION == 1u, "wire version must remain stable");
_Static_assert(ASTER_DEFAULT_SEMANTIC_VERSION == 9u, "default semantic version changed");
_Static_assert(ASTER_HIGHEST_SUPPORTED_SEMANTIC_VERSION == 9u,
               "highest semantic version changed");

int main(void) {
    aster_node_options_t options = ASTER_STRUCT_INIT(aster_node_options_t);
    aster_publish_request_t items[2] = {
        ASTER_STRUCT_INIT(aster_publish_request_t),
        ASTER_STRUCT_INIT(aster_publish_request_t),
    };
    aster_publish_batch_request_t batch = ASTER_STRUCT_INIT(aster_publish_batch_request_t);
    aster_batch_result_t batch_result = {0};
    aster_blob_publish_options_t blob = ASTER_STRUCT_INIT(aster_blob_publish_options_t);
    aster_blob_writer_t blob_writers[2] = {{0}, {0}};
    aster_blob_publish_batch_request_t blob_batch =
        ASTER_STRUCT_INIT(aster_blob_publish_batch_request_t);
    aster_rekey_recipient_t recipient = ASTER_STRUCT_INIT(aster_rekey_recipient_t);
    aster_rekey_request_t rekey = ASTER_STRUCT_INIT(aster_rekey_request_t);
    aster_rekey_receipt_t receipt = ASTER_STRUCT_INIT(aster_rekey_receipt_t);
    aster_bridge_enrollment_request_t enrollment_request =
        ASTER_STRUCT_INIT(aster_bridge_enrollment_request_t);
    aster_bridge_enable_policy_t bridge_policy =
        ASTER_STRUCT_INIT(aster_bridge_enable_policy_t);
    aster_bridge_page_request_t bridge_page =
        ASTER_STRUCT_INIT(aster_bridge_page_request_t);
    aster_bridge_authorization_status_t bridge_status =
        ASTER_STRUCT_INIT(aster_bridge_authorization_status_t);
    recipient.access = ASTER_REKEY_ROUTE_ONLY;
    bridge_policy.allowed_priority_mask = ASTER_PRIORITY_MASK_IMMEDIATE;
    bridge_policy.max_total_hops = 8u;
    batch.items = items;
    batch.item_count = 2u;
    batch.policy = ASTER_BATCH_RETAINED_DUAL;
    blob_batch.writers = blob_writers;
    blob_batch.writer_count = 2u;
    blob_batch.policy = ASTER_BATCH_ONLY;
    rekey.recipients = &recipient;
    rekey.recipient_count = 1u;
    return (options.abi_version == ASTER_ABI_VERSION &&
            blob.struct_size == sizeof(blob) &&
            batch.items[1].struct_size == sizeof(aster_publish_request_t) &&
            batch.policy == ASTER_BATCH_RETAINED_DUAL &&
            batch_result.value == 0u &&
            blob_batch.writers[1].value == 0u &&
            blob_batch.policy == ASTER_BATCH_ONLY &&
            rekey.recipients->access == ASTER_REKEY_ROUTE_ONLY &&
            receipt.struct_size == sizeof(receipt) &&
            enrollment_request.struct_size == sizeof(enrollment_request) &&
            bridge_policy.allowed_priority_mask == ASTER_PRIORITY_MASK_IMMEDIATE &&
            bridge_page.struct_size == sizeof(bridge_page) &&
            bridge_status.topics.data == NULL &&
            aster_protocol_version() == ASTER_REPLICATION_WIRE_VERSION &&
            aster_replication_wire_version() == ASTER_REPLICATION_WIRE_VERSION &&
            aster_default_semantic_version() == ASTER_DEFAULT_SEMANTIC_VERSION &&
            aster_highest_supported_semantic_version() ==
                ASTER_HIGHEST_SUPPORTED_SEMANTIC_VERSION) ? 0 : 1;
}
