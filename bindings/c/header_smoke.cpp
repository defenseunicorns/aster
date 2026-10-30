#include "aster_mesh.h"

static_assert(ASTER_ID_BYTES == 32u, "Aster identifiers must remain fixed width");
static_assert(ASTER_BATCH_MIN_ITEMS == 2u && ASTER_BATCH_MAX_ITEMS == 64u,
              "batch bounds changed");
static_assert(ASTER_ABI_VERSION == 1u, "smoke test targets ABI version 1");
static_assert(ASTER_REPLICATION_WIRE_VERSION == 1u, "wire version must remain stable");
static_assert(ASTER_DEFAULT_SEMANTIC_VERSION == 9u, "default semantic version changed");
static_assert(ASTER_HIGHEST_SUPPORTED_SEMANTIC_VERSION == 9u,
              "highest semantic version changed");

int main() {
    aster_node_t node{};
    aster_publish_request_t items[2] = {
        ASTER_STRUCT_INIT(aster_publish_request_t),
        ASTER_STRUCT_INIT(aster_publish_request_t),
    };
    aster_publish_batch_request_t batch = ASTER_STRUCT_INIT(aster_publish_batch_request_t);
    aster_batch_result_t batch_result{};
    aster_blob_writer_t blob_writers[2]{};
    aster_blob_publish_batch_request_t blob_batch =
        ASTER_STRUCT_INIT(aster_blob_publish_batch_request_t);
    aster_owned_buffer_t buffer = ASTER_STRUCT_INIT(aster_owned_buffer_t);
    aster_rekey_recipient_t recipient = ASTER_STRUCT_INIT(aster_rekey_recipient_t);
    aster_rekey_request_t request = ASTER_STRUCT_INIT(aster_rekey_request_t);
    aster_rekey_receipt_t receipt = ASTER_STRUCT_INIT(aster_rekey_receipt_t);
    aster_bridge_enrollment_t enrollment{};
    aster_bridge_extend_request_t extension = ASTER_STRUCT_INIT(aster_bridge_extend_request_t);
    aster_bridge_route_result_t route = ASTER_STRUCT_INIT(aster_bridge_route_result_t);
    aster_bridge_route_status_t status = ASTER_STRUCT_INIT(aster_bridge_route_status_t);
    recipient.access = ASTER_REKEY_READ_TOPICS;
    request.recipients = &recipient;
    request.recipient_count = 1u;
    extension.allowed_priority_mask = ASTER_PRIORITY_MASK_FLASH;
    batch.items = items;
    batch.item_count = 2u;
    batch.policy = ASTER_BATCH_ONLY;
    blob_batch.writers = blob_writers;
    blob_batch.writer_count = 2u;
    blob_batch.policy = ASTER_BATCH_RETAINED_DUAL;
    return (node.value == 0u && buffer.abi_version == ASTER_ABI_VERSION &&
            batch.items[0].abi_version == ASTER_ABI_VERSION &&
            batch.policy == ASTER_BATCH_ONLY && batch_result.value == 0u &&
            blob_batch.writers[0].value == 0u &&
            blob_batch.policy == ASTER_BATCH_RETAINED_DUAL &&
            enrollment.value == 0u &&
            request.recipients->access == ASTER_REKEY_READ_TOPICS &&
            receipt.struct_size == sizeof(receipt) &&
            extension.allowed_priority_mask == ASTER_PRIORITY_MASK_FLASH &&
            route.commit_status == ASTER_BRIDGE_ACTIVE &&
            status.origin_scope.data == nullptr &&
            aster_protocol_version() == ASTER_REPLICATION_WIRE_VERSION &&
            aster_replication_wire_version() == ASTER_REPLICATION_WIRE_VERSION &&
            aster_default_semantic_version() == ASTER_DEFAULT_SEMANTIC_VERSION &&
            aster_highest_supported_semantic_version() ==
                ASTER_HIGHEST_SUPPORTED_SEMANTIC_VERSION) ? 0 : 1;
}
