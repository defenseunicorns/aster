/* SPDX-License-Identifier: Apache-2.0 */
#include "aster_mesh.h"
#include <stdio.h>
#include <string.h>
#define INIT(v) do { memset(&(v), 0, sizeof(v)); (v).abi_version = ASTER_ABI_VERSION; (v).struct_size = (uint32_t)sizeof(v); } while (0)
static AsterBytes text(const char *s) { AsterBytes b = {(const uint8_t *)s, strlen(s)}; return b; }
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s ABSOLUTE_PROVISIONING_FILE ABSOLUTE_STATE_DIRECTORY\n", argv[0]); return 1; }
    AsterNodeOptions options; AsterHandle node = 0, result = 0;
    AsterItem item; INIT(item);
    uint32_t status = aster_node_options_init(&options);
    if (status) return 1;
    options.provisioning_path = text(argv[1]); options.state_path = text(argv[2]);
    status = aster_node_open(&options, &node);
    if (status) goto done;
    AsterPublishRequest request; INIT(request);
    request.data_class = ASTER_STATE; request.priority = 2;
    request.topic = text("position.current"); request.scope = text("mission/team/alpha");
    request.operation_key = text("example/position/1"); request.logical_key = text("unit-7");
    request.payload = text("{\"lat\":38.9,\"lon\":-77.0}");
    AsterPublishReceipt receipt; INIT(receipt);
    status = aster_node_publish(node, &request, &receipt);
    if (status) goto done;
    AsterQueryRequest query; INIT(query);
    query.data_class = ASTER_STATE; query.topic = request.topic; query.scope = request.scope; query.logical_key = request.logical_key;
    status = aster_node_query(node, &query, &result);
    if (status) goto done;
    status = aster_result_item(node, result, 0, 0, &item);
    if (!status) printf("%.*s\n", (int)item.payload.len, (const char *)item.payload.data);
done:
    if (status) {
        AsterOwnedBuffer error; INIT(error);
        if (!aster_last_error(&error)) {
            fprintf(stderr, "Aster status %u: %.*s\n", status, (int)error.len, (const char *)error.data);
            (void)aster_buffer_free(&error);
        }
    }
    (void)aster_item_free(&item);
    if (result) (void)aster_result_close(node, &result);
    (void)aster_node_close(&node);
    return status ? 1 : 0;
}
