/* SPDX-License-Identifier: Apache-2.0 */
#include "aster_mesh.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define INIT(v) do { memset(&(v), 0, sizeof(v)); (v).abi_version = ASTER_ABI_VERSION; (v).struct_size = (uint32_t)sizeof(v); } while (0)
static AsterBytes text(const char *s) { AsterBytes b = {(const uint8_t *)s, strlen(s)}; return b; }
static void check(uint32_t status) {
    if (status != 0) {
        AsterOwnedBuffer error; INIT(error);
        if (aster_last_error(&error) == 0) {
            fprintf(stderr, "C ABI status %u: %.*s\n", status, (int)error.len, (const char *)error.data);
            (void)aster_buffer_free(&error);
        }
        exit(1);
    }
}
int main(int argc, char **argv) {
    assert(argc == 3);
    assert(aster_abi_version() == 2);
    AsterNodeOptions options; check(aster_node_options_init(&options));
    options.state_path = text(argv[1]); options.provisioning_path = text(argv[2]);
    AsterHandle node = 0; check(aster_node_open(&options, &node));
    AsterPublishRequest publish; INIT(publish);
    publish.topic = text("position.current"); publish.scope = text("mission/team/alpha");
    publish.logical_key = text("c-key"); publish.operation_key = text("c-state-1");
    const uint8_t payload[] = {'a', 0, 'b'};
    publish.payload.data = payload; publish.payload.len = sizeof(payload);
    AsterPublishReceipt receipt; INIT(receipt);
    receipt.abi_version = 1;
    assert(aster_node_publish(node, &publish, &receipt) == 2);
    receipt.abi_version = 2; check(aster_node_publish(node, &publish, &receipt));
    assert(receipt.inserted == 1);
    uint8_t published[32]; memcpy(published, receipt.item_id, 32);
    check(aster_node_publish(node, &publish, &receipt)); assert(receipt.inserted == 0);
    AsterQueryRequest query; INIT(query);
    query.topic = publish.topic; query.scope = publish.scope; query.logical_key = publish.logical_key;
    AsterHandle result = 0; check(aster_node_query(node, &query, &result));
    AsterItem item; INIT(item); check(aster_result_item(node, result, 0, 0, &item));
    assert(item.payload.len == sizeof(payload)); assert(memcmp(item.payload.data, payload, sizeof(payload)) == 0);
    assert(memcmp(item.id, published, 32) == 0);
    check(aster_item_free(&item)); check(aster_result_close(node, &result));
    /* The prepared fixture contains three independently authenticated heads,
       including a tombstone. Delivery must not split them at limit one. */
    query.data_class = ASTER_RECORD; query.logical_key = text("unit-7");
    check(aster_node_conflicts(node, &query, &result));
    AsterEntry entry; INIT(entry); check(aster_result_entry(node, result, 0, &entry));
    assert(entry.item_count == 3 && entry.has_guard == 1 && entry.sibling_ids.len == 96);
    check(aster_entry_free(&entry));
    AsterSubscribeRequest subscribe; INIT(subscribe);
    subscribe.data_class = ASTER_RECORD; subscribe.topic = query.topic; subscribe.scope = query.scope; subscribe.operation_key = text("c-record-sub");
    AsterSubscription subscription = {{0}, 0}; check(aster_node_subscribe(node, &subscribe, &subscription));
    AsterPollRequest poll; INIT(poll); poll.subscription = subscription; poll.delivery_limit = 1; poll.scan_limit = 100;
    AsterHandle deliveries = 0; check(aster_node_poll(node, &poll, &deliveries));
    check(aster_result_entry(node, deliveries, 0, &entry)); assert(entry.item_count == 3 && entry.has_guard == 0);
    AsterAckRequest ack; INIT(ack); ack.subscription = subscription; memcpy(ack.id, entry.id, 32); ack.token.data = entry.token.data; ack.token.len = entry.token.len;
    check(aster_node_acknowledge(node, &ack)); check(aster_entry_free(&entry)); check(aster_result_close(node, &deliveries));
    AsterResolveRequest resolve; INIT(resolve); resolve.guard = result; resolve.operation_key = text("c-resolve"); resolve.payload = text("merged");
    check(aster_node_resolve(node, &resolve, &receipt)); assert(receipt.inserted == 1);
    check(aster_node_resolve(node, &resolve, &receipt)); assert(receipt.inserted == 0);
    check(aster_result_close(node, &result)); assert(aster_node_resolve(node, &resolve, &receipt) == 8);
    AsterBlobPublishOptions blob; INIT(blob); blob.operation_key = text("c-blob"); blob.topic = query.topic; blob.scope = query.scope; blob.total_len = sizeof(payload);
    AsterBlobWriterInfo writer; INIT(writer); check(aster_node_blob_writer_open(node, &blob, &writer));
    check(aster_blob_writer_write(node, writer.writer, 0, publish.payload)); check(aster_blob_writer_finish(node, writer.writer, &receipt));
    check(aster_blob_writer_close(node, &writer.writer));
    AsterBlobReadRequest read; INIT(read); read.topic = query.topic; read.scope = query.scope; memcpy(read.blob_id, receipt.blob_id, 32);
    AsterHandle reader = 0; check(aster_node_blob_reader_open(node, &read, &reader));
    AsterOwnedBuffer page; INIT(page); check(aster_blob_reader_read(node, reader, 8, &page));
    assert(page.len == sizeof(payload)); assert(memcmp(page.data, payload, sizeof(payload)) == 0);
    check(aster_buffer_free(&page)); check(aster_blob_reader_close(node, &reader));
    check(aster_node_close(&node)); check(aster_node_close(&node));
    check(aster_node_open(&options, &node)); check(aster_node_zeroize(&node));
    assert(aster_node_open(&options, &node) != 0);
    puts("C ABI v2 runtime smoke passed");
    return 0;
}
