/* SPDX-License-Identifier: Apache-2.0 */
#include "aster_mesh.h"
_Static_assert(ASTER_ABI_VERSION == 2, "ABI mismatch");
_Static_assert(sizeof(AsterHandle) == 8, "handle width");
_Static_assert(sizeof(((AsterItem *)0)->id) == 32, "identifier width");
void aster_header_smoke(void) {
    uint32_t (*open_node)(const AsterNodeOptions *, uint64_t *) = aster_node_open;
    uint32_t (*resolve)(uint64_t, const AsterResolveRequest *, AsterPublishReceipt *) = aster_node_resolve;
    (void)open_node;
    (void)resolve;
}
