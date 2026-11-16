// SPDX-License-Identifier: Apache-2.0
#include "aster_mesh.h"
#include <type_traits>
static_assert(ASTER_ABI_VERSION == 2, "ABI mismatch");
static_assert(std::is_standard_layout<AsterPublishRequest>::value, "C layout");
static_assert(std::is_standard_layout<AsterEntry>::value, "C layout");
static_assert(sizeof(AsterHandle) == 8, "handle width");
void aster_cpp_header_smoke() {
    auto *open_node = &aster_node_open;
    auto *resolve = &aster_node_resolve;
    (void)open_node;
    (void)resolve;
}
