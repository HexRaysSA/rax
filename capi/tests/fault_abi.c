#include "rax.h"
#include <stddef.h>

_Static_assert(sizeof(rax_fault_info) == 48, "fault record size");
_Static_assert(offsetof(rax_fault_info, pc) == 16, "fault PC offset");
_Static_assert(offsetof(rax_fault_info, address) == 24, "fault address offset");
_Static_assert(offsetof(rax_fault_info, size) == 32, "fault width offset");
_Static_assert(offsetof(rax_fault_info, retired_instructions) == 40, "fault count offset");
_Static_assert(RAX_FAULT_UNMAPPED == 1u, "unmapped kind");
_Static_assert(RAX_FAULT_ACCESS_FETCH == 3u, "fetch access");

rax_status fault_abi_query(const rax_engine *engine) {
    rax_fault_info fault = {0};
    fault.struct_size = (uint32_t)sizeof(fault);
    fault.version = RAX_FAULT_INFO_VERSION;
    return rax_emu_last_fault(engine, &fault);
}
