#include "rax.h"
#include <stddef.h>
_Static_assert(RAX_API_MAJOR == 1 && RAX_API_MINOR >= 18, "ARM SMIR version");
_Static_assert(sizeof(rax_smir_operand) == 16, "operand ABI preserved");
_Static_assert(sizeof(rax_smir_address) == 64, "address ABI preserved");
_Static_assert(sizeof(rax_smir_op) == 184, "operation ABI preserved");
_Static_assert(sizeof(rax_smir_instruction) == 136, "instruction ABI preserved");
_Static_assert(offsetof(rax_smir_op, guest_pc) == 176, "operation provenance");
_Static_assert(sizeof(rax_arm_system_info_t) == 32, "static system query ABI");
rax_status smir_arm_abi_query(void) {
    const unsigned char code[] = {3,16,193,168};
    rax_smir_instruction out = {0};
    return rax_smir_lift_arm(RAX_ARCH_ARM64, RAX_MODE_LITTLE_ENDIAN, 0x14,
                             code, sizeof(code), &out, NULL, 0);
}
