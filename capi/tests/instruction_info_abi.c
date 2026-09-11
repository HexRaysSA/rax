#include "rax.h"
#include <stddef.h>
_Static_assert(sizeof(rax_decoded) == 40, "existing decode ABI preserved");
_Static_assert(sizeof(rax_instruction_operand) == 96, "operand size");
_Static_assert(sizeof(rax_instruction_info_t) == 576, "instruction info size");
_Static_assert(offsetof(rax_instruction_info_t, decoded) == 8, "decoded offset");
_Static_assert(offsetof(rax_instruction_info_t, mnemonic) == 48, "mnemonic offset");
_Static_assert(offsetof(rax_instruction_info_t, operands) == 96, "operands offset");
_Static_assert(offsetof(rax_instruction_operand, displacement) == 80, "displacement offset");
rax_status instruction_info_abi_query(void) {
    const unsigned char code[] = {0xc3};
    rax_instruction_info_t out = {0};
    out.struct_size = (uint32_t)sizeof(out);
    out.abi_version = RAX_INSTRUCTION_INFO_VERSION;
    return rax_instruction_info(RAX_ARCH_X86, RAX_MODE_32, 0x1000, code, sizeof(code), &out);
}
