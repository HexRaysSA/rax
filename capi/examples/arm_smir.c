/* A C consumer of the ARM SMIR export; no native mnemonic parsing. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "rax.h"
int main(void) {
    const unsigned char bytes[] = {0x03,0x10,0xc1,0xa8}; /* ldp x3,x4,[x0],#16 */
    rax_smir_instruction instruction = {0};
    assert(rax_smir_lift_arm(RAX_ARCH_ARM64, RAX_MODE_LITTLE_ENDIAN, 0x14,
        bytes, sizeof(bytes), &instruction, NULL, 0) == RAX_OK);
    size_t count = instruction.required_op_count;
    rax_smir_op *ops = calloc(count ? count : 1, sizeof(*ops));
    assert(ops);
    assert(rax_smir_lift_arm(RAX_ARCH_ARM64, RAX_MODE_LITTLE_ENDIAN, 0x14,
        bytes, sizeof(bytes), &instruction, ops, count) == RAX_OK);
    assert(instruction.flags == RAX_SMIR_COMPLETE && instruction.op_count == count);
    assert(count >= 2 && ops[0].opcode == RAX_SMIR_LOAD_PAIR && ops[0].width_bits == 64);
    assert(ops[0].dst.kind == RAX_SMIR_OPERAND_ARM && ops[0].dst.id == 3 && ops[0].dst2.id == 4);
    printf("ARM SMIR: %zu operations, paired 64-bit load + writeback\n", count);
    free(ops);
    const unsigned char conditional[] = {0x38,0x00,0x9f,0x05}; /* ldreq r0,[pc,#0x38] */
    rax_smir_op guarded[4];
    assert(rax_smir_lift_arm(RAX_ARCH_ARM, RAX_MODE_ARM, 0x1054,
        conditional, sizeof(conditional), &instruction, guarded, 4) == RAX_OK);
    assert(instruction.op_count == 2 && guarded[0].opcode == RAX_SMIR_GUARD_CC);
    assert(guarded[0].condition == 0 && guarded[1].opcode == RAX_SMIR_LOAD);
    printf("A32 SMIR: instruction guard suppresses the complete memory body\n");
    return 0;
}
