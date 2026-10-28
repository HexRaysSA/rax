// EL1 kernel/CLI profile oracle. Parameters: TEST_EL, FPEN, OPCODE.
.section .text
.global _start
_start:
    adr x9, vectors
    msr VBAR_EL1, x9
    mrs x9, ID_AA64PFR0_EL1
    ubfx x20, x9, #16, #4
    ubfx x9, x9, #20, #4
    cmp x20, x9
    b.ne fail
    cmp x20, #1
    b.hi fail
    ldr x9, =FPEN << 20
    msr CPACR_EL1, x9
    isb
.if TEST_EL == 0
    adr x9, test_entry
    msr ELR_EL1, x9
    mov x9, #0x3c0
    msr SPSR_EL1, x9
    eret
.endif
test_entry:
    ldr x0, =0x40001000
instruction:
    .inst OPCODE
after_access:
    svc #0
    b fail
    .balign 2048
vectors:
    .rept 16
    b handler
    .space 124
    .endr
handler:
    mrs x9, SPSR_EL1
    and x9, x9, #31
.if TEST_EL == 0
    cmp x9, #0
.else
    cmp x9, #5
.endif
    b.ne fail
    mrs x9, ESR_EL1
    lsr x9, x9, #26
    mrs x10, ELR_EL1
    adr x11, instruction
    cmp x10, x11
    b.ne after
    ldr x11, =0x40001000
    cmp x0, x11
    b.ne fail
    mov w12, #'U'
    cbz x9, output
    cmp x9, #7
    b.ne fail
    mov w12, #'D'
    b output
after:
    adr x11, after_access + 4
    cmp x10, x11
    b.ne fail
    cmp x9, #0x15
    b.ne fail
    mov w12, #'P'
output:
    add w20, w20, #'0'
    ldr x9, =0x09000000
    strb w20, [x9]
    strb w12, [x9]
    b exit
fail:
    ldr x9, =0x09000000
    mov w12, #'F'
    strb w12, [x9]
exit:
    ldr x0, =0x84000008
    hvc #0
    b .
    .ltorg
