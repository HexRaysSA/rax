// Assemble with integer symbols OPCODE, TEST_EL (0/1), FPEN (0..3).
.global _start
.text
_start:
    mov x20, #0x09000000
    mrs x5, CurrentEL
    cmp x5, #4
    b.ne fail
    msr spsel, #1
    adr x5, vectors
    msr vbar_el1, x5
    mov x5, #(3 << 20)
    msr cpacr_el1, x5
    isb
    movi v0.16b, #0x11
    movi v1.16b, #0x22
    movi v2.16b, #0x33
    mov x0, #0xdead
    adr x3, data
    mov x5, #(FPEN << 20)
    msr cpacr_el1, x5
    isb
.if TEST_EL == 0
    adr x5, instruction
    msr elr_el1, x5
    mov x5, #0
    msr spsr_el1, x5
    eret
.else
    b instruction
.endif
instruction:
    .inst OPCODE
after:
    svc #0x42
    b fail
.balign 2048
vectors:
.rept 16
    b handler
    .space 124
.endr
handler:
    mov x19, x0
    mrs x5, esr_el1
    ubfx x5, x5, #26, #6
.if (FPEN == 3) || ((TEST_EL == 1) && (FPEN == 1))
    cmp x5, #0x15
    b.ne fail
    mrs x5, elr_el1
    adr x6, after
    add x6, x6, #4
    cmp x5, x6
    b.ne fail
    mov w21, #80 // P: permitted, next SVC reached.
.else
    cmp x5, #7
    b.ne fail
    mrs x5, elr_el1
    adr x6, instruction
    cmp x5, x6
    b.ne fail
    mrs x5, spsr_el1
    and x5, x5, #31
    cmp x5, #(TEST_EL * 5)
    b.ne fail
    mov x6, #0xdead
    cmp x19, x6
    b.ne fail
    adr x5, data
    cmp x3, x5
    b.ne fail
    mov x5, #(3 << 20)
    msr cpacr_el1, x5
    isb
    umov x5, v0.d[0]
    mov x6, #0x1111111111111111
    cmp x5, x6
    b.ne fail
    umov x5, v0.d[1]
    cmp x5, x6
    b.ne fail
    umov x5, v2.d[0]
    mov x6, #0x3333333333333333
    cmp x5, x6
    b.ne fail
    adr x5, storage
    mov x6, #0xaaaaaaaaaaaaaaaa
    mov x7, #12
check_memory:
    ldr x8, [x5], #8
    cmp x8, x6
    b.ne fail
    subs x7, x7, #1
    b.ne check_memory
    mov w21, #68 // D: denied, fault PC/state preserved.
.endif
    b finish
fail:
    mov w21, #70
finish:
    strb w21, [x20]
    mov w0, #8
    movk w0, #0x8400, lsl #16
    hvc #0
    b .
.data
.balign 16
storage:
.rept 4
    .quad 0xaaaaaaaaaaaaaaaa
.endr
data:
.rept 8
    .quad 0xaaaaaaaaaaaaaaaa
.endr
