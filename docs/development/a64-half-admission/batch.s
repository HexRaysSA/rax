// Batched admission oracle. Link a read-only test_words..test_words_end array.
// TEST_EL=0/1, FPEN=0/3. One U/D/P byte per word; F marks a harness failure.
.section .text
.global _start
_start:
    mrs x9, CurrentEL
    cmp x9, #12
    b.ne fail
    msr CPTR_EL3, xzr
    msr CPTR_EL2, xzr
    ldr x9, =0x80000000
    msr HCR_EL2, x9
    mov x9, #0x501
    msr SCR_EL3, x9
    ldr x9, =FPEN << 20
    msr CPACR_EL1, x9
    adr x9, vectors
    msr VBAR_EL1, x9
    adr x9, driver
    msr ELR_EL3, x9
    mov x9, #0x3c5
    msr SPSR_EL3, x9
    isb
    eret
driver:
    mov x20, #0
    ldr x21, =test_words
    ldr x24, =test_words_end
    sub x24, x24, x21
    lsr x24, x24, #2
    ldr x22, =0x40100000
    ldr x23, =0x40300000
    ldr w9, =0xd4000001
    str w9, [x23, #4]
    mov x1, #0
next_word:
    ldr w9, [x21, x20, lsl #2]
    str w9, [x23]
    dsb sy
    ic iallu
    dsb sy
    isb
    ldr x0, =0x40001000
.if TEST_EL == 0
    msr ELR_EL1, x23
    mov x9, #0x3c0
    msr SPSR_EL1, x9
    eret
.else
    br x23
.endif
driver_next:
    add x20, x20, #1
    cmp x20, x24
    b.lo next_word
    strb wzr, [x22, x20]
    mov x1, x22
    b print
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
    cmp x10, x23
    b.ne after
    ldr x11, =0x40001000
    cmp x0, x11
    b.ne fail
    mov w12, #'U'
    cbz x9, record
    cmp x9, #7
    b.ne fail
    mov w12, #'D'
    b record
after:
    add x11, x23, #8
    cmp x10, x11
    b.ne fail
    cmp x9, #0x15
    b.ne fail
    mov w12, #'P'
record:
    strb w12, [x22, x20]
    adr x9, driver_next
    msr ELR_EL1, x9
    mov x9, #0x3c5
    msr SPSR_EL1, x9
    eret
fail:
    ldr x1, =0x40000300
    mov w9, #'F'
    strb w9, [x1]
    strb wzr, [x1, #1]
print:
    mov x0, #4
    hlt #0xf000
    ldr x1, =0x40000200
    ldr x9, =0x20026
    str x9, [x1]
    str xzr, [x1, #8]
    mov x0, #0x20
    hlt #0xf000
    b .
    .ltorg
