.text
.global _start
_start:
    mov x20, #0x2000
    movk x20, #0x4008, lsl #16
    mov x21, #0
    adr x0, vectors
    msr vbar_el2, x0
    mov x0, #(1 << 31)
    movk x0, #TRAP_BITS, lsl #16
    msr hcr_el2, x0
    adr x0, lower
    msr elr_el2, x0
    mov x0, #0x3c5
    msr spsr_el2, x0
    isb
    eret
lower:
    mrs x0, MVFR0_EL1
    str w0, [x20]
    mrs x1, MVFR1_EL1
    str w1, [x20, #4]
    mrs x2, MVFR2_EL1
    str w2, [x20, #8]
    add x20, x20, #REPORT_OFFSET
    mov x22, #3
    mov x3, #0x09000000
next:
    ldr w1, [x20], #4
    mov x2, #8
digit:
    lsr w0, w1, #28
    cmp w0, #10
    b.hs letter
    add w0, w0, #48
    b put
letter:
    add w0, w0, #87
put:
    strb w0, [x3]
    lsl w1, w1, #4
    subs x2, x2, #1
    b.ne digit
    mov w0, #10
    strb w0, [x3]
    subs x22, x22, #1
    b.ne next
    mov x0, #0x18
    adr x1, reason
    hlt #0xf000
reason:
    .quad 0x20026, 0
    .balign 2048
vectors:
    .space 0x400
    b trap
trap:
    mrs x10, esr_el2
    add x11, x20, #32
    str w10, [x11, x21, lsl #2]
    add x21, x21, #1
    mrs x10, elr_el2
    add x10, x10, #4
    msr elr_el2, x10
    eret
