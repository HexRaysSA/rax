.text
.global _start
_start:
    mov x20, #0x4000
    movk x20, #0x4008, lsl #16
    mov x21, #0
    adr x0, vectors
    msr vbar_el1, x0
    mrs x0, midr_el1
    msr vpidr_el2, x0
    mov x0, #(1 << 31)
    msr hcr_el2, x0
    adr x0, lower
    msr elr_el2, x0
    mov x0, #0x3c5
    msr spsr_el2, x0
    isb
    eret
lower:
    mrs x10, CurrentEL
    str w10, [x20, #8]
    mrs x10, MIDR_EL1
    str w10, [x20]
    mov x0, #0x1234
    .inst 0xd5180000
    .inst 0xd51800a0
    .inst 0xd51800c0
    .inst 0xd5180100
    .inst 0xd5180200
    .inst 0xd5180300
    .inst 0xd5180400
    .inst 0xd5180500
    .inst 0xd5180600
    .inst 0xd5180700
report:
    str w0, [x20, #16]
    str w21, [x20, #12]
    mrs x10, MIDR_EL1
    str w10, [x20, #4]
    mov x22, #15
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
    .space 0x200
    b trap
    .space 0x800 - 0x204
trap:
    cmp x21, #10
    b.hs report
    mrs x10, esr_el1
    add x11, x20, #20
    str w10, [x11, x21, lsl #2]
    add x21, x21, #1
    mrs x10, elr_el1
    add x10, x10, #4
    msr elr_el1, x10
    eret
