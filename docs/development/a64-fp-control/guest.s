// AArch64 normal-execution FP access oracle. Entry must be EL3.
// Parameters: TEST_EL, FPEN, HCR, CPTR2, CPTR3, SECURE, OPCODE.
// Output: target EL, two hexadecimal EC digits, I=fault PC / A=after access.
.section .text
.global _start
_start:
    mrs x9, CurrentEL
    cmp x9, #12
    b.ne fail
    adr x9, vectors1
    msr VBAR_EL1, x9
    adr x9, vectors2
    msr VBAR_EL2, x9
    adr x9, vectors3
    msr VBAR_EL3, x9
    msr CPTR_EL3, xzr
    msr CPTR_EL2, xzr
    ldr x9, =FPEN << 20
    msr CPACR_EL1, x9
    ldr x9, =HCR
    msr HCR_EL2, x9
    ldr x9, =CPTR2
    msr CPTR_EL2, x9
    ldr x9, =CPTR3
    msr CPTR_EL3, x9
    ldr x9, =0x500 + (1 - SECURE)
    msr SCR_EL3, x9
    isb
.if TEST_EL == 3
    b test_entry
.else
    adr x9, test_entry
    msr ELR_EL3, x9
.if TEST_EL == 0
    mov x9, #0x3c0
.else
    mov x9, #(0x3c1 + TEST_EL * 4)
.endif
    msr SPSR_EL3, x9
    eret
.endif
test_entry:
.if TEST_EL != 0
    mrs x9, CurrentEL
    cmp x9, #(TEST_EL * 4)
    b.ne fail
.endif
    mov x0, #0x1234
instruction:
    .inst OPCODE
after_access:
    svc #0
    b fail

.macro vectors name, handler
    .balign 2048
\name:
    .rept 16
    b \handler
    .space 124
    .endr
.endm
vectors vectors1, handler1
vectors vectors2, handler2
vectors vectors3, handler3
handler1:
    mov x10, #1
    mrs x11, ESR_EL1
    mrs x12, ELR_EL1
    mrs x13, SPSR_EL1
    b report
handler2:
    mov x10, #2
    mrs x11, ESR_EL2
    mrs x12, ELR_EL2
    mrs x13, SPSR_EL2
    b report
handler3:
    mov x10, #3
    mrs x11, ESR_EL3
    mrs x12, ELR_EL3
    mrs x13, SPSR_EL3
report:
    and x13, x13, #31
.if TEST_EL == 0
    cmp x13, #0
.else
    cmp x13, #(1 + TEST_EL * 4)
.endif
    b.ne fail
    lsr x11, x11, #26
    mov x14, #'I'
    adr x15, instruction
    cmp x12, x15
    b.ne permitted
    mov x9, #0x1234
    cmp x0, x9
    b.ne fail
    b output
permitted:
    adr x15, after_access + 4
    cmp x12, x15
    b.ne fail
    cmp x11, #0x15
    b.ne fail
    mov x14, #'A'
output:
    ldr x1, =0x40000100
    add x10, x10, #'0'
    strb w10, [x1]
    adr x15, hex
    ubfx x16, x11, #4, #2
    ldrb w16, [x15, x16]
    strb w16, [x1, #1]
    and x16, x11, #15
    ldrb w16, [x15, x16]
    strb w16, [x1, #2]
    strb w14, [x1, #3]
    strb wzr, [x1, #4]
    b print
fail:
    ldr x1, =0x40000100
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
hex:
    .ascii "0123456789abcdef"
    .ltorg
