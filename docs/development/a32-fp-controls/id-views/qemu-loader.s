.text
.global _start
_start:
    mov x20, #0x2000
    movk x20, #0x4008, lsl #16
    mrs x0, CurrentEL
    str w0, [x20]
    mrs x0, MVFR0_EL1
    str w0, [x20, #4]
    mrs x0, MVFR1_EL1
    str w0, [x20, #8]
    mrs x0, MVFR2_EL1
    str w0, [x20, #12]
    msr cptr_el2, xzr
    mov x0, #(3 << 20)
    msr cpacr_el1, x0
    mov x0, #(1 << 30)
    msr fpexc32_el2, x0
    msr hcr_el2, xzr
    mov x0, #0x1000
    movk x0, #0x4008, lsl #16
    msr elr_el2, x0
    mov x0, #SAVED_PSTATE
    msr spsr_el2, x0
    isb
    eret
    .balign 4096
    .incbin "a32.bin"
