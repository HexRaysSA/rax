// The oracle prefixes NR_CPUS=1,2,4. No stack or guest OS is required.
.global _start
.text
_start:
    mov x0, #7
    msr ICC_SRE_EL1, x0
    isb
    mov x0, #0x80
    msr ICC_PMR_EL1, x0
    mov x0, #0x08000000
    mov w1, #0x13
    str w1, [x0]
    adr x21, flags
    mov x22, #1
next_cpu:
    cmp x22, #NR_CPUS
    b.hs all_started
    mov x1, x22
    adr x2, secondary
    add x3, x22, #0x40
    mov x0, #3
    movk x0, #0xc400, lsl #16
    hvc #0
    cbnz x0, failure
    add x4, x21, x22, lsl #3
wait_started:
    ldar x5, [x4]
    cmp x5, #1
    b.ne wait_started
    mov x0, #7
    lsl x0, x0, #24
    mov x6, #1
    lsl x6, x6, x22
    orr x0, x0, x6
    msr ICC_SGI1R_EL1, x0
    isb
wait_irq_done:
    ldar x5, [x4]
    cmp x5, #2
    b.ne wait_irq_done
wait_off:
    mov x1, x22
    mov x2, #0
    mov x0, #4
    movk x0, #0xc400, lsl #16
    hvc #0
    cmp x0, #1
    b.ne wait_off
    mrs x0, ICC_PMR_EL1
    cmp x0, #0x80
    b.ne failure
    mov x0, #0x08000000
    ldr w0, [x0]
    tbz w0, #0, failure
    add x22, x22, #1
    b next_cpu
all_started:
    mov w1, #83
    b output
secondary:
    mrs x9, MPIDR_EL1
    and x9, x9, #0xff
    add x10, x9, #0x40
    cmp x0, x10
    b.ne failure
    mov x0, #7
    msr ICC_SRE_EL1, x0
    isb
    lsl x10, x9, #4
    add x10, x10, #0x80
    msr ICC_PMR_EL1, x10
    mrs x0, ICC_PMR_EL1
    cmp x0, x10
    b.ne failure
    mov x0, #0x08000000
    ldr w0, [x0]
    tbz w0, #0, failure
    adr x0, vectors
    msr VBAR_EL1, x0
    mov x0, #0x080a0000
    lsl x10, x9, #17
    add x10, x10, x0
    str wzr, [x10, #0x14]
    mov w0, #-1
    mov x11, #128
    movk x11, #1, lsl #16
    str w0, [x10, x11]
    mov w0, #0x80
    mov x11, #256
    movk x11, #1, lsl #16
    str w0, [x10, x11]
    mov w0, #0x40
    mov x11, #1031
    movk x11, #1, lsl #16
    strb w0, [x10, x11]
    mov x0, #1
    msr ICC_IGRPEN1_EL1, x0
    isb
    adr x4, flags
    add x4, x4, x9, lsl #3
    mov x0, #1
    stlr x0, [x4]
    msr DAIFClr, #2
wait_irq:
    msr DAIFSet, #2
    ldar x5, [x4]
    cmp x5, #2
    b.eq irq_done
    wfi
    msr DAIFClr, #2
    b wait_irq
irq_done:
    msr DAIFClr, #2
    mov x0, #2
    movk x0, #0x8400, lsl #16
    hvc #0
failure:
    mov w1, #70
output:
    mov x0, #0x09000000
    strb w1, [x0]
    mov x0, #8
    movk x0, #0x8400, lsl #16
    hvc #0
    b .
.balign 8
flags:
    .zero 32

.balign 2048
vectors:
    .space 0x280
irq_vector:
    mrs x10, ICC_IAR1_EL1
    cmp x10, #7
    b.ne failure
    msr ICC_EOIR1_EL1, x10
    adr x11, flags
    add x11, x11, x9, lsl #3
    mov x12, #2
    stlr x12, [x11]
    eret
