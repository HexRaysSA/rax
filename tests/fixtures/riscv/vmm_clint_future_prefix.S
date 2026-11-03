/* Set every deadline 64 timer ticks in the future before the common guest. */
.option norvc
.set CLINT_TIMER_PRESET,1
.text
.globl _future_start
_future_start:
    csrr t3,mhartid
    slli t3,t3,3
    li t4,0x02004000
    add t3,t3,t4
    rdtime t4
    addi t4,t4,64
    sd t4,0(t3)
.include "vmm_clint.S"
