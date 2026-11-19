/* Virt PLIC UART IRQ 10. Every hart handles both M and S contexts in turn. */
.option norvc
.option norelax
.section .text
.globl _start
_start:
    csrr s0,mhartid
    lla s1,shared
    lw s2,8(s1)
    li s3,0x0c000000
    li s4,0x10000000
    li s5,0x400
    slli t0,s0,8
    li s6,0x0c002000
    add s6,s6,t0
    slli t0,s0,13
    li s7,0x0c200000
    add s7,s7,t0
    li t1,0x1000
    add s8,s7,t1
    slli t0,s0,2
    add s9,s1,t0
    addi s9,s9,16

    lla t0,machine_handler
    csrw mtvec,t0
    lla t0,supervisor_handler
    csrw stvec,t0
wait_turn:
    lw t0,0(s1)
    bne t0,s0,wait_turn

    /* MEI: controller pending; mstatus.MIE admits the trap at m_after. */
    li t0,3
    sw t0,40(s3)
    sw s5,0(s6)
    li t0,2
    sb t0,1(s4)
    li t0,0x800
    csrs mie,t0
    csrsi mstatus,8
m_after:
    li a0,1
    lw t0,0(s9)
    li t1,1
    bne t0,t1,fail
    li t0,0x200
    csrs mideleg,t0
    csrs sie,t0
    lla t0,s_entry
    csrw mepc,t0
    li t0,0x1800
    csrc mstatus,t0
    li t0,0x800
    csrs mstatus,t0
    mret

s_entry:
    /* SEI: same UART, separate per-hart supervisor enable/claim target. */
    sw s5,128(s6)
    li t0,2
    sb t0,1(s4)
    csrsi sstatus,2
s_after:
    li a0,2
    lw t0,0(s9)
    li t1,2
    bne t0,t1,fail
    li t0,3
    sw t0,0(s9)
    addi t0,s0,1
    sw t0,0(s1)
    beq t0,s2,success
finished:
    j finished

machine_handler:
    li a0,3
    csrr t0,mcause
    li t1,1
    slli t1,t1,63
    addi t1,t1,11
    bne t0,t1,fail
    csrr t0,mepc
    lla t1,m_after
    bne t0,t1,fail
    lw t0,4(s7)
    li t1,10
    bne t0,t1,fail
    li a0,4
    lbu t0,2(s4)
    andi t0,t0,15
    li t2,2
    bne t0,t2,fail
    sb zero,1(s4)
    sw t1,4(s7)
    lw t0,4(s7)
    bnez t0,fail
    sw zero,0(s6)
    li t0,1
    sw t0,0(s9)
    mret

supervisor_handler:
    li a0,5
    csrr t0,scause
    li t1,1
    slli t1,t1,63
    addi t1,t1,9
    bne t0,t1,fail
    csrr t0,sepc
    lla t1,s_after
    bne t0,t1,fail
    lw t0,4(s8)
    li t1,10
    bne t0,t1,fail
    li t0,2
    sw t0,0(s9)
hold_in_service:
    lw t0,4(s1)
    beqz t0,hold_in_service
    li a0,6
    csrr t0,sip
    andi t0,t0,0x200
    bnez t0,fail
    lw t0,4(s8)
    bnez t0,fail
    lw t0,12(s1)
    andi t0,t0,1
    beqz t0,skip_repend
    /* The specification requires a still-asserted source to re-pend. */
    li a0,7
    sw t1,4(s8)
    lw t0,4(s8)
    bne t0,t1,fail
skip_repend:
    li a0,8
    lbu t0,2(s4)
    andi t0,t0,15
    li t2,2
    bne t0,t2,fail
    sb zero,1(s4)
    sw t1,4(s8)
    lw t0,4(s8)
    bnez t0,fail
    sw zero,128(s6)
    sret

success:
    li a0,0
    li t1,0x5555
    j finish
fail:
    slli t1,a0,16
    li t0,0x3333
    or t1,t1,t0
finish:
    li t0,0x100000
    sw t1,0(t0)
    lw t0,12(s1)
    andi t0,t0,2
    beqz t0,1f
    li a7,93
    ecall
1:  j 1b

.balign 4
.globl shared
shared:
    .word 0        /* turn */
    .word 1        /* release in-service handler */
    .word 1        /* number of harts */
    .word 0        /* bit 0 check spec re-pend, bit 1 issue RAX ecall */
    .zero 16       /* per-hart stage */
