/* RV64 machine-mode CLINT witness; assembled with LLVM, no compressed forms. */
.option norvc
.section .text
.globl _start
_start:
    csrr s1,mhartid
    lla t0,handler
    csrw mtvec,t0
    li t0,0x88
    csrw mie,t0
    slli t0,s1,3
    li t1,0x02004000
    add t0,t0,t1
timer_store:
.ifdef CLINT_TIMER_PRESET
    nop
.else
    sd zero,0(t0)
.endif
    li s0,0x80008000
    li t0,1
    amoadd.w.aqrl zero,t0,(s0)
count_patch:
    li s2,4
wait_patch:
    li a5,0
    bnez s1,wait_go
    li a4,65536
ready:
    lw t0,0(s0)
    beq t0,s2,send
    addi a4,a4,-1
    bnez a4,ready
    j fail
send:
    li t0,0
    li t1,0x02000000
    li t2,1
send_next:
    sw t2,0(t1)
    addi t1,t1,4
    addi t0,t0,1
    blt t0,s2,send_next
    sw t2,8(s0)
wait_go:
    beqz a5,enable
    lw t0,4(s0)
    beqz t0,wait_go
enable:
    li t0,8
    csrs mstatus,t0
    bnez s1,park
    li a4,65536
check_all:
    li t0,0
    li t1,0x80008100
check_next:
    lw t2,0(t1)
    li a3,3
    bne t2,a3,retry
    addi t1,t1,4
    addi t0,t0,1
    blt t0,s2,check_next
    li a1,0x100000
    li t1,0x5555
    sw t1,0(a1)
    li a7,93
    li a0,0
    ecall
retry:
    addi a4,a4,-1
    bnez a4,check_all
    j fail
park:
    wfi
    j park
.balign 4
handler:
    csrr t3,mcause
    andi t3,t3,0x7ff
    li t4,3
    beq t3,t4,software
    li t4,7
    bne t3,t4,fail
    slli t5,s1,3
    li t4,0x02004000
    add t5,t5,t4
    li t6,-1
    sd t6,0(t5)
    li t6,2
    j publish
software:
    slli t5,s1,2
    li t4,0x02000000
    add t5,t5,t4
    sw zero,0(t5)
    li t6,1
publish:
    slli t5,s1,2
    li t4,0x80008100
    add t5,t5,t4
    amoor.w.aqrl zero,t6,(t5)
    mret
fail:
    li a7,93
    li a0,1
    ecall
    j fail
