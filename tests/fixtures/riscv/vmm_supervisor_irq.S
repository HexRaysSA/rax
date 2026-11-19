/* Bare-metal RV64 delegated supervisor software interrupt and SRET. */
.option norvc
.option norelax
.section .text
.globl _start
_start:
    csrr s0,mhartid
    lla s1,records
    slli t0,s0,2
    add s1,s1,t0
    lla s2,release
    lla t0,machine_trap
    csrw mtvec,t0
    lla t0,supervisor_vectors
    ori t0,t0,1
    csrw stvec,t0
    addi t0,s0,0x65
    csrw sscratch,t0
    li t0,2
    csrw mideleg,t0
    csrw mie,t0
    csrw mip,t0
    lla t0,supervisor_entry
    csrw mepc,t0
    li t0,0x802
    csrw mstatus,t0
    mret

supervisor_entry:
    lw t0,0(s1)
    li t1,1
    bne t0,t1,fail
    csrr t0,sstatus
    andi t0,t0,0x122
    li t1,0x22
    bne t0,t1,fail
    csrr t0,sip
    andi t0,t0,2
    bnez t0,fail
    li t0,2
    sw t0,0(s1)
    bnez s0,park
    lla s3,records
    lw s4,4(s2)
    li a4,65536
scan:
    mv t2,s3
    mv t3,s4
    li t1,2
scan_next:
    lw t0,0(t2)
    bne t0,t1,retry
    addi t2,t2,4
    addi t3,t3,-1
    bnez t3,scan_next
    li a0,0
    li t1,0x5555
    j finish
retry:
    addi a4,a4,-1
    bnez a4,scan
    j fail
park:
    wfi
    j park

.balign 4
supervisor_vectors:
    j fail
    j supervisor_software_irq

supervisor_software_irq:
    li t0,1
    sw t0,0(s1)
wait_release:
    lw t0,0(s2)
    beqz t0,wait_release
    csrr t0,scause
    li t1,1
    slli t1,t1,63
    ori t1,t1,1
    bne t0,t1,fail
    csrr t0,sepc
    lla t1,supervisor_entry
    bne t0,t1,fail
    csrr t0,stval
    bnez t0,fail
    csrr t0,sscratch
    addi t1,s0,0x65
    bne t0,t1,fail
    csrr t0,sstatus
    andi t0,t0,0x122
    li t1,0x120
    bne t0,t1,fail
    csrr t0,sip
    andi t0,t0,2
    beqz t0,fail
    csrci sip,2
    sret

machine_trap:
    j fail
fail:
    li a0,1
    li t1,0x3333
finish:
    li t0,0x100000
    sw t1,0(t0)
    li a7,93
    ecall
    j park

.balign 4
release:
    .word 1
hart_count:
    .word 4
records:
    .space 16
