.option norvc
.section .text
.globl _start, startup_count, startup_wait
_start:
 csrr t0,mhartid
 bne t0,a0,fail
 mv s11,sp
 addi t1,t0,1
 mv t6,t1
 li s0,0x80008000
 li t2,1
 amoadd.w.aqrl zero,t2,(s0)
startup_count:
 li a6,4
startup_wait:
 li a5,0
 beqz a5,go
 li s1,0x80008200
wait_go:
 lw t3,0(s1)
 beqz t3,wait_go
go:
 li t4,1
 addi s0,s0,0x100
 amoadd.w.aqrl zero,t4,(s0)
 bnez t0,park
 li t5,65536
wait_done:
 lw t3,0(s0)
 beq t3,a6,success
 addi t5,t5,-1
 bnez t5,wait_done
 j fail
success:
 fence r,rw
 mv t5,a6
 li a1,0x10000000
 li t1,82
 sb t1,0(a1)
 li t1,86
 sb t1,0(a1)
 addi t1,a6,48
 sb t1,0(a1)
 li t1,10
 sb t1,0(a1)
 # QEMU virt exits through its test finisher. RAX maps this address as RAM
 # and continues to its existing successful ECALL shutdown convention.
 li a1,0x100000
 li t1,0x5555
 sw t1,0(a1)
 li a7,93
 li a0,0
 ecall
park:
 wfi
 j park
fail:
 li t6,0xbad
 li a7,93
 li a0,1
 ecall
 j fail
