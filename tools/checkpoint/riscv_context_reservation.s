.option norelax
.option norvc
.section .text
.global _start
_start:
    la a0, data
    la t2, tohost
    .rept 995
    nop
    .endr
.global checkpoint_frontier
checkpoint_frontier:
    lr.w t0, (a0)
    sc.w a1, t0, (a0)
    li t3, 0x10000000
    addi a1, a1, '0'
    sb a1, 0(t3)
    li t1, 1
    sd t1, 0(t2)
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.section .tohost,"aw",@progbits
.balign 8
.global tohost
tohost:
    .quad 0
data:
    .word 0x12345678
