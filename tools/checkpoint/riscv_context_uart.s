.option norelax
.option norvc
.section .text
.global _start
_start:
    li t0, 0x200
    csrs mstatus, t0
    vsetivli zero, 4, e8, m1, ta, ma
    la a0, payload
    vle8.v v1, (a0)
    li a0, 0x10000000
    li t0, 7
    sb t0, 2(a0)
    li a1, 0
.global checkpoint_frontier
checkpoint_frontier:
    vsse8.v v1, (a0), a1
2:  lbu t0, 5(a0)
    andi t0, t0, 0x40
    beqz t0, 2b
    la t0, tohost
    li t1, 1
    sd t1, 0(t0)
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
1:  j 1b
.section .rodata
payload:
    .ascii "ABCD"
.section .tohost,"aw",@progbits
.balign 8
.global tohost
tohost:
    .quad 0
