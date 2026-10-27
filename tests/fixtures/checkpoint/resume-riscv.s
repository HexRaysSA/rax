.option norelax
.section .text
.global _start
_start:
    li t0, 0x10000000
    li t1, 'R'
    sb t1, 0(t0)
    li t1, 'A'
    sb t1, 0(t0)
    li t1, 'X'
    sb t1, 0(t0)
    li t1, 10
    sb t1, 0(t0)
    la t0, tohost
    li t1, 1
    sd t1, 0(t0)
1:  j 1b
.section .tohost,"aw",@progbits
.balign 8
.global tohost
tohost:
    .quad 0
