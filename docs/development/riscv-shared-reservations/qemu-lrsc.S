.section .text
.globl _start
_start:
    csrr t0, mhartid
    li s0, 0x80001000
    li s1, 0x80001100
    li s2, 0x80001200
    bnez t0, writer
    li s3, 1
next_case:
    li t0, 0x11111111
    sd t0, 0(s0)
    li t3, 0x33333333
    li t1, 4
    beq s3, t1, double_lr
    lr.w t2, (s0)
    j publish
double_lr:
    lr.d t2, (s0)
publish:
    fence w,w
    sw s3, 0(s1)
wait_done:
    lw t0, 0(s2)
    bne t0, s3, wait_done
    fence r,rw
    li t1, 4
    beq s3, t1, double_sc
    sc.w t4, t3, (s0)
    j output
double_sc:
    sc.d t4, t3, (s0)
output:
    addi t4, t4, 48
    li t0, 0x10000000
    sb t4, 0(t0)
    addi s3, s3, 1
    li t1, 5
    bne s3, t1, next_case
    li t1, 10
    sb t1, 0(t0)
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
halt:
    wfi
    j halt
writer:
    li s4, 0
wait_go:
    lw t0, 0(s1)
    beq t0, s4, wait_go
    fence r,rw
    li t1, 1
    beq t0, t1, different
    li t1, 3
    beq t0, t1, aba
    li t1, 4
    beq t0, t1, double_same
    li t1, 0x11111111
    sw t1, 0(s0)
    j acknowledge
different:
    li t1, 0x22222222
    sw t1, 0(s0)
    j acknowledge
aba:
    li t1, 0x22222222
    sw t1, 0(s0)
    li t1, 0x11111111
    sw t1, 0(s0)
    j acknowledge
double_same:
    li t1, 0x11111111
    sd t1, 0(s0)
acknowledge:
    fence w,w
    sw t0, 0(s2)
    mv s4, t0
    j wait_go
