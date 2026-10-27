.section .text
.global _start
_start:
    csrr t0, mhartid
    li t1, 0x10000000
    addi t2, t0, 48
    sb t2, 0(t1)
    fence iorw, iorw
    la t1, completed
    li t2, 1
    amoadd.w.aqrl t3, t2, (t1)
    addi t3, t3, 1
    li t4, NHARTS
    bne t3, t4, parked
    li t1, 0x100000
    li t2, 0x5555
    sw t2, 0(t1)
parked:
    wfi
    j parked
.section .bss
.balign 4
completed:
    .word 0
