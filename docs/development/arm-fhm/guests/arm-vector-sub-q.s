
.global _start
.text
_start:
 mov x4, #0x09000000
 adr x0, vectors
 msr vbar_el1, x0
 mov x0, #(3<<20)
 msr cpacr_el1, x0
 isb
 movi v0.16b, #0
 movi v1.16b, #0
 movi v2.16b, #0
 movi v3.16b, #0
 mrs x0, s3_0_c0_c2_7
 ubfx x1, x0, #8, #4
 add w1, w1, #48
 strb w1, [x4]
 adr x0, arm_entry
 msr elr_el1, x0
 mov x0, #0x10
 msr spsr_el1, x0
 eret
.balign 4
arm_entry:
.word 0xfca20853
.word 0xef000042
.word 0xeafffffe
.balign 2048
vectors:
.rept 16
 b handler
 .space 124
.endr
handler:
 mrs x0, esr_el1
 ubfx x0, x0, #26, #6
 mov w1, #69
 cbz x0, undef
 cmp x0, #0x11
 b.ne finish
 mov w1, #80
 b finish
undef:
 mov w1, #85
finish:
 strb w1, [x4]
 mov w0, #8
 movk w0, #0x8400, lsl #16
 hvc #0
 b .
