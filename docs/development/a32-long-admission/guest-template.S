.syntax unified
.arch armv7-a
.fpu neon
.arm
.section .text
.global _start
_start:
 b start
 b undef
 b .
 b .
 b .
 b .
 b .
 b .
start:
 ldr r0, =_start
 mcr p15, 0, r0, c12, c0, 0
 mrc p15, 0, r0, c1, c0, 2
 orr r0, r0, #0x00f00000
 mcr p15, 0, r0, c1, c0, 2
 isb
 mov r0, #0x40000000
 vmsr fpexc, r0
 ldr r0, =0x03020100
 ldr r1, =0x07060504
 vmov d0, r0, r1
 ldr r0, =0x12345678
 ldr r1, =0x9abcdef0
 vmov d1, r0, r1
 mov r8, #'L'
 ldr r9, =after
 ENTER_MODE
case:
 CASE_INSTRUCTION
after:
 ldr r3, =finish
 bx r3
.arm
undef:
 mov r8, #'U'
 movs pc, r9
finish:
 ldr r4, =0x09000000
 str r8, [r4]
 vmov r0, r1, d0
 bl puthex
 mov r0, r1
 bl puthex
 vmov r0, r1, d1
 bl puthex
 mov r0, r1
 bl puthex
 mov r0, #10
 str r0, [r4]
 mov r0, #0x18
 ldr r1, =0x20026
 svc 0x123456
 b .
puthex:
 mov r2, #8
1:
 mov r3, r0, lsr #28
 cmp r3, #10
 addlo r3, r3, #'0'
 addhs r3, r3, #('a'-10)
 str r3, [r4]
 lsl r0, r0, #4
 subs r2, r2, #1
 bne 1b
 bx lr
 .ltorg
