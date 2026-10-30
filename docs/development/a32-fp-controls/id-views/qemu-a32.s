.syntax unified
.arch armv8.2-a
.fpu neon-fp-armv8
EXECUTION_MODE
.text
.global _start
_start:
    movw r4, #0x2000
    movt r4, #0x4008
    vmrs r0, mvfr0
    vmrs r1, mvfr1
    vmrs r2, mvfr2
    str r0, [r4, #16]
    str r1, [r4, #20]
    str r2, [r4, #24]
    mov r5, #7
    movw r3, #0
    movt r3, #0x0900
1:
    ldr r0, [r4], #4
    bl print_hex
    subs r5, r5, #1
    bne 1b
    mov r0, #0x18
    movw r1, #0x26
    movt r1, #2
SEMIHOST_EXIT
2:  b 2b
print_hex:
    mov r1, r0
    mov r2, #8
3:
    lsr r0, r1, #28
    cmp r0, #10
    bhs 4f
    add r0, r0, #48
    b 5f
4:  add r0, r0, #87
5:  strb r0, [r3]
    lsl r1, r1, #4
    subs r2, r2, #1
    bne 3b
    mov r0, #10
    strb r0, [r3]
    bx lr
