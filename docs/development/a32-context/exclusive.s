.syntax unified
.arch armv7-a
.arm
.text
ldrex r1, [r2]
strex r3, r1, [r2]
