.syntax unified
.arm
.fpu neon
vadd.f64 d16, d0, d1
ldrex r2, [r1]
strex r3, r4, [r1]
ldrexb r2, [r1]
strexb r3, r4, [r1]
ldrexh r2, [r1]
strexh r3, r4, [r1]
ldrexd r2, r3, [r1]
strexd r6, r4, r5, [r1]
clrex
mov r0, r1
wfe
