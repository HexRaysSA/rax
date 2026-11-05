.syntax unified
.arch armv7-a
.fpu neon
.text
.arm
vshl.i8 d0, d0, #0
vshl.i64 d0, d0, #0
vshr.u64 d0, d0, #1
vshr.u64 d0, d0, #64
vsli.64 d0, d0, #0
vsri.64 d0, d0, #64
vqshl.s64 d0, d0, #0
vqshl.s64 d0, d0, #63
vqshlu.s64 d0, d0, #0
