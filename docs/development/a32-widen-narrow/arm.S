.syntax unified
.arch armv7-a
.fpu neon
.arm
vshll.s8 q0, d2, #1
vshll.s8 q0, d2, #7
vshll.u8 q0, d2, #1
vshll.u8 q0, d2, #7
vshll.s16 q0, d2, #1
vshll.s16 q0, d2, #15
vshll.u16 q0, d2, #1
vshll.u16 q0, d2, #15
vshll.s32 q0, d2, #1
vshll.s32 q0, d2, #31
vshll.u32 q0, d2, #1
vshll.u32 q0, d2, #31
vshll.i8 q0, d2, #8
vshll.i16 q0, d2, #16
vshll.i32 q0, d2, #32
