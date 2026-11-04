 .syntax unified
.thumb
.fpu neon
vmov s0,r0
vmov r0,s0
vmov.32 d0[0],r0
vmov.32 r0,d0[0]
vmov.16 d0[0],r0
vmov.s16 r0,d0[0]
vmov.u16 r0,d0[0]
vmov.8 d0[0],r0
vmov.s8 r0,d0[0]
vmov.u8 r0,d0[0]
