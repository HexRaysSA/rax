.syntax unified
.fpu neon-vfpv4
.arm
vadd.i8 q0,q1,q2
vdup.8 q0,r1
vmov.8 d0[0],r1
vld1.8 {d0},[r0]!
vst1.8 {d0},[r0]!
vld2.8 {d0,d1},[r0]!
vst2.8 {d0,d1},[r0]!
vld3.8 {d0,d1,d2},[r0]!
vst3.8 {d0,d1,d2},[r0]!
vld4.8 {d0,d1,d2,d3},[r0]!
vst4.8 {d0,d1,d2,d3},[r0]!
