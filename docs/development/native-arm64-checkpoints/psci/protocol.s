// Native PSCI test protocol instructions, independently encoded by LLVM MC.
.text
.arch armv8-a
hvc #0
smc #0
ldr x10,[x11]
mov w0,#2
movk w0,#0x8400,lsl #16
hvc #0
mov w0,#8
movk w0,#0x8400,lsl #16
hvc #0
