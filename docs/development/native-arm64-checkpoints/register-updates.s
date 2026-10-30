.text
ldr x0,[x1]
str x0,[x1]
mov x2,#0xbad
mov x2,#0xbeef
mov w0,#8
movk w0,#0x8400,lsl #16
hvc #0
