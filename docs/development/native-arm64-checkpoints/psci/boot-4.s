.text
.arch armv8-a
.global _start
_start:
ldr x20,=0x40010100
ldr x21,=0x40010000
ldr x11,=0x09000000
mov w0,#3
movk w0,#0xc400,lsl #16
mov x1,#1
ldr x2,=ap1
ldr x3,=1073807368
hvc #0
str x0,[x20,#8]
mov w0,#3
movk w0,#0xc400,lsl #16
mov x1,#2
ldr x2,=ap2
ldr x3,=1073807376
hvc #0
str x0,[x20,#16]
mov w0,#3
movk w0,#0xc400,lsl #16
mov x1,#3
ldr x2,=ap3
ldr x3,=1073807384
hvc #0
str x0,[x20,#24]
mov x0,x21
mov x7,#0x1000
loop0:
add x7,x7,#1
str x7,[x0]
ldr x8,[x11]
b loop0
.ltorg
.balign 256
ap1:
mov x7,#8192
ldr x11,=0x09000000
loop1:
add x7,x7,#1
str x7,[x0]
ldr x8,[x11]
b loop1
.ltorg
.balign 256
ap2:
mov x7,#12288
ldr x11,=0x09000000
loop2:
add x7,x7,#1
str x7,[x0]
ldr x8,[x11]
b loop2
.ltorg
.balign 256
ap3:
mov x7,#16384
ldr x11,=0x09000000
loop3:
add x7,x7,#1
str x7,[x0]
ldr x8,[x11]
b loop3
.ltorg
