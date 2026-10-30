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
