.text
.global _start
_start:
    mov x20,#0x08000000
    ldr w0,[x20,#4]
    bl print_hex
    ldr w0,[x20]
    bl print_hex
    mov w0,#0x52
    str w0,[x20]
    ldr w0,[x20]
    bl print_hex
    ldr w0,[x20,#0x820]
    bl print_hex
    add x21,x20,#6,lsl#12
    add x21,x21,#0x100
    movz x0,#0x3456
    movk x0,#0x12,lsl#16
    movk x0,#0x78,lsl#32
    str x0,[x21]
    ldr x0,[x21]
    bl print_hex
    mov w0,#0xab
    str w0,[x21,#4]
    ldr x0,[x21]
    bl print_hex
    mov w0,#3
    str w0,[x21]
    ldr x0,[x21]
    bl print_hex
    str wzr,[x21,#4]
    ldr x0,[x21]
    bl print_hex
    ldr w22,[x20,#4]
    and w22,w22,#31
    mov w23,#1
    mov w24,#0
1:
    cmp w23,w22
    b.hi 3f
    add x25,x20,#0x100
    add x25,x25,x23,lsl#2
    mov w0,#-1
    str w0,[x25]
    ldr w0,[x25]
    cbz w0,2f
    clz w1,w0
    lsl w24,w23,#5
    add w24,w24,#31
    sub w24,w24,w1
2:
    add w23,w23,#1
    b 1b
3:
    mov w0,w24
    bl print_hex
    mov x0,#0x20
    adr x1,exit_block
    hlt #0xf000
4:
    wfi
    b 4b
print_hex:
    mov x9,x30
    mov x10,x0
    mov x11,#60
    mov x12,#0x09000000
5:
    lsr x13,x10,x11
    and w13,w13,#15
    cmp w13,#10
    add w14,w13,#'0'
    add w15,w13,#('a'-10)
    csel w14,w14,w15,lo
    strb w14,[x12]
    subs x11,x11,#4
    b.ge 5b
    mov w14,#10
    strb w14,[x12]
    ret x9
.balign 8
exit_block:
    .quad 0x20026,0
