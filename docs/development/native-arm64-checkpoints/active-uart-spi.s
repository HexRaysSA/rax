.text
mov x9,#0x08000000
ldr w10,[x9]
orr w10,w10,#3
str w10,[x9]
mov w10,#2
str w10,[x9,#0x84]
str w10,[x9,#0x104]
movz w10,#0x8080
movk w10,#0x8080,lsl#16
str w10,[x9,#0x420]
str xzr,[x9,#0x6108]
mov w10,#7
msr icc_sre_el1,x10
mov w10,#0xff
msr icc_pmr_el1,x10
mov w10,#1
msr icc_igrpen1_el1,x10
isb
mrs x3,icc_iar1_el1
checkpoint_status:
ldr w8,[x7,#0x18]
continuation:
msr icc_eoir1_el1,x3
isb
mrs x4,icc_iar1_el1
ldrb w6,[x7]
msr icc_eoir1_el1,x4
isb
mrs x5,icc_iar1_el1
mov w0,#8
movk w0,#0x8400,lsl#16
hvc #0
