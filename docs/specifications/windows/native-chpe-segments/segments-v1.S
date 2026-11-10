.text
.globl read_selectors
read_selectors:
 movw %cs, %ax
 movw %ax, 0(%rcx)
 movw %ss, %ax
 movw %ax, 2(%rcx)
 movw %ds, %ax
 movw %ax, 4(%rcx)
 movw %es, %ax
 movw %ax, 6(%rcx)
 movw %fs, %ax
 movw %ax, 8(%rcx)
 movw %gs, %ax
 movw %ax, 10(%rcx)
 retq
.globl read_fsbase
read_fsbase:
 .byte 0xf3,0x48,0x0f,0xae,0xc0
 retq
.globl read_gsbase
read_gsbase:
 .byte 0xf3,0x48,0x0f,0xae,0xc8
 retq
.globl read_descriptor
read_descriptor:
 xorl %eax, %eax
 larl %ecx, %eax
 setz 8(%rdx)
 movl %eax, 0(%rdx)
 xorl %eax, %eax
 lsll %ecx, %eax
 setz 9(%rdx)
 movl %eax, 4(%rdx)
 retq
