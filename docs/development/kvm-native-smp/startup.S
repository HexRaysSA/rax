.section .text.bsp,"ax"
.code64
.global bsp_start
bsp_start:
 cli
 cld
 movl $0x1001200, %esi
 movl $0x20000, %edi
 movl $256, %ecx
 rep movsb
 movabs $0x00cf9a000000ffff, %rax
 movq %rax, 0x7308
 movabs $0x00cf92000000ffff, %rax
 movq %rax, 0x7310
 movw $23, 0x7200
 movl $0x7300, 0x7202
 movl $(0x20000 + isr - ap_start), %eax
 movl %eax, %ebx
 andl $0xffff, %ebx
 orl $0x80000, %ebx
 movl %ebx, 0x240208
 andl $0xffff0000, %eax
 orl $0x8e00, %eax
 movl %eax, 0x24020c
 movw $0x20f, 0x7410
 movl $0x240000, 0x7412
 xorl %eax, %eax
 cpuid
 movl %eax, 0x230000
 movl $0xb, %eax
 xorl %ecx, %ecx
 cpuid
 movl %edx, 0x230004
 movl %ebx, 0x23000c
 movl $0x1f, %eax
 xorl %ecx, %ecx
 cpuid
 movl %edx, 0x230008
 movl %ebx, 0x230010
 movl $1, %eax
 cpuid
 shrl $24, %ebx
 movl %ebx, 0x220000
 movl $0xfee00000, %edx
 movl $0x1ff, 0xf0(%rdx)
 movl $0xa5a55a5a, 0x200000
 movl $0xc4500, 0x300(%rdx)
 outb %al, $0x80
 movl $0xc8500, 0x300(%rdx)
 outb %al, $0x80
 movl $0xc0620, 0x300(%rdx)
 outb %al, $0x80
 movl $1000, %ebp
poll:
 movl 0x210000, %ecx
 xorl %ebx, %ebx
check:
 cmpl $0xa5a55a5a, 0x200000(,%rbx,8)
 jne waiting
 incl %ebx
 cmpl %ecx, %ebx
 jb check
 movl $1, %edi
send_fixed:
 movl $0xc0041, 0x300(%rdx)
 outb %al, $0x80
 movl $1000, %ebp
poll_irq:
 movl 0x210000, %ecx
 movl $1, %ebx
check_irq:
 cmpl %ecx, %ebx
 jae irq_done
 cmpl %edi, 0x200004(,%rbx,8)
 jne wait_irq
 incl %ebx
 jmp check_irq
wait_irq:
 outb %al, $0x80
 decl %ebp
 jnz poll_irq
 movl $0xbad1bad1, 0x210004
 jmp shutdown
irq_done:
 incl %edi
 cmpl $3, %edi
 jb send_fixed
 movl $0x600d600d, 0x210004
 jmp shutdown
waiting:
 outb %al, $0x80
 decl %ebp
 jnz poll
 movl $0xbad0bad0, 0x210004
shutdown:
 movl $0x604, %edx
 movl $0x2000, %eax
 outw %ax, %dx
 hlt
.section .text.ap,"ax"
.code16
.global ap_start
ap_start:
 cli
 xorw %ax, %ax
 movw %ax, %ds
 movw %ax, %es
 movw %ax, %ss
 lgdtl 0x7200
 movl %cr0, %eax
 orl $1, %eax
 movl %eax, %cr0
 ljmpl $8, $(0x20000 + ap32 - ap_start)
.code32
ap32:
 movw $16, %ax
 movw %ax, %ds
 movw %ax, %es
 movw %ax, %ss
 movl 0xfee00020, %ebp
 shrl $24, %ebp
 movl %ebp, %edi
 shll $5, %edi
 xorl %eax, %eax
 cpuid
 movl %eax, 0x230000(%edi)
 movl $0xb, %eax
 xorl %ecx, %ecx
 cpuid
 movl %edx, 0x230004(%edi)
 movl %ebx, 0x23000c(%edi)
 movl $0x1f, %eax
 xorl %ecx, %ecx
 cpuid
 movl %edx, 0x230008(%edi)
 movl %ebx, 0x230010(%edi)
 movl $1, %eax
 cpuid
 shrl $24, %ebx
 movl %ebx, 0x220000(,%ebp,4)
 movl $0x400000, %esp
 movl %ebp, %eax
 shll $12, %eax
 subl %eax, %esp
 lidtl 0x7410
 movl $0x1ff, 0xfee000f0
 movl $0xa5a55a5a, 0x200000(,%ebp,8)
 sti
halt:
 hlt
 jmp halt
isr:
 pushal
 incl 0x200004(,%ebp,8)
 movl $0, 0xfee000b0
 popal
 iretl
