.macro capture_profile
 movl $0x0, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 0(%edi)
 movl %ebx, 4(%edi)
 movl %ecx, 8(%edi)
 movl %edx, 12(%edi)
 movl $0x1, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 16(%edi)
 movl %ebx, 20(%edi)
 movl %ecx, 24(%edi)
 movl %edx, 28(%edi)
 movl $0x80000000, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 32(%edi)
 movl %ebx, 36(%edi)
 movl %ecx, 40(%edi)
 movl %edx, 44(%edi)
 movl $0x80000001, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 48(%edi)
 movl %ebx, 52(%edi)
 movl %ecx, 56(%edi)
 movl %edx, 60(%edi)
 movl $0x80000008, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 64(%edi)
 movl %ebx, 68(%edi)
 movl %ecx, 72(%edi)
 movl %edx, 76(%edi)
 movl $0x8000001e, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 80(%edi)
 movl %ebx, 84(%edi)
 movl %ecx, 88(%edi)
 movl %edx, 92(%edi)
 movl $0x15, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 96(%edi)
 movl %ebx, 100(%edi)
 movl %ecx, 104(%edi)
 movl %edx, 108(%edi)
 movl $0x4, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 112(%edi)
 movl %ebx, 116(%edi)
 movl %ecx, 120(%edi)
 movl %edx, 124(%edi)
 movl $0x4, %eax
 movl $1, %ecx
 cpuid
 movl %eax, 128(%edi)
 movl %ebx, 132(%edi)
 movl %ecx, 136(%edi)
 movl %edx, 140(%edi)
 movl $0x4, %eax
 movl $2, %ecx
 cpuid
 movl %eax, 144(%edi)
 movl %ebx, 148(%edi)
 movl %ecx, 152(%edi)
 movl %edx, 156(%edi)
 movl $0x4, %eax
 movl $3, %ecx
 cpuid
 movl %eax, 160(%edi)
 movl %ebx, 164(%edi)
 movl %ecx, 168(%edi)
 movl %edx, 172(%edi)
 movl $0x4, %eax
 movl $4, %ecx
 cpuid
 movl %eax, 176(%edi)
 movl %ebx, 180(%edi)
 movl %ecx, 184(%edi)
 movl %edx, 188(%edi)
 movl $0x4, %eax
 movl $5, %ecx
 cpuid
 movl %eax, 192(%edi)
 movl %ebx, 196(%edi)
 movl %ecx, 200(%edi)
 movl %edx, 204(%edi)
 movl $0x4, %eax
 movl $6, %ecx
 cpuid
 movl %eax, 208(%edi)
 movl %ebx, 212(%edi)
 movl %ecx, 216(%edi)
 movl %edx, 220(%edi)
 movl $0x4, %eax
 movl $7, %ecx
 cpuid
 movl %eax, 224(%edi)
 movl %ebx, 228(%edi)
 movl %ecx, 232(%edi)
 movl %edx, 236(%edi)
 movl $0x8000001d, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 240(%edi)
 movl %ebx, 244(%edi)
 movl %ecx, 248(%edi)
 movl %edx, 252(%edi)
 movl $0x8000001d, %eax
 movl $1, %ecx
 cpuid
 movl %eax, 256(%edi)
 movl %ebx, 260(%edi)
 movl %ecx, 264(%edi)
 movl %edx, 268(%edi)
 movl $0x8000001d, %eax
 movl $2, %ecx
 cpuid
 movl %eax, 272(%edi)
 movl %ebx, 276(%edi)
 movl %ecx, 280(%edi)
 movl %edx, 284(%edi)
 movl $0x8000001d, %eax
 movl $3, %ecx
 cpuid
 movl %eax, 288(%edi)
 movl %ebx, 292(%edi)
 movl %ecx, 296(%edi)
 movl %edx, 300(%edi)
 movl $0x8000001d, %eax
 movl $4, %ecx
 cpuid
 movl %eax, 304(%edi)
 movl %ebx, 308(%edi)
 movl %ecx, 312(%edi)
 movl %edx, 316(%edi)
 movl $0x8000001d, %eax
 movl $5, %ecx
 cpuid
 movl %eax, 320(%edi)
 movl %ebx, 324(%edi)
 movl %ecx, 328(%edi)
 movl %edx, 332(%edi)
 movl $0x8000001d, %eax
 movl $6, %ecx
 cpuid
 movl %eax, 336(%edi)
 movl %ebx, 340(%edi)
 movl %ecx, 344(%edi)
 movl %edx, 348(%edi)
 movl $0x8000001d, %eax
 movl $7, %ecx
 cpuid
 movl %eax, 352(%edi)
 movl %ebx, 356(%edi)
 movl %ecx, 360(%edi)
 movl %edx, 364(%edi)
 movl $0xb, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 368(%edi)
 movl %ebx, 372(%edi)
 movl %ecx, 376(%edi)
 movl %edx, 380(%edi)
 movl $0xb, %eax
 movl $1, %ecx
 cpuid
 movl %eax, 384(%edi)
 movl %ebx, 388(%edi)
 movl %ecx, 392(%edi)
 movl %edx, 396(%edi)
 movl $0xb, %eax
 movl $2, %ecx
 cpuid
 movl %eax, 400(%edi)
 movl %ebx, 404(%edi)
 movl %ecx, 408(%edi)
 movl %edx, 412(%edi)
 movl $0xb, %eax
 movl $3, %ecx
 cpuid
 movl %eax, 416(%edi)
 movl %ebx, 420(%edi)
 movl %ecx, 424(%edi)
 movl %edx, 428(%edi)
 movl $0x1f, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 432(%edi)
 movl %ebx, 436(%edi)
 movl %ecx, 440(%edi)
 movl %edx, 444(%edi)
 movl $0x1f, %eax
 movl $1, %ecx
 cpuid
 movl %eax, 448(%edi)
 movl %ebx, 452(%edi)
 movl %ecx, 456(%edi)
 movl %edx, 460(%edi)
 movl $0x1f, %eax
 movl $2, %ecx
 cpuid
 movl %eax, 464(%edi)
 movl %ebx, 468(%edi)
 movl %ecx, 472(%edi)
 movl %edx, 476(%edi)
 movl $0x1f, %eax
 movl $3, %ecx
 cpuid
 movl %eax, 480(%edi)
 movl %ebx, 484(%edi)
 movl %ecx, 488(%edi)
 movl %edx, 492(%edi)
 movl $0x80000026, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 496(%edi)
 movl %ebx, 500(%edi)
 movl %ecx, 504(%edi)
 movl %edx, 508(%edi)
 movl $0x80000026, %eax
 movl $1, %ecx
 cpuid
 movl %eax, 512(%edi)
 movl %ebx, 516(%edi)
 movl %ecx, 520(%edi)
 movl %edx, 524(%edi)
 movl $0x80000026, %eax
 movl $2, %ecx
 cpuid
 movl %eax, 528(%edi)
 movl %ebx, 532(%edi)
 movl %ecx, 536(%edi)
 movl %edx, 540(%edi)
 movl $0x80000026, %eax
 movl $3, %ecx
 cpuid
 movl %eax, 544(%edi)
 movl %ebx, 548(%edi)
 movl %ecx, 552(%edi)
 movl %edx, 556(%edi)
 movl $0x80000026, %eax
 movl $4, %ecx
 cpuid
 movl %eax, 560(%edi)
 movl %ebx, 564(%edi)
 movl %ecx, 568(%edi)
 movl %edx, 572(%edi)
 movl $0x40000000, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 576(%edi)
 movl %ebx, 580(%edi)
 movl %ecx, 584(%edi)
 movl %edx, 588(%edi)
 movl $0x40000001, %eax
 movl $0, %ecx
 cpuid
 movl %eax, 592(%edi)
 movl %ebx, 596(%edi)
 movl %ecx, 600(%edi)
 movl %edx, 604(%edi)
.endm
.macro enable_clock
 movl $1, %eax
 xorl %ecx, %ecx
 cpuid
 btl $31, %ecx
 jnc .Lno_clock\@
 movl $0x40000001, %eax
 xorl %ecx, %ecx
 cpuid
 testl $8, %eax
 jz .Lno_clock\@
 movl %edi, %eax
 movl $0x4b564d01, %ecx
 xorl %edx, %edx
 wrmsr
.Lno_clock\@:
.endm
.section .text.bsp,"ax"
.code64
.global bsp_start
bsp_start:
 cli
 cld
 movl $0x1001200, %esi
 movl $0x20000, %edi
 movl $4096, %ecx
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
 movl $0x250000, %edi
 capture_profile
 movl $0x260001, %edi
 enable_clock
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
 shll $10, %edi
 addl $0x250000, %edi
 capture_profile
 movl %ebp, %edi
 shll $12, %edi
 addl $0x260001, %edi
 enable_clock
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
