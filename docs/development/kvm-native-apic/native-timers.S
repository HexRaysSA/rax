.macro arm_timer
    movl $0xfee00000, %esi
    movl $0x1ff, 0x0f0(%esi)
    cmpl $0, 0x210008
    je .Lperiodic\@
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    btl $24, %ecx
    jnc .Lmissing\@
    movl $0xfee00000, %esi
    movl $0x40042, 0x320(%esi)
    rdtsc
    addl $100000000, %eax
    adcl $0, %edx
    movl $0x6e0, %ecx
    wrmsr
    jmp .Larmed\@
.Lperiodic\@:
    movl $0xfee00000, %esi
    movl $3, 0x3e0(%esi)
    movl $0xfee00000, %esi
    movl $0x20042, 0x320(%esi)
    movl $0xfee00000, %esi
    movl $625000, 0x380(%esi)
    jmp .Larmed\@
.Lmissing\@:
    movl $1, 0x220000(,%ebp,4)
.Larmed\@:
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
    movl $(0x20000 + ap_isr - ap_start), %eax
    movl %eax, %ebx
    andl $0xffff, %ebx
    orl $0x80000, %ebx
    movl %ebx, 0x240210
    andl $0xffff0000, %eax
    orl $0x8e00, %eax
    movl %eax, 0x240214
    movw $0x217, 0x7410
    movl $0x240000, 0x7412
    leaq bsp_isr(%rip), %rax
    movq %rax, %rbx
    andq $0xffff, %rbx
    orq $0x100000, %rbx
    movl %ebx, 0x241420
    shrq $16, %rax
    shlq $16, %rax
    orq $0x8e00, %rax
    movl %eax, 0x241424
    movl $0, 0x241428
    movw $0x42f, 0x7420
    movq $0x241000, 0x7422
    lidt 0x7420
    xorl %ebp, %ebp
    movl $0xfee00000, %edx
    movl $0x1ff, 0xf0(%rdx)
    movl $0xc4500, 0x300(%rdx)
    outb %al, $0x80
    movl $0xc8500, 0x300(%rdx)
    outb %al, $0x80
    movl $0xc0620, 0x300(%rdx)
    outb %al, $0x80
    arm_timer
    movl $0xa5a55a5a, 0x200000
    sti
    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    movabs $35000000000, %r8
    addq %rax, %r8
bsp_poll:
    movl 0x210000, %ecx
    xorl %ebx, %ebx
bsp_check:
    cmpl $0, 0x220000(,%rbx,4)
    jne missing
    cmpl $0xa5a55a5a, 0x200000(,%rbx,8)
    jne bsp_wait
    cmpl $2, 0x200004(,%rbx,8)
    jb bsp_wait
    incl %ebx
    cmpl %ecx, %ebx
    jb bsp_check
    movl $0x600d0042, 0x210004
    jmp shutdown
bsp_wait:
    outb %al, $0x80
    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    cmpq %r8, %rax
    jb bsp_poll
    movl $0xbad00042, 0x210004
    jmp shutdown
missing:
    movl $0xbad10042, 0x210004
shutdown:
    cli
    movl $0x604, %edx
    movl $0x2000, %eax
    outw %ax, %dx
    hlt
bsp_isr:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    incl 0x200004
    cmpl $2, 0x200004
    jb bsp_rearm
    movl $0xfee00000, %esi
    movl $0x10042, 0x320(%esi)
    jmp bsp_eoi
bsp_rearm:
    cmpl $0, 0x210008
    je bsp_eoi
    rdtsc
    addl $100000000, %eax
    adcl $0, %edx
    movl $0x6e0, %ecx
    wrmsr
bsp_eoi:
    movl $0xfee00000, %esi
    movl $0, 0x0b0(%esi)
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
    iretq
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
    movl $0x400000, %esp
    movl %ebp, %eax
    shll $12, %eax
    subl %eax, %esp
    lidtl 0x7410
    arm_timer
    movl $0xa5a55a5a, 0x200000(,%ebp,8)
    sti
ap_halt:
    hlt
    jmp ap_halt
ap_isr:
    pushal
    incl 0x200004(,%ebp,8)
    cmpl $2, 0x200004(,%ebp,8)
    jb ap_rearm
    movl $0xfee00000, %esi
    movl $0x10042, 0x320(%esi)
    jmp ap_eoi
ap_rearm:
    cmpl $0, 0x210008
    je ap_eoi
    rdtsc
    addl $100000000, %eax
    adcl $0, %edx
    movl $0x6e0, %ecx
    wrmsr
ap_eoi:
    movl $0xfee00000, %esi
    movl $0, 0x0b0(%esi)
    popal
    iretl
