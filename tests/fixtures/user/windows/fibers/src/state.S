/* Nonvolatile register/SP probes; no SDK assembly includes or unwind tables. */
#if defined(__i386__)
.def @feat.00; .scl 3; .type 0; .endef
.set @feat.00, 1 /* No hand-written exception handlers; SafeSEH-compatible object. */
.text
.globl _ProbeSwitch
_ProbeSwitch:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    subl $20, %esp
    movl 40(%esp), %eax
    movl %eax, 0(%esp)
    movl 44(%esp), %eax
    movl %eax, 4(%esp)
    movl %esp, 8(%esp)
    leal 1(%eax), %ebx
    leal 2(%eax), %esi
    leal 3(%eax), %edi
    leal 4(%eax), %ebp
    pushl 0(%esp)
    calll *__imp__SwitchToFiber@4
    movl $1, %edx
    cmpl 8(%esp), %esp
    jne 1f
    movl 4(%esp), %eax
    addl $1, %eax
    cmpl %eax, %ebx
    jne 1f
    addl $1, %eax
    cmpl %eax, %esi
    jne 1f
    addl $1, %eax
    cmpl %eax, %edi
    jne 1f
    addl $1, %eax
    cmpl %eax, %ebp
    jne 1f
    xorl %edx, %edx
1:
    movl %edx, %eax
    addl $20, %esp
    popl %ebp
    popl %edi
    popl %esi
    popl %ebx
    retl
.globl _FpRead
_FpRead:
    subl $4, %esp
    stmxcsr (%esp)
    movl (%esp), %eax
    addl $4, %esp
    retl
.globl _FpWrite
_FpWrite:
    ldmxcsr 4(%esp)
    retl
.globl _X87Read
_X87Read:
    subl $4, %esp
    fnstcw (%esp)
    movzwl (%esp), %eax
    addl $4, %esp
    retl
.globl _X87Write
_X87Write:
    fldcw 4(%esp)
    retl
#elif defined(__x86_64__)
.text
.globl ProbeSwitch
ProbeSwitch:
    pushq %rbx
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $232, %rsp
    .set off,32
    .irp r,%xmm6,%xmm7,%xmm8,%xmm9,%xmm10,%xmm11,%xmm12,%xmm13,%xmm14,%xmm15
    movdqu \r, off(%rsp)
    .set off,off+16
    .endr
    movq %rcx, 192(%rsp)
    movq %rdx, 200(%rsp)
    movq %rsp, 208(%rsp)
    .set n,1
    .irp r,%rbx,%rbp,%rdi,%rsi,%r12,%r13,%r14,%r15
    leaq n(%rdx), \r
    .set n,n+1
    .endr
    movl %edx, %eax
    .irp r,%xmm6,%xmm7,%xmm8,%xmm9,%xmm10,%xmm11,%xmm12,%xmm13,%xmm14,%xmm15
    movd %eax, \r
    pshufd $0, \r, \r
    .endr
    movq 192(%rsp), %rcx
    callq *__imp_SwitchToFiber(%rip)
    movl $1, %edx
    cmpq 208(%rsp), %rsp
    jne 1f
    movq 200(%rsp), %rax
    .irp r,%rbx,%rbp,%rdi,%rsi,%r12,%r13,%r14,%r15
    addq $1, %rax
    cmpq %rax, \r
    jne 1f
    .endr
    movl 200(%rsp), %eax
    .irp r,%xmm6,%xmm7,%xmm8,%xmm9,%xmm10,%xmm11,%xmm12,%xmm13,%xmm14,%xmm15
    movdqu \r, 216(%rsp)
    cmpl %eax, 216(%rsp)
    jne 1f
    cmpl %eax, 220(%rsp)
    jne 1f
    cmpl %eax, 224(%rsp)
    jne 1f
    cmpl %eax, 228(%rsp)
    jne 1f
    .endr
    xorl %edx, %edx
1:
    .set off,32
    .irp r,%xmm6,%xmm7,%xmm8,%xmm9,%xmm10,%xmm11,%xmm12,%xmm13,%xmm14,%xmm15
    movdqu off(%rsp), \r
    .set off,off+16
    .endr
    movl %edx, %eax
    addq $232, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rsi
    popq %rdi
    popq %rbp
    popq %rbx
    retq
.globl FpRead
FpRead:
    subq $8, %rsp
    stmxcsr (%rsp)
    movl (%rsp), %eax
    addq $8, %rsp
    retq
.globl FpWrite
FpWrite:
    subq $8, %rsp
    movl %ecx, (%rsp)
    ldmxcsr (%rsp)
    addq $8, %rsp
    retq
.globl X87Read
X87Read:
    subq $8, %rsp
    fnstcw (%rsp)
    movzwl (%rsp), %eax
    addq $8, %rsp
    retq
.globl X87Write
X87Write:
    subq $8, %rsp
    movl %ecx, (%rsp)
    fldcw (%rsp)
    addq $8, %rsp
    retq
#else
.text
.globl ProbeSwitch
.p2align 2
ProbeSwitch:
    sub sp, sp, #192
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp d8, d9, [sp, #96]
    stp d10, d11, [sp, #112]
    stp d12, d13, [sp, #128]
    stp d14, d15, [sp, #144]
    stp x0, x1, [sp, #160]
    mov x2, sp
    str x2, [sp, #176]
    .set n,1
    .irp r,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,x29
    add \r, x1, #n
    .set n,n+1
    .endr
    .set n,1
    .irp r,d8,d9,d10,d11,d12,d13,d14,d15
    add x2, x1, #n
    fmov \r, x2
    .set n,n+1
    .endr
    adrp x16, __imp_SwitchToFiber
    ldr x16, [x16, :lo12:__imp_SwitchToFiber]
    blr x16
    mov w0, #1
    mov x2, sp
    ldr x1, [sp, #176]
    cmp x1, x2
    b.ne 1f
    ldr x1, [sp, #168]
    .irp r,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,x29
    add x1, x1, #1
    cmp x1, \r
    b.ne 1f
    .endr
    ldr x1, [sp, #168]
    .irp r,d8,d9,d10,d11,d12,d13,d14,d15
    add x1, x1, #1
    fmov x2, \r
    cmp x1, x2
    b.ne 1f
    .endr
    mov w0, #0
1:
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldp d8, d9, [sp, #96]
    ldp d10, d11, [sp, #112]
    ldp d12, d13, [sp, #128]
    ldp d14, d15, [sp, #144]
    add sp, sp, #192
    ret
.globl FpRead
FpRead:
    mrs x0, fpcr
    ret
.globl FpWrite
FpWrite:
    msr fpcr, x0
    ret
/* No x87 on ARM64; these keep shared C control-flow explicit. */
.globl X87Read
X87Read:
    mov w0, #0
    ret
.globl X87Write
X87Write:
    ret
#endif
