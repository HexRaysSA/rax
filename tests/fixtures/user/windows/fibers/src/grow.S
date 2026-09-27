/* Touch 32 descending 4096-byte pages; no compiler __chkstk or private quantum. */
#if defined(__i386__)
.def @feat.00; .scl 3; .type 0; .endef
.set @feat.00, 1
.text
.globl _GrowStackSwitch
_GrowStackSwitch:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    movl %esp, %ebp
    subl $32, %esp
    movl 32(%ebp), %ebx
    movl %esp, %esi
    andl $-4096, %esi
    movl %esi, %eax
    movl $1, %edi
1:
    subl $4096, %eax
    leal 512(%eax), %esp
    leal (%ebx,%edi), %edx
    movl %edx, (%esp)
    incl %edi
    cmpl $33, %edi
    jne 1b
    /* Call from 64 bytes above the lowest touched page's lower boundary. */
    leal 64(%eax), %esp
    pushl 28(%ebp)
    pushl 24(%ebp)
    calll *__imp__FlsSetValue@8
    testl %eax, %eax
    jz 3f
    pushl 24(%ebp)
    calll *__imp__FlsFree@4
    testl %eax, %eax
    jz 3f
    pushl 20(%ebp)
    calll *__imp__SwitchToFiber@4
    movl %esi, %eax
    movl $1, %edi
2:
    subl $4096, %eax
    leal (%ebx,%edi), %edx
    cmpl %edx, 512(%eax)
    jne 3f
    incl %edi
    cmpl $33, %edi
    jne 2b
    xorl %eax, %eax
    jmp 4f
3:
    movl $1, %eax
4:
    movl %ebp, %esp
    popl %ebp
    popl %edi
    popl %esi
    popl %ebx
    retl
#elif defined(__x86_64__)
.text
.globl GrowStackSwitch
GrowStackSwitch:
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    movq %rsp, %rbp
    subq $72, %rsp
    movq %rcx, -40(%rbp)
    movq %rdx, -32(%rbp)
    movq %r8, -24(%rbp)
    movq %r9, %rbx
    movq %rsp, %rsi
    andq $-4096, %rsi
    movq %rsi, %rax
    movl $1, %edi
1:
    subq $4096, %rax
    leaq 512(%rax), %rsp
    leaq (%rbx,%rdi), %rdx
    movq %rdx, (%rsp)
    incl %edi
    cmpl $33, %edi
    jne 1b
    leaq 64(%rax), %rsp
    movl -32(%rbp), %ecx
    movq -24(%rbp), %rdx
    callq *__imp_FlsSetValue(%rip)
    testl %eax, %eax
    jz 3f
    movl -32(%rbp), %ecx
    callq *__imp_FlsFree(%rip)
    testl %eax, %eax
    jz 3f
    movq -40(%rbp), %rcx
    callq *__imp_SwitchToFiber(%rip)
    movq %rsi, %rax
    movl $1, %edi
2:
    subq $4096, %rax
    leaq (%rbx,%rdi), %rdx
    cmpq %rdx, 512(%rax)
    jne 3f
    incl %edi
    cmpl $33, %edi
    jne 2b
    xorl %eax, %eax
    jmp 4f
3:
    movl $1, %eax
4:
    movq %rbp, %rsp
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    retq
#else
.text
.globl GrowStackSwitch
.p2align 2
GrowStackSwitch:
    sub sp, sp, #96
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x29, x30, [sp, #32]
    stp x0, x1, [sp, #48]
    stp x2, x3, [sp, #64]
    mov x19, sp
    and x20, x19, #0xfffffffffffff000
    mov x9, x20
    mov x21, x3
    mov x22, #1
1:
    sub x9, x9, #4096
    add x10, x9, #512
    mov sp, x10
    add x10, x21, x22
    str x10, [sp]
    add x22, x22, #1
    cmp x22, #33
    b.ne 1b
    add x9, x9, #64
    mov sp, x9
    ldr w0, [x19, #56]
    ldr x1, [x19, #64]
    adrp x16, __imp_FlsSetValue
    ldr x16, [x16, :lo12:__imp_FlsSetValue]
    blr x16
    cbz w0, 3f
    ldr w0, [x19, #56]
    adrp x16, __imp_FlsFree
    ldr x16, [x16, :lo12:__imp_FlsFree]
    blr x16
    cbz w0, 3f
    ldr x0, [x19, #48]
    adrp x16, __imp_SwitchToFiber
    ldr x16, [x16, :lo12:__imp_SwitchToFiber]
    blr x16
    mov x9, x20
    mov x22, #1
2:
    sub x9, x9, #4096
    add x10, x21, x22
    ldr x11, [x9, #512]
    cmp x10, x11
    b.ne 3f
    add x22, x22, #1
    cmp x22, #33
    b.ne 2b
    mov w0, #0
    b 4f
3:
    mov w0, #1
4:
    mov sp, x19
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x29, x30, [sp, #32]
    add sp, sp, #96
    ret
#endif
