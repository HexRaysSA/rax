/* Call an actual CRT cdecl import pointer; verify stack and nonvolatile GPRs.
 * No unwind metadata: this is a normal-call probe, not an exception oracle. */
#if defined(_M_IX86) || defined(__i386__)
    .text
    .def @feat.00; .scl 3; .type 0; .endef
    .set @feat.00, 1
    .globl _abi_copy
_abi_copy:
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl %esp, %ebp
    movl $0x12345678, %ebx
    movl $0x23456789, %esi
    movl $0x3456789a, %edi
    pushl 32(%ebp)
    pushl 28(%ebp)
    pushl 24(%ebp)
    call *20(%ebp)
    addl $12, %esp
    cmpl %ebp, %esp
    jne 1f
    cmpl 24(%ebp), %eax
    jne 1f
    cmpl $0x12345678, %ebx
    jne 1f
    cmpl $0x23456789, %esi
    jne 1f
    cmpl $0x3456789a, %edi
    jne 1f
    movl $1, %eax
    jmp 2f
1:  xorl %eax, %eax
2:  movl %ebp, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret
#elif defined(_M_X64) || defined(__x86_64__)
    .text
    .globl abi_copy
abi_copy:
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $72, %rsp
    movq %rcx, 32(%rsp)
    movq %rdx, 40(%rsp)
    movq %r8, 48(%rsp)
    movq %r9, 56(%rsp)
    movq %rsp, %rbp
    movq $0x1234, %rbx
    movq $0x2345, %rsi
    movq $0x3456, %rdi
    movq $0x4567, %r12
    movq $0x5678, %r13
    movq $0x6789, %r14
    movq $0x789a, %r15
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    call *32(%rsp)
    cmpq %rbp, %rsp
    jne 1f
    cmpq 40(%rbp), %rax
    jne 1f
    cmpq $0x1234, %rbx
    jne 1f
    cmpq $0x2345, %rsi
    jne 1f
    cmpq $0x3456, %rdi
    jne 1f
    cmpq $0x4567, %r12
    jne 1f
    cmpq $0x5678, %r13
    jne 1f
    cmpq $0x6789, %r14
    jne 1f
    cmpq $0x789a, %r15
    jne 1f
    movl $1, %eax
    jmp 2f
1:  xorl %eax, %eax
2:  movq %rbp, %rsp
    addq $72, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    ret
#elif defined(_M_ARM64) || defined(__aarch64__)
    .text
    .globl abi_copy
abi_copy:
    sub sp, sp, #128
    stp x19, x20, [sp]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp x0, x1, [sp, #96]
    stp x2, x3, [sp, #112]
    mov x29, sp
    mov x19, #0x19
    mov x20, #0x20
    mov x21, #0x21
    mov x22, #0x22
    mov x23, #0x23
    mov x24, #0x24
    mov x25, #0x25
    mov x26, #0x26
    mov x27, #0x27
    mov x28, #0x28
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    blr x9
    mov x9, sp
    cmp x9, x29
    b.ne 1f
    ldr x9, [x29, #104]
    cmp x0, x9
    b.ne 1f
    cmp x19, #0x19
    b.ne 1f
    cmp x20, #0x20
    b.ne 1f
    cmp x21, #0x21
    b.ne 1f
    cmp x22, #0x22
    b.ne 1f
    cmp x23, #0x23
    b.ne 1f
    cmp x24, #0x24
    b.ne 1f
    cmp x25, #0x25
    b.ne 1f
    cmp x26, #0x26
    b.ne 1f
    cmp x27, #0x27
    b.ne 1f
    cmp x28, #0x28
    b.ne 1f
    mov w0, #1
    b 2f
1:  mov w0, #0
2:  mov sp, x29
    ldp x19, x20, [sp]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #128
    ret
#endif
