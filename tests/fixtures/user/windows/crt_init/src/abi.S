/* Invoke the real two-pointer cdecl import. Check caller cleanup and GPRs.
 * No unwind/FP oracle is claimed; callbacks are covered by compiled C. */
#if defined(_M_IX86) || defined(__i386__)
    .text
    .def @feat.00; .scl 3; .type 0; .endef
    .set @feat.00, 1
    .globl _abi_init
_abi_init:
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl %esp, %ebp
    movl $0x12345678, %ebx
    movl $0x23456789, %esi
    movl $0x3456789a, %edi
    pushl 28(%ebp)
    pushl 24(%ebp)
    call *20(%ebp)
    addl $8, %esp
    cmpl %ebp, %esp
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
    .globl _abi_clobber
_abi_clobber:
    movl $0x13579bdf, %eax
    movl $0x2468ace0, %ecx
    movl $0x3579bdf1, %edx
    ret
#elif defined(_M_X64) || defined(__x86_64__)
    .text
    .globl abi_init
abi_init:
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
    call *32(%rsp)
    cmpq %rbp, %rsp
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
    .globl abi_clobber
abi_clobber:
    movq $0x13579bdf, %rax
    movq $0x2468ace0, %rcx
    movq $0x3579bdf1, %rdx
    movq $0x468ace02, %r8
    movq $0x579bdf13, %r9
    movq $0x68ace024, %r10
    movq $0x79bdf135, %r11
    ret
#elif defined(_M_ARM64) || defined(__aarch64__)
    .text
    .globl abi_init
abi_init:
    sub sp, sp, #128
    stp x19, x20, [sp]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    str x0, [sp, #96]
    mov x19, #0x1234
    mov x20, #0x2345
    mov x21, #0x3456
    mov x22, #0x4567
    mov x23, #0x5678
    mov x24, #0x6789
    mov x25, #0x789a
    mov x26, #0x89ab
    mov x27, #0x9abc
    mov x28, #0xabcd
    mov x29, sp
    mov x16, x0
    mov x0, x1
    mov x1, x2
    blr x16
    mov x16, sp
    cmp x16, x29
    b.ne 1f
    mov x17, #0x1234
    cmp x19, x17
    b.ne 1f
    mov x17, #0x2345
    cmp x20, x17
    b.ne 1f
    mov x17, #0x3456
    cmp x21, x17
    b.ne 1f
    mov x17, #0x4567
    cmp x22, x17
    b.ne 1f
    mov x17, #0x5678
    cmp x23, x17
    b.ne 1f
    mov x17, #0x6789
    cmp x24, x17
    b.ne 1f
    mov x17, #0x789a
    cmp x25, x17
    b.ne 1f
    mov x17, #0x89ab
    cmp x26, x17
    b.ne 1f
    mov x17, #0x9abc
    cmp x27, x17
    b.ne 1f
    mov x17, #0xabcd
    cmp x28, x17
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
    .globl abi_clobber
abi_clobber:
    mov x0, #0x1357
    mov x1, #0x2468
    mov x2, #0x3579
    mov x3, #0x468a
    mov x4, #0x579b
    mov x5, #0x68ac
    mov x6, #0x79bd
    mov x7, #0x8ace
    mov x8, #0x9bdf
    mov x9, #0xace0
    mov x10, #0xbdf1
    mov x11, #0xce02
    mov x12, #0xdf13
    mov x13, #0xe024
    mov x14, #0xf135
    mov x15, #0x0246
    mov x16, #0x1357
    mov x17, #0x2468
    ret
#endif
