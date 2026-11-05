.text
.code64
.global _start
# Cold direct-kernel entry. The original startup BSP begins at0x1000400.
# No CPU count or ID list is supplied by the host.
_start:
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    movl %eax, %r15d
    movl %edx, %r13d
    movl $0xfee00030, %eax
    movl (%rax), %eax
    movzbl %al, %r12d
    movl $0xf0000, %edi
    movl $4096, %ecx
search:
    cmpl $0x5f504d5f, (%rdi)
    je pointer
    addq $16, %rdi
    loop search
    jmp failure
pointer:
    cmpb $1, 8(%rdi)
    jne failure
    cmpb $4, 9(%rdi)
    jne failure
    cmpb $0, 11(%rdi)
    jne failure
    movq %rdi, %rsi
    xorl %edx, %edx
    movl $16, %ecx
pointer_sum:
    addb (%rsi), %dl
    incq %rsi
    loop pointer_sum
    testb %dl, %dl
    jne failure
    movl 4(%rdi), %ebx
    cmpl $0xf0010, %ebx
    jb failure
    cmpl $0xfffd4, %ebx
    ja failure
    cmpl $0x504d4350, (%rbx)
    jne failure
    cmpb $4, 6(%rbx)
    jne failure
    movzwl 4(%rbx), %ecx
    cmpl $44, %ecx
    jb failure
    leaq (%rbx,%rcx), %r14
    cmpq $0x100000, %r14
    ja failure
    movq %rbx, %rsi
    xorl %edx, %edx
configuration_sum:
    addb (%rsi), %dl
    incq %rsi
    loop configuration_sum
    testb %dl, %dl
    jne failure
    movzwl 34(%rbx), %ecx
    cmpl $20, %ecx
    jb failure
    cmpl $274, %ecx
    ja failure
    xorl %r8d, %r8d
    addq $44, %rbx
record:
    leaq 8(%rbx), %rax
    cmpq %r14, %rax
    ja failure
    movzbl (%rbx), %eax
    testl %eax, %eax
    je cpu
    cmpl $4, %eax
    ja failure
    cmpl $2, %eax
    je ioapic
    cmpl $3, %eax
    je interrupt
skip:
    addq $8, %rbx
    jmp next
ioapic:
    cmpb $1, 3(%rbx)
    jne failure
    cmpl $0xfec00000, 4(%rbx)
    jne failure
    movl $0xfec00000, %edi
    movl $1, (%rdi)
    movl 16(%rdi), %eax
    cmpb %al, 2(%rbx)
    jne failure
    movl $0, (%rdi)
    movl 16(%rdi), %eax
    shrl $24, %eax
    cmpb %al, 1(%rbx)
    jne failure
    movl %eax, %r9d
    jmp skip
interrupt:
    cmpl $0, 1(%rbx)
    jne failure
    cmpb $0, 5(%rbx)
    jne skip
    cmpb %r9b, 6(%rbx)
    jne failure
    cmpb $2, 7(%rbx)
    jne failure
    jmp skip
cpu:
    leaq 20(%rbx), %rax
    cmpq %r14, %rax
    ja failure
    testb $1, 3(%rbx)
    jz disabled
    movzbl 1(%rbx), %eax
    cmpl %r8d, %eax
    jne failure
    cmpb %r12b, 2(%rbx)
    jne failure
    cmpl %r15d, 4(%rbx)
    jne failure
    cmpl %r13d, 8(%rbx)
    jne failure
    movl %eax, 0x250000(,%r8,4)
    incl %r8d
disabled:
    addq $20, %rbx
next:
    decl %ecx
    jnz record
    cmpq %r14, %rbx
    jne failure
    testl %r8d, %r8d
    jz failure
    movl %r8d, 0x210000
    movl $0x1000400, %eax
    jmp *%rax
failure:
    movl $0xbad00bad, 0x210004
    movw $0x604, %dx
    movl $0x2000, %eax
    outw %ax, %dx
    hlt
