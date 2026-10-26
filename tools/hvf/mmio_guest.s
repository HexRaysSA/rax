.section .multiboot,"a"
.align 4
.long 0x1badb002,0,-0x1badb002
.section .text
.code32
.global _start
_start:
    cli
    lgdt gdt_ptr
    ljmp $8,$protected
protected:
    movw $16,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    movl $stack_top,%esp
    movl $pdpt+3,pml4
    movl $directories+3,%eax
    movl $pdpt,%edi
    movl $4,%ecx
1:
    movl %eax,(%edi)
    addl $4096,%eax
    addl $8,%edi
    loop 1b
    xorl %ecx,%ecx
2:
    movl %ecx,%eax
    shll $21,%eax
    orl $0x83,%eax
    movl %eax,directories(,%ecx,8)
    incl %ecx
    cmpl $2048,%ecx
    jne 2b
    movl $0x20,%eax
    movl %eax,%cr4
    movl $pml4,%eax
    movl %eax,%cr3
    movl $0xc0000080,%ecx
    rdmsr
    orl $0x100,%eax
    wrmsr
    movl %cr0,%eax
    orl $0x80000001,%eax
    movl %eax,%cr0
    ljmp $24,$long_mode
.code64
long_mode:
    movl $0x400000,%esp
    movq $cases,current_case(%rip)
    movq $records,current_output(%rip)
next_case:
    cld
    movq current_case(%rip),%rsi
    movl $seed,%edi
    movl $16,%ecx
    rep movsq
    movq current_case(%rip),%rsi
    movq 128(%rsi),%rax
    movq %rax,0x200000
    movl 144(%rsi),%ecx
    addq $148,%rsi
    movl $0x300000,%edi
    rep movsb
    movb $0xe9,(%rdi)
    movl $record,%eax
    subl %edi,%eax
    subl $5,%eax
    movl %eax,1(%rdi)
    // Serialize self-modified probe code before restoring input registers.
    xorl %eax,%eax
    cpuid
    movq current_case(%rip),%rsi
    pushq 136(%rsi)
    popfq
    pushfq
    popq flags_before(%rip)
    movq seed+0(%rip),%rax
    movq seed+8(%rip),%rcx
    movq seed+16(%rip),%rdx
    movq seed+24(%rip),%rbx
    movq seed+32(%rip),%rsp
    movq seed+40(%rip),%rbp
    movq seed+48(%rip),%rsi
    movq seed+56(%rip),%rdi
    movq seed+64(%rip),%r8
    movq seed+72(%rip),%r9
    movq seed+80(%rip),%r10
    movq seed+88(%rip),%r11
    movq seed+96(%rip),%r12
    movq seed+104(%rip),%r13
    movq seed+112(%rip),%r14
    movq seed+120(%rip),%r15
    jmp *probe_pointer(%rip)
record:
    movq %rax,observed+0(%rip)
    movq %rcx,observed+8(%rip)
    movq %rdx,observed+16(%rip)
    movq %rbx,observed+24(%rip)
    movq %rsp,observed+32(%rip)
    movq %rbp,observed+40(%rip)
    movq %rsi,observed+48(%rip)
    movq %rdi,observed+56(%rip)
    movq %r8,observed+64(%rip)
    movq %r9,observed+72(%rip)
    movq %r10,observed+80(%rip)
    movq %r11,observed+88(%rip)
    movq %r12,observed+96(%rip)
    movq %r13,observed+104(%rip)
    movq %r14,observed+112(%rip)
    movq %r15,observed+120(%rip)
    movl $0x400000,%esp
    pushfq
    popq flags_after(%rip)
    movl $observed,%esi
    movq current_output(%rip),%rdi
    movl $16,%ecx
    rep movsq
    movq 0x200000,%rax
    movq %rax,(%rdi)
    movq flags_before(%rip),%rax
    movq %rax,8(%rdi)
    movq flags_after(%rip),%rax
    movq %rax,16(%rdi)
    addq $24,%rdi
    movq %rdi,current_output(%rip)
    addq $168,current_case(%rip)
    incl completed(%rip)
    cmpl $@CASE_COUNT@,completed(%rip)
    jne next_case
    movl $header,%esi
    movl $12,%ecx
    call output
    movl $records,%esi
    movl $(@CASE_COUNT@*152),%ecx
    call output
    movl $trailer,%esi
    movl $8,%ecx
    call output
    movl $0x10,%eax
    jmp finish
fail:
    movl $0x11,%eax
finish:
    movw $0xf4,%dx
    outl %eax,%dx
    hlt
    jmp finish
output:
    movw $0xe9,%dx
1:
    lodsb
    outb %al,%dx
    loop 1b
    ret
.align 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff,0x00af9a000000ffff
gdt_ptr:
    .word 31
    .long gdt
.section .rodata
probe_pointer:
    .quad 0x300000
header:
    .ascii "RAXMM001"
    .long @CASE_COUNT@
trailer:
    .ascii "MM_DONE!"
.align 8
cases:
    .incbin "cases.bin"
.section .bss
.align 4096
pml4:
    .skip 4096
pdpt:
    .skip 4096
directories:
    .skip 16384
seed:
    .skip 128
observed:
    .skip 128
flags_before:
    .skip 8
flags_after:
    .skip 8
current_case:
    .skip 8
current_output:
    .skip 8
records:
    .skip @CASE_COUNT@*152
completed:
    .skip 4
.align 16
stack:
    .skip 16384
stack_top:
