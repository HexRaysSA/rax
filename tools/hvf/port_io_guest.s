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
    movl $stack_top,%esp
    movl $cases,%esi
    movl $records,%edi
next_case:
    cmpl $1,(%rsi)
    je byte_case
    cmpl $2,(%rsi)
    je word_case
    cmpl $4,(%rsi)
    jne fail
    cmpl $0,4(%rsi)
    jne dword_imm
    movw $0x80,%dx
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inl %dx,%eax
    jmp record
dword_imm:
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inl $0x80,%eax
    jmp record
byte_case:
    cmpl $0,4(%rsi)
    jne byte_imm
    movw $0x80,%dx
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inb %dx,%al
    jmp record
byte_imm:
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inb $0x80,%al
    jmp record
word_case:
    cmpl $0,4(%rsi)
    jne word_imm
    movw $0x80,%dx
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inw %dx,%ax
    jmp record
word_imm:
    movq 8(%rsi),%rax
    pushfq
    popq %rbx
    inw $0x80,%ax
record:
    movq %rax,(%rdi)
    movq %rbx,8(%rdi)
    pushfq
    popq %rax
    movq %rax,16(%rdi)
    addq $16,%rsi
    addq $24,%rdi
    incl completed(%rip)
    cmpl $@CASE_COUNT@,completed(%rip)
    jne next_case
    movl $header,%esi
    movl $12,%ecx
    call output
    movl $records,%esi
    movl $(@CASE_COUNT@*24),%ecx
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
header:
    .ascii "RAXIO001"
    .long @CASE_COUNT@
trailer:
    .ascii "IO_DONE!"
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
records:
    .skip @CASE_COUNT@*24
completed:
    .skip 4
.align 16
stack:
    .skip 16384
stack_top:
