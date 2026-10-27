.section .multiboot,"a"
.align 4
.long 0x1badb002,0,-0x1badb002
.section .text
.code32
.global _start
_start:
    cli
    cld
    lgdt gdt_ptr
    ljmp $8,$protected
protected:
    movw $16,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    movl $stack_top,%esp
    movl $db_handler,%eax
    movw %ax,idt+8
    movw $8,idt+10
    movw $0x8e00,idt+12
    shrl $16,%eax
    movw %ax,idt+14
    lidt idt_ptr
    movl $cases,%esi
    movl $records,%edi
next_case:
    movl $0,trap_count
    movl 0(%esi),%eax
    movw %ax,far_target+4
    movl 4(%esi),%eax
    movl %eax,far_target
    movl %eax,expected_start
    pushl %edi
    movl %eax,%edi
    movl 12(%esi),%ecx
    subl $2,%ecx
    movb $0x66,%al
    rep stosb
    movw $0xa20f,%ax
    stosw
    popl %edi
    xorl %eax,%eax
    pushfl
    orl $0x100,(%esp)
    popfl
    ljmp *far_target
resume:
    movl observed_ip,%eax
    movl %eax,(%edi)
    movl observed_cs,%eax
    movl %eax,4(%edi)
    movl trap_count,%eax
    movl %eax,8(%edi)
    addl $12,%edi
    addl $16,%esi
    incl completed
    cmpl $@CASE_COUNT@,completed
    jne next_case
    movl $header,%esi
    movl $12,%ecx
    call output
    movl $records,%esi
    movl $(@CASE_COUNT@*12),%ecx
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
db_handler:
    pushal
    incl trap_count
    cmpl $1,trap_count
    jne capture
    movl 32(%esp),%eax
    cmpl expected_start,%eax
    jne fail
    jmp return
capture:
    cmpl $2,trap_count
    jne fail
    movl 32(%esp),%eax
    movl %eax,observed_ip
    movl 36(%esp),%eax
    movl %eax,observed_cs
    movl $resume,32(%esp)
    movl $8,36(%esp)
    andl $0xfffffeff,40(%esp)
return:
    popal
    iret
.align 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff,0x008f9a000000ffff
gdt_ptr:
    .word 31
    .long gdt
idt_ptr:
    .word 2047
    .long idt
.section .rodata
header:
    .ascii "RAXIP001"
    .long @CASE_COUNT@
trailer:
    .ascii "IP_DONE!"
.align 4
cases:
    .incbin "cases.bin"
.section .data
far_target:
    .long 0
    .word 8
.section .bss
.align 16
idt:
    .skip 2048
records:
    .skip @CASE_COUNT@*12
trap_count:
    .skip 4
observed_ip:
    .skip 4
observed_cs:
    .skip 4
expected_start:
    .skip 4
completed:
    .skip 4
.align 16
stack:
    .skip 16384
stack_top:
