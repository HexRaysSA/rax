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
    movl $irq_handler,%eax
    movw %ax,idt+256
    movw $8,idt+258
    movw $0x8e00,idt+260
    shrl $16,%eax
    movw %ax,idt+262
    lidt idt_ptr
    movb $0x11,%al
    outb %al,$0x20
    outb %al,$0xa0
    movb $0x20,%al
    outb %al,$0x21
    movb $0x28,%al
    outb %al,$0xa1
    movb $4,%al
    outb %al,$0x21
    movb $2,%al
    outb %al,$0xa1
    movb $1,%al
    outb %al,$0x21
    outb %al,$0xa1
    movb $0xfe,%al
    outb %al,$0x21
    movb $0xff,%al
    outb %al,$0xa1
    movl $cases,%esi
    movl $records,%edi
next_case:
    cli
    movl $0,irq_count
    pushl %edi
    movl $0x200000,%edi
    movb $0xfb,%al
    stosb
    movl 4(%esi),%ecx
    cmpl $0,(%esi)
    jne make_hlt
    subl $2,%ecx
    movb $0x66,%al
    rep stosb
    movw $0xa20f,%ax
    stosw
    jmp ready
make_hlt:
    decl %ecx
    movb $0x66,%al
    rep stosb
    movb $0xf4,%al
    stosb
ready:
    movl %edi,expected_ip
    // IRQ handler rewrites EIP; no fallthrough instruction should execute.
    movb $0xfa,(%edi)
    movb $0xf4,1(%edi)
    popl %edi
    movb $0x30,%al
    outb %al,$0x43
    movb $32,%al
    outb %al,$0x40
    movb $0,%al
    outb %al,$0x40
    movl $1000000,%ecx
poll:
    movb $0x0a,%al
    outb %al,$0x20
    inb $0x20,%al
    testb $1,%al
    jnz pending
    loop poll
    jmp fail
pending:
    movl $0x200000,%eax
    jmp *%eax
resume:
    cli
    movl observed_ip,%eax
    movl %eax,(%edi)
    movl irq_count,%eax
    movl %eax,4(%edi)
    addl $8,%edi
    addl $8,%esi
    incl completed
    cmpl $@CASE_COUNT@,completed
    jne next_case
    movl $header,%esi
    movl $12,%ecx
    call output
    movl $records,%esi
    movl $(@CASE_COUNT@*8),%ecx
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
irq_handler:
    pushal
    incl irq_count
    movl 32(%esp),%eax
    movl %eax,observed_ip
    cmpl expected_ip,%eax
    jne fail
    movl $resume,32(%esp)
    andl $0xfffffdff,40(%esp)
    movb $0x20,%al
    outb %al,$0x20
    popal
    iret
.align 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff
gdt_ptr:
    .word 23
    .long gdt
idt_ptr:
    .word 2047
    .long idt
.section .rodata
header:
    .ascii "RAXSH001"
    .long @CASE_COUNT@
trailer:
    .ascii "SH_DONE!"
.align 4
cases:
    .incbin "cases.bin"
.section .bss
.align 16
idt:
    .skip 2048
records:
    .skip @CASE_COUNT@*8
irq_count:
    .skip 4
observed_ip:
    .skip 4
expected_ip:
    .skip 4
completed:
    .skip 4
.align 16
stack:
    .skip 16384
stack_top:
