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
    movl $0x80000,%esp
    // PCI mechanism1, bus0/function0, class010802:NVMe.
    xorl %ebx,%ebx
scan:
    movl %ebx,%eax
    shll $11,%eax
    orl $0x80000008,%eax
    movw $0xcf8,%dx
    outl %eax,%dx
    movw $0xcfc,%dx
    inl %dx,%eax
    andl $0xffffff00,%eax
    cmpl $0x01080200,%eax
    je found
    incl %ebx
    cmpl $32,%ebx
    jne scan
    jmp failed
found:
    shll $11,%ebx
    orl $0x80000000,%ebx
    movl %ebx,pci_base
    movl $0x10,%ecx
    movl $0xfeb00000,%eax
    call pci_write
    movl $0x14,%ecx
    xorl %eax,%eax
    call pci_write
    movl $4,%ecx
    movl $6,%eax
    call pci_write
    movl $0xfeb00000,%ebp
    movl $0,0x14(%ebp)
    movl $10000000,%ecx
wait_off:
    testl $1,0x1c(%ebp)
    jz configure
    loop wait_off
    jmp failed
configure:
    movl $0x003f003f,0x24(%ebp)
    movl $0x01000000,0x28(%ebp)
    movl $0,0x2c(%ebp)
    movl $0x01001000,0x30(%ebp)
    movl $0,0x34(%ebp)
    movl input,%eax
    movl %eax,0x14(%ebp)
    movl $10000000,%ecx
wait_ready:
    testl $2,0x1c(%ebp)
    jnz failed
    testl $1,0x1c(%ebp)
    jnz begin
    loop wait_ready
    jmp failed
begin:
    movl $begin_marker,%esi
    movl $8,%ecx
    call emit
    movl $input,%esi
    movl $8,%ecx
    call emit
next_command:
    movl sequence,%eax
    cmpl input+4,%eax
    je finish
    shll $6,%eax
    leal input+8(%eax),%esi
    leal 0x01000000(%eax),%edi
    movl $16,%ecx
    rep movsl
    movl sequence,%eax
    incl %eax
    movl %eax,0x1000(%ebp)
    decl %eax
    shll $4,%eax
    leal 0x01001000(%eax),%edi
    movl $10000000,%ecx
wait_completion:
    testb $1,14(%edi)
    jnz completed
    loop wait_completion
    jmp failed
completed:
    movl %edi,%esi
    movl $16,%ecx
    call emit
    incl sequence
    movl sequence,%eax
    movl %eax,0x1004(%ebp)
    jmp next_command
finish:
    movl $done_marker,%esi
    movl $8,%ecx
    call emit
    movw $0xf4,%dx
    movl $0x10,%eax
    outl %eax,%dx
    jmp .
pci_write:
    pushl %eax
    movl %ebx,%eax
    orl %ecx,%eax
    movw $0xcf8,%dx
    outl %eax,%dx
    popl %eax
    movw $0xcfc,%dx
    outl %eax,%dx
    ret
emit:
    movw $0xe9,%dx
emit_byte:
    lodsb
    outb %al,%dx
    loop emit_byte
    ret
failed:
    movl $fail_marker,%esi
    movl $8,%ecx
    call emit
    movw $0xf4,%dx
    movl $0x11,%eax
    outl %eax,%dx
    jmp .
.align 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff
gdt_end:
gdt_ptr:
    .word gdt_end-gdt-1
    .long gdt
.align 4
sequence: .long 0
pci_base: .long 0
begin_marker: .ascii "RAXNVAD1"
done_marker: .ascii "NVADDONE"
fail_marker: .ascii "NVADFAIL"
.align 4
input:
    .incbin "input.bin"
