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
    movl $0x00460001,0x14(%ebp)
    movl $10000000,%ecx
wait_ready:
    testl $2,0x1c(%ebp)
    jnz failed
    testl $1,0x1c(%ebp)
    jnz queues
    loop wait_ready
    jmp failed
queues:
    movl input,%eax
    decl %eax
    shll $16,%eax
    orl $1,%eax
    movl %eax,cq_command+40
    movl input+4,%eax
    shll $1,%eax
    orl $1,%eax
    movl %eax,cq_command+44
    movl $cq_command,%esi
    movl $0x01000000,%edi
    movl $16,%ecx
    rep movsl
    movl $sq_command,%esi
    movl $16,%ecx
    rep movsl
    movl $2,0x1000(%ebp)
    movl $0x01001000,%edi
    call wait_cqe
    movl $0x01001010,%edi
    call wait_cqe
    movl $2,0x1004(%ebp)
    movl $begin_marker,%esi
    movl $8,%ecx
    call emit
    movl $input,%esi
    movl $12,%ecx
    call emit
command_loop:
    movl sequence,%eax
    cmpl input+8,%eax
    je drain
    call submit
    // At most size-1 CQEs can remain unacknowledged. Submit one more
    // command before acknowledging; retain every unread CQ slot first.
    movl sequence,%eax
    incl %eax
    subl acknowledged,%eax
    cmpl input,%eax
    jb await_new
    movl $100000,%ecx
settle:
    movl 0x1c(%ebp),%eax
    loop settle
    movl $0x01003000,%esi
    movl input,%ecx
    shll $4,%ecx
    call emit
    incl acknowledged
    movl acknowledged,%eax
    xorl %edx,%edx
    divl input
    movl %edx,0x100c(%ebp)
await_new:
    movl sequence,%eax
    xorl %edx,%edx
    divl input
    andl $1,%eax
    xorl $1,%eax
    movl %eax,phase
    shll $4,%edx
    leal 0x01003000(%edx),%edi
    call wait_completion
    movl %edi,%esi
    movl $16,%ecx
    call emit
    call emit_pin
    incl sequence
    jmp command_loop
drain:
    movl sequence,%eax
    movl %eax,acknowledged
    xorl %edx,%edx
    divl input
    movl %edx,0x100c(%ebp)
    call emit_pin
    // A new unacknowledged CQE remains pending across mask/unmask.
    call submit
    movl sequence,%eax
    xorl %edx,%edx
    divl input
    andl $1,%eax
    xorl $1,%eax
    movl %eax,phase
    shll $4,%edx
    leal 0x01003000(%edx),%edi
    call wait_completion
    movl %edi,%esi
    movl $16,%ecx
    call emit
    call emit_pin
    movl $1,0x0c(%ebp)
    call emit_pin
    movl $1,0x10(%ebp)
    call emit_pin
    movl sequence,%eax
    incl %eax
    xorl %edx,%edx
    divl input
    movl %edx,0x100c(%ebp)
    call emit_pin
    movl $-1,0x0c(%ebp)
    movl $0,0x14(%ebp)
    movl $10000000,%ecx
wait_reset:
    testl $1,0x1c(%ebp)
    jz reset_done
    loop wait_reset
    jmp failed
reset_done:
    movl 0x0c(%ebp),%eax
    movl %eax,observation
    movl $observation,%esi
    movl $4,%ecx
    call emit
    call emit_pin
    movl $done_marker,%esi
    movl $8,%ecx
    call emit
    movw $0xf4,%dx
    movl $0x10,%eax
    outl %eax,%dx
    jmp .
submit:
    pushal
    movl sequence,%eax
    andl $63,%eax
    movl %eax,%edi
    shll $6,%edi
    addl $0x01002000,%edi
    movl %edi,%ebx
    xorl %eax,%eax
    movl $16,%ecx
    rep stosl
    movl sequence,%eax
    addl $0x5000,%eax
    movw %ax,2(%ebx)
    movl $1,4(%ebx)
    movl sequence,%eax
    incl %eax
    andl $63,%eax
    movl %eax,0x1008(%ebp)
    popal
    ret
wait_completion:
    movl $10000000,%ecx
wait_current:
    movzbl 14(%edi),%eax
    andl $1,%eax
    cmpl phase,%eax
    je received
    loop wait_current
    jmp failed
received:
    testw $0xfffe,14(%edi)
    jnz failed
    ret
emit_pin:
    movl pci_base,%eax
    orl $4,%eax
    movw $0xcf8,%dx
    outl %eax,%dx
    movw $0xcfc,%dx
    inl %dx,%eax
    shrl $19,%eax
    andl $1,%eax
    movl %eax,observation
    movl $observation,%esi
    movl $4,%ecx
    call emit
    ret
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
wait_cqe:
    movl $10000000,%ecx
wait_phase:
    testb $1,14(%edi)
    jnz admin_received
    loop wait_phase
    jmp failed
admin_received:
    // A nonzero status remains an actual captured failure, never success.
    testw $0xfffe,14(%edi)
    jnz bad_completion
    ret
bad_completion:
    movl %edi,%esi
    movl $16,%ecx
    call emit
    jmp failed
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
acknowledged: .long 0
pci_base: .long 0
phase: .long 1
observation: .long 0
begin_marker: .ascii "RAXNVQ01"
done_marker: .ascii "NVQ0DONE"
fail_marker: .ascii "NVQ0FAIL"
.align 4
cq_command:
    .long 0x110005,0,0,0,0,0,0x01003000,0,0,0,0x00030001,3,0,0,0,0
sq_command:
    .long 0x120001,0,0,0,0,0,0x01002000,0,0,0,0x003f0001,0x00010001,0,0,0,0
input:
    .incbin "input.bin"
