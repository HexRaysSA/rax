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
    pause
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
    pause
    testl $2,0x1c(%ebp)
    jnz failed
    testl $1,0x1c(%ebp)
    jnz queues
    loop wait_ready
    jmp failed
queues:
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
    // IdentifyController SGLS is an actual independent profile observation.
    movl $0x01000080,%edi
    xorl %eax,%eax
    movl $16,%ecx
    rep stosl
    movl $0x00130006,0x01000080
    movl $0x01200000,0x01000098
    movl $1,0x010000a8
    movl $3,0x1000(%ebp)
    movl $0x01001020,%edi
    call wait_cqe
    movl $3,0x1004(%ebp)
    // Identify Namespace provides the actual independent DLFEAT word.
    movl $0x010000c0,%edi
    xorl %eax,%eax
    movl $16,%ecx
    rep stosl
    movl $0x00140006,0x010000c0
    movl $1,0x010000c4
    movl $0x01201000,0x010000d8
    movl $4,0x1000(%ebp)
    movl $0x01001030,%edi
    call wait_cqe
    movl $4,0x1004(%ebp)
    // Input:command count,DWORD write count,final output extent count.
    movl input,%eax
    shll $6,%eax
    leal input+12(%eax),%esi
    movl input+4,%ecx
install:
    testl %ecx,%ecx
    jz installed
    movl (%esi),%edi
    movl 4(%esi),%eax
    movl %eax,(%edi)
    addl $8,%esi
    loop install
installed:
    movl %esi,output_extents
    movl $begin_marker,%esi
    movl $8,%ecx
    call emit
    movl $input,%esi
    movl $12,%ecx
    call emit
    movzwl 0x01200208,%eax
    movzbl 0x0120020d,%edx
    shll $16,%edx
    orl %edx,%eax
    movzbl 0x01201021,%edx
    shll $24,%edx
    orl %edx,%eax
    movl %eax,capabilities
    movl 0x01200218,%eax
    movl %eax,capabilities+4
    movl 0x01200204,%eax
    movl %eax,capabilities+8
    movl $capabilities,%esi
    movl $12,%ecx
    call emit
next_command:
    movl sequence,%eax
    cmpl input,%eax
    je outputs
    shll $6,%eax
    leal input+12(%eax),%esi
    leal 0x01002000(%eax),%edi
    movl $16,%ecx
    rep movsl
    movl sequence,%eax
    incl %eax
    movl %eax,0x1008(%ebp)
    decl %eax
    shll $4,%eax
    leal 0x01003000(%eax),%edi
    movl $10000000,%ecx
wait_completion:
    pause
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
    movl %eax,0x100c(%ebp)
    jmp next_command
outputs:
    movl output_extents,%ebx
    movl input+8,%edi
next_extent:
    testl %edi,%edi
    jz finish
    movl (%ebx),%esi
    movl 4(%ebx),%ecx
    call emit
    addl $8,%ebx
    decl %edi
    jmp next_extent
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
wait_cqe:
    movl $10000000,%ecx
wait_phase:
    pause
    testb $1,14(%edi)
    jnz received
    loop wait_phase
    jmp failed
received:
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
output_extents: .long 0
capabilities: .long 0,0,0
begin_marker: .ascii "RAXNVCM2"
done_marker: .ascii "NVCMDONE"
fail_marker: .ascii "NVCMFAIL"
.align 4
cq_command:
    .long 0x110005,0,0,0,0,0,0x01003000,0,0,0,0x003f0001,1,0,0,0,0
sq_command:
    .long 0x120001,0,0,0,0,0,0x01002000,0,0,0,0x003f0001,0x00010001,0,0,0,0
input:
    .incbin "input.bin"
