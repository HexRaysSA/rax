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
    // Input:total,PSDT,16-byte SGL descriptor,segmentCount,DWORDwriteCount.
    movl $input+32,%esi
    movl %esi,segment_pointer
    movl input+24,%eax
    leal (%esi,%eax,8),%esi
    movl input+28,%ecx
install_lists:
    testl %ecx,%ecx
    jz begin
    movl (%esi),%edi
    movl 4(%esi),%eax
    movl %eax,(%edi)
    addl $8,%esi
    loop install_lists
begin:
    movl $begin_marker,%esi
    movl $8,%ecx
    call emit
    movl $input,%esi
    movl $32,%ecx
    call emit
    movl $0x01200218,%esi
    movl $4,%ecx
    call emit
    movl $2,%eax
    call io_command
    movl $0x01003000,%esi
    movl $16,%ecx
    call emit
    call emit_data
    movb $0x5a,%al
    call fill_data
    movl $1,%eax
    call io_command
    movl $0x01003010,%esi
    movl $16,%ecx
    call emit
    xorl %eax,%eax
    call fill_data
    movl $2,%eax
    call io_command
    movl $0x01003020,%esi
    movl $16,%ecx
    call emit
    call emit_data
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
io_command:
    pushal
    movl io_index,%ebx
    movl %ebx,%edi
    shll $6,%edi
    addl $0x01002000,%edi
    movl %edi,%edx
    pushl %eax
    xorl %eax,%eax
    movl $16,%ecx
    rep stosl
    popl %eax
    movl %edx,%edi
    movl input+4,%ecx
    shll $14,%ecx
    orl %ecx,%eax
    movl %eax,(%edi)
    movw $0x73a5,2(%edi)
    movl $1,4(%edi)
    movl input+8,%eax
    movl %eax,24(%edi)
    movl input+12,%eax
    movl %eax,28(%edi)
    movl input+16,%eax
    movl %eax,32(%edi)
    movl input+20,%eax
    movl %eax,36(%edi)
    movl input,%eax
    shrl $9,%eax
    decl %eax
    movl %eax,48(%edi)
    incl %ebx
    movl %ebx,io_index
    movl %ebx,0x1008(%ebp)
    decl %ebx
    shll $4,%ebx
    leal 0x01003000(%ebx),%edi
    call wait_cqe
    movl io_index,%eax
    movl %eax,0x100c(%ebp)
    popal
    ret
fill_data:
    pushal
    movl segment_pointer,%esi
    movl input+24,%ebx
fill_segment:
    movl (%esi),%edi
    movl 4(%esi),%ecx
    rep stosb
    addl $8,%esi
    decl %ebx
    jnz fill_segment
    popal
    ret
emit_data:
    pushal
    movl segment_pointer,%ebx
    movl input+24,%edi
emit_segment:
    movl (%ebx),%esi
    movl 4(%ebx),%ecx
    call emit
    addl $8,%ebx
    decl %edi
    jnz emit_segment
    popal
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
io_index: .long 0
segment_pointer: .long 0
begin_marker: .ascii "RAXNVSG1"
done_marker: .ascii "NVSGDONE"
fail_marker: .ascii "NVSGFAIL"
.align 4
cq_command:
    .long 0x110005,0,0,0,0,0,0x01003000,0,0,0,0x003f0001,1,0,0,0,0
sq_command:
    .long 0x120001,0,0,0,0,0,0x01002000,0,0,0,0x003f0001,0x00010001,0,0,0,0
input:
    .incbin "input.bin"
