// Bare-metal AHCI command transport; inputs and all captured bytes are retained.
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
 cmpl $0x01060100,%eax
 je found
 incl %ebx
 cmpl $32,%ebx
 jne scan
 jmp failed
found:
 shll $11,%ebx
 orl $0x80000000,%ebx
 movl $0x24,%ecx
 movl $0xfeb00000,%eax
 call pci_write
 movl $4,%ecx
 movl $6,%eax
 call pci_write
 movl $0xfeb00000,%ebp
 movl $0x80000001,4(%ebp)
 movl $10000000,%ecx
reset_wait:
 pause
 testl $1,4(%ebp)
 jz configure
 loop reset_wait
 jmp failed
configure:
 movl $0x80000002,4(%ebp)
 movl $0x01000000,0x100(%ebp)
 movl $0,0x104(%ebp)
 movl $0x01001000,0x108(%ebp)
 movl $0,0x10c(%ebp)
 movl $0xffffffff,0x114(%ebp)
 movl $0x10,0x118(%ebp)
 movl $10000000,%ecx
ready_wait:
 pause
 testl $0x88,0x120(%ebp)
 jz ready
 loop ready_wait
 jmp failed
ready:
 movl $0x11,0x118(%ebp)
 movl input,%eax
 imull $36,%eax,%eax
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
next_command:
 movl sequence,%eax
 cmpl input,%eax
 je outputs
 movl $0x01001000,%edi
 xorl %eax,%eax
 movl $64,%ecx
 rep stosl
 movl $0xffffffff,0x110(%ebp)
 movl $1,8(%ebp)
 movl sequence,%eax
 imull $36,%eax,%eax
 leal input+12(%eax),%esi
 lodsl
 movl %eax,slot
 shll $5,%eax
 leal 0x01000000(%eax),%edi
 movl $8,%ecx
 rep movsl
 movl slot,%ecx
 movl $1,%eax
 shll %cl,%eax
 movl %eax,slot_mask
 movl %eax,0x138(%ebp)
 movl $10000000,%ecx
completion_wait:
 pause
 movl 0x110(%ebp),%eax
 testl $0x68000000,%eax
 jnz completed
 movl slot_mask,%eax
 testl %eax,0x138(%ebp)
 jz completed
 loop completion_wait
 jmp failed
completed:
 movl 0x110(%ebp),%eax
 movl %eax,record
 movl 8(%ebp),%eax
 movl %eax,record+4
 movl 0x138(%ebp),%eax
 movl %eax,record+8
 movl 0x120(%ebp),%eax
 movl %eax,record+12
 movl 0x118(%ebp),%eax
 movl %eax,record+16
 movl 0x128(%ebp),%eax
 movl %eax,record+20
 movl slot,%eax
 shll $5,%eax
 movl 0x01000004(%eax),%eax
 movl %eax,record+24
 movl 0x130(%ebp),%eax
 movl %eax,record+28
 movl $record,%esi
 movl $32,%ecx
 call emit
 movl $0x01001000,%esi
 movl $256,%ecx
 call emit
 // Each record is captured before an explicit stop/start recovery boundary.
 movl $0x10,0x118(%ebp)
 movl $10000000,%ecx
stop_wait:
 pause
 testl $0x8000,0x118(%ebp)
 jz restart
 loop stop_wait
 jmp failed
restart:
 movl $0xffffffff,0x110(%ebp)
 movl $1,8(%ebp)
 movl $0x11,0x118(%ebp)
 incl sequence
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
gdt: .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff
gdt_end:
gdt_ptr: .word gdt_end-gdt-1
.long gdt
.align 4
sequence: .long 0
slot: .long 0
slot_mask: .long 0
output_extents: .long 0
record: .space 32
begin_marker: .ascii "RAXAHCI1"
done_marker: .ascii "AHCIDONE"
fail_marker: .ascii "AHCIFAIL"
.align 4
input: .incbin "input.bin"
