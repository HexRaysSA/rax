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
    movl $0x90000,%esp
    cld
    xorl %eax,%eax
    movl $0x1000,%edi
    movl $(0xf000/4),%ecx
    rep stosl
.macro entry address,value
    movl $\value,\address
.endm
    entry 0x1000,0x2003
    entry 0x2000,0x3003
    entry 0x3000,0x83
    entry 0x1800,0x4003
    entry 0x4000,0x5003
    entry 0x5010,0x6003
    entry 0x6000,0xa001
    entry 0x6008,0xc001
    entry 0x7000,0x2003
    entry 0x7800,0xd003
    entry 0xd000,0xe003
    entry 0xe010,0xf003
    entry 0xf000,0xb001
    entry 0xa000,0x30555043
    entry 0xa004,0x41544144
    entry 0xb000,0x31555043
    entry 0xb004,0x41544144
    movw $(gdt_end-gdt-1),0x500
    movl $gdt,0x502
    movl $ap_trampoline,%esi
    movl $0x9000,%edi
    movl $(ap_end-ap_trampoline),%ecx
    rep movsb
    movl $0x01000000,0xfee00310
    movl $0x4500,0xfee00300
    movl $100000,%ecx
1:  loop 1b
    movl $0x4609,0xfee00300
    jmp select_root
ap32:
    movw $16,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    movl $0x8f00,%esp
select_root:
    movl $1,%eax
    xorl %ecx,%ecx
    cpuid
    shrl $24,%ebx
    movl %ebx,%edi
    movl $0x1000,%eax
    testl %edi,%edi
    jz 1f
    movl $0x7000,%eax
1:  movl %eax,%cr3
    movl $0x20,%eax
    movl %eax,%cr4
    movl $0xc0000080,%ecx
    movl $0x900,%eax
    xorl %edx,%edx
    wrmsr
    movl %cr0,%eax
    orl $0x80010001,%eax
    movl %eax,%cr0
    ljmp $24,$long_entry
.code64
long_entry:
    movabsq $0xffff800000400000,%rax
    movq (%rax),%rax
    movq %rax,0x700(,%rdi,8)
    movw $0xe9,%dx
    movb $82,%al
    outb %al,%dx
1:  hlt
    jmp 1b
.code16
ap_trampoline:
    cli
    xorw %ax,%ax
    movw %ax,%ds
    lgdtl 0x500
    movl %cr0,%eax
    orl $1,%eax
    movl %eax,%cr0
    ljmpl $8,$ap32
ap_end:
.code32
.align 8
gdt:
.quad 0,0x00cf9a000000ffff,0x00cf92000000ffff,0x00af9a000000ffff
gdt_end:
gdt_ptr:
.word gdt_end-gdt-1
.long gdt
