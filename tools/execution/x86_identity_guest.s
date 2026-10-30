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
    movl $gp_handler,%eax
    movw %ax,idt+13*8
    movw $8,idt+13*8+2
    movw $0x8e00,idt+13*8+4
    shrl $16,%eax
    movw %ax,idt+13*8+6
    lidt idt_ptr
    movl $ap_start,%esi
    movl $0x7000,%edi
    movl $(ap_end-ap_start),%ecx
    cld
    rep movsb
    call observe
    movl $1,%ebp
start_ap:
    cmpl $@CPU_COUNT@,%ebp
    jae output_records
    movl %ebp,%eax
    shll $24,%eax
    movl %eax,0xfee00310
    movl $0x4500,0xfee00300
    movl $100000,%ecx
1:  loop 1b
    movl $0x4607,0xfee00300
wait_ap:
    cmpl $1,completed(,%ebp,4)
    jne wait_ap
    incl %ebp
    jmp start_ap
output_records:
    movl $header,%esi
    movl $12,%ecx
    call output
    movl $records,%esi
    movl $(@CPU_COUNT@*40),%ecx
    call output
    movl $trailer,%esi
    movl $8,%ecx
    call output
    movl $0x10,%eax
    movw $0xf4,%dx
    outl %eax,%dx
halt:
    hlt
    jmp halt
output:
    movw $0xe9,%dx
1:  lodsb
    outb %al,%dx
    loop 1b
    ret
observe:
    movl $1,%eax
    xorl %ecx,%ecx
    cpuid
    shrl $24,%ebx
    movl %ebx,%esi
    imull $40,%ebx,%edi
    addl $records,%edi
    movl %ebx,(%edi)
    movl $0xb,%eax
    xorl %ecx,%ecx
    cpuid
    movl %edx,4(%edi)
    movl $0x1b,%ecx
    rdmsr
    movl %eax,8(%edi)
    movl %edx,12(%edi)
    xorl $256,%eax
    wrmsr
    rdmsr
    movl %eax,16(%edi)
    movl %edx,20(%edi)
    movl 8(%edi),%eax
    movl 12(%edi),%edx
    wrmsr
    rdmsr
    movl %eax,24(%edi)
    movl %edx,28(%edi)
    movl 0xfee00020,%eax
    shrl $24,%eax
    movl %eax,36(%edi)
    movl $1,completed(,%esi,4)
    ret
gp_handler:
    movl $13,32(%edi)
    addl $2,4(%esp)
    addl $4,%esp
    iret
.code16
ap_start:
    cli
    xorw %ax,%ax
    movw %ax,%ds
    movw %ax,%ss
    lgdtl (ap_gdt_ptr-ap_start+0x7000)
    movl %cr0,%eax
    orl $1,%eax
    movl %eax,%cr0
    ljmpl $8,$ap_protected
ap_gdt_ptr:
    .word 23
    .long gdt
ap_end:
.code32
ap_protected:
    movw $16,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    lidt idt_ptr
    movl $1,%eax
    xorl %ecx,%ecx
    cpuid
    shrl $24,%ebx
    shll $12,%ebx
    movl $0x90000,%esp
    subl %ebx,%esp
    call observe
    jmp halt
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
    .ascii "RAXID001"
    .long @CPU_COUNT@
trailer:
    .ascii "ID_DONE!"
.section .bss
.align 8
records:
    .skip @CPU_COUNT@*40
completed:
    .skip @CPU_COUNT@*4
.align 16
idt:
    .skip 2048
