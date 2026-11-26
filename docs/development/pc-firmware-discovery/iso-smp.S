/* El-Torito no-emulation RAX boot image at 0x7c00, AP SIPI page at 0x8000. */
.section .text
.code16
.globl _start
_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    lgdt gdtr
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $protected_mode

.p2align 3
gdt:
    .quad 0, 0x00cf9a000000ffff, 0x00cf92000000ffff
gdtr:
    .word 23
    .long gdt

.code32
protected_mode:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $0x7000, %esp
    movl $0xf0000, %esi
find_pointer:
    cmpl $0x5f504d5f, (%esi)
    je pointer_found
    addl $16, %esi
    cmpl $0x100000, %esi
    jb find_pointer
    jmp bad
pointer_found:
    movl 4(%esi), %esi
    cmpl $0x504d4350, (%esi)
    jne bad
    movzwl 34(%esi), %edi
    addl $44, %esi
    xorl %ecx, %ecx
count_cpus:
    cmpb $0, (%esi)
    jne have_count
    cmpb %cl, 1(%esi)
    jne bad
    testb $1, 3(%esi)
    jz bad
    incl %ecx
    addl $20, %esi
    decl %edi
    jnz count_cpus
    jmp bad
have_count:
    testl %ecx, %ecx
    jz bad
    movl %ecx, 0x550
    movl $0x534d5052, 0x580
    cmpl $1, %ecx
    je success
    movl $0x1ff, 0xfee000f0
    movl $0x000c4500, 0xfee00300
    outb %al, $0x80
    movl $0x000c8500, 0xfee00300
    outb %al, $0x80
    movl $0x000c4608, 0xfee00300
    outb %al, $0x80
    movl $65536, %edx
    movl $1, %ebx
wait_peer:
    cmpl $0x534d5052, 0x580(,%ebx,4)
    je peer_arrived
    decl %edx
    jnz wait_peer
    jmp bad
peer_arrived:
    incl %ebx
    cmpl %ecx, %ebx
    jb wait_peer
success:
    movl $0x600d600d, 0x554
    jmp shutdown
bad:
    movl $0xbad00bad, 0x554
shutdown:
    movw $0x604, %dx
    movw $0x2000, %ax
    outw %ax, %dx
    hlt

.org 0x400
.code16
ap:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movl $1, %eax
    cpuid
    shrl $24, %ebx
    movl $0x534d5052, 0x580(,%ebx,4)
    hlt
