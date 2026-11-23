/* New guest work for the existing 2/4-vCPU x86 startup image.
 * BSP begins after the first ACPI exit. APs retain their protected-mode IDT.
 */

.equ IOAPIC_SELECTOR, 0xfec00000
.equ IOAPIC_WINDOW, 0xfec00010
.equ LAPIC_EOI, 0xfee000b0
.equ GSI4_LOW, 0x18
.equ GSI4_HIGH, 0x19
.equ IRQ_VECTOR, 0x41
.equ RTE_LEVEL, 0x8000
.equ IDT41_LOW, 0x240208
.equ IDT41_HIGH, 0x24020c
.equ AP_HANDLER, 0x20100
.equ OBS, 0x270000
.equ TARGET, 0x270020
.equ VISITS, 0x270040
.equ SUCCESS, 0x700d1a51
.equ TIMEOUT, 0xbad11a51

.section .text.bsp,"ax"
.code64
    movl $(0x80000 | (AP_HANDLER & 0xffff)), IDT41_LOW
    movl $(0x8e00 | (AP_HANDLER & 0xffff0000)), IDT41_HIGH
    movl $IOAPIC_SELECTOR, %ecx
    movl $GSI4_HIGH, (%rcx)
    movl TARGET, %eax
    shll $24, %eax
    movl %eax, 16(%rcx)
    movl $GSI4_LOW, (%rcx)
    movl $(IRQ_VECTOR | RTE_LEVEL), 16(%rcx)
    movw $0x3fc, %dx
    movb $8, %al
    outb %al, %dx
    movw $0x3f9, %dx
    movb $2, %al
    outb %al, %dx
    movl $4000, %edi
1:
    cmpl $SUCCESS, OBS+12
    je 2f
    outb %al, $0x80
    decl %edi
    jnz 1b
    movl $TIMEOUT, OBS+16
    jmp 3f
2:
    /* Give an erroneously repeated fixed interrupt time to reach its AP. */
    movl $8, %ecx
4:
    outb %al, $0x80
    loop 4b
    movl $SUCCESS, OBS+16
3:
    movw $0x604, %dx
    movw $0x2000, %ax
    outw %ax, %dx
    hlt

.section .text.ap,"ax"
.code32
    pushal
    incl VISITS(,%ebp,4)
    movl IOAPIC_WINDOW, %eax
    movl %eax, OBS
    movw $0x604, %dx
    movw $0x2000, %ax
    /* Stop while the UART level is still asserted and the handler owns EOI. */
    outw %ax, %dx
.global irq_resume
irq_resume:
    movw $0x3fa, %dx
    inb %dx, %al
    movb %al, OBS+8
    movl $0, LAPIC_EOI
    movl IOAPIC_WINDOW, %eax
    movl %eax, OBS+4
    movl $SUCCESS, OBS+12
    popal
    iretl
