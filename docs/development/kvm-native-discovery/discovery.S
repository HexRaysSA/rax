.text
.code64
.global _start
_start:
cli
mov $1, %eax
cpuid
mov %eax, 0x210000
mov %edx, 0x210004
movabs $0xfee00030, %rax
mov (%rax), %eax
mov %eax, 0x210008
movabs $0xfec00000, %rax
movl $1, (%rax)
mov 0x10(%rax), %ebx
mov %ebx, 0x21000c
movl $0, (%rax)
mov 0x10(%rax), %ebx
mov %ebx, 0x210010
mov $0x604, %dx
mov $0x2000, %ax
out %ax, %dx
hlt
