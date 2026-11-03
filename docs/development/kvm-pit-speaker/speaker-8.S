.text
.code64
.global _start
_start:
cli
in $0x61, %al
and $0xfc, %al
out %al, $0x61
mov $0xb0, %al
out %al, $0x43
mov $16, %al
out %al, $0x42
xor %eax, %eax
out %al, $0x42
mov $1, %al
out %al, $0x61
rdtsc
shl $32, %rdx
or %rdx, %rax
mov %rax, %r8
poll:
xor %eax, %eax
in $0x61, %al
mov %eax, %ebx
and $0xffffff00, %ebx
jnz failed
mov %eax, %ebx
and $3, %ebx
cmp $1, %ebx
jne failed
test $0x20, %al
jnz passed
rdtsc
shl $32, %rdx
or %rdx, %rax
sub %r8, %rax
cmp $1000000000, %rax
jb poll
failed:
mov $0xbad00061, %eax
jmp finish
passed:
mov $0x600d0061, %eax
finish:
mov %eax, 0x211000
mov $0x604, %dx
mov $0x2000, %ax
out %ax, %dx
hlt
