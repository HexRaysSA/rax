.text
.code64
.global _start
_start:
    mov $0x3ff, %edx
    mov $0x5a, %al
    out %al, (%dx)
    mov $0x3fc, %edx
    mov $0x110000, %edi
    mov $256, %ecx
    rep insl
    mov $0x110003, %esi
    mov $256, %ecx
check:
    cmpb $0x5a, (%rsi)
    jne bad
    add $4, %rsi
    loop check
    movl $0x5a5a5a5a, 0x110400
    jmp done
bad:
    movl $0xbad0bad0, 0x110400
done:
    mov $0x604, %edx
    mov $0x2000, %eax
    out %ax, (%dx)
    hlt
