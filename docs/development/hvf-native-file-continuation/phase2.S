// Continuation at the captured BSP PC; APs retain their existing IRQ handlers.
// Original native startup leaves every AP counter at two. Require three/four.
.intel_syntax noprefix
.text
.code64
.global _start
_start:
    mov edx, 0xfee00000
    mov edi, 3
round:
    mov DWORD PTR [rdx + 0x300], 0x000c0041
    mfence
    out 0x80, al
    mov ebp, 1000
wait:
    mov ecx, DWORD PTR [0x210000]
    mov ebx, 1
next:
    cmp ebx, ecx
    jae done_round
    cmp DWORD PTR [rbx * 8 + 0x200004], edi
    jne yield
    inc ebx
    jmp next
yield:
    out 0x80, al
    dec ebp
    jne wait
    mov DWORD PTR [0x210004], 0xbad2bad2
    jmp shutdown
done_round:
    inc edi
    cmp edi, 5
    jb round
    mov DWORD PTR [0x210004], 0x700d700d
shutdown:
    mov edx, 0x604
    mov eax, 0x2000
    out dx, ax
    hlt
