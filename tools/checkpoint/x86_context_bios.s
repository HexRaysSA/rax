.intel_syntax noprefix
.code16
.section .text
.global _start
_start:
 cli
 xor ax,ax
 mov ds,ax
 mov ss,ax
 mov sp,0x7000
 mov eax,dword ptr [0x4c]
 mov dword ptr [old_int13],eax
 mov word ptr [0x4c],offset int13_shim
 mov word ptr [0x4e],0
 .rept 1000
 nop
 .endr
checkpoint_frontier:
 mov si,offset dap
 mov ax,0x4200
 mov dl,0xe0
 int 0x13
 jc failure
 mov al,byte ptr [0x1000]
 jmp emit
int13_shim:
 cmp dword ptr [old_int13],0
 je failure
 push word ptr [old_int13+2]
 push word ptr [old_int13]
 .byte 0xcb # 16-bit far return; LLVM Intel retf selected a 32-bit operand
failure:
 mov al,'F'
emit:
 mov dx,0x3f8
 out dx,al
 mov dx,0x604
 mov ax,0x2000
 out dx,ax
 cli
1: hlt
 jmp 1b
.balign 4
old_int13:
 .long 0
.balign 16
dap:
 .byte 16,0
 .short 1,0x1000,0
 .quad 25
.org 2048
