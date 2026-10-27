.section .text
.global _start
_start:
    nop
.global checkpoint_cookie
checkpoint_cookie:
    .byte 0xab
