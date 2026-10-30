.text

off_hvc:
    mov w0, #8
    movk w0, #0x8400, lsl #16
    hvc #0
    mov x2, #0xbad
    hvc #0

reset_hvc:
    mov w0, #9
    movk w0, #0x8400, lsl #16
    hvc #0
    mov x2, #0xbad
    hvc #0

off_smc:
    mov w0, #8
    movk w0, #0x8400, lsl #16
    smc #0
    mov x2, #0xbad
    smc #0

reset_smc:
    mov w0, #9
    movk w0, #0x8400, lsl #16
    smc #0
    mov x2, #0xbad
    smc #0
