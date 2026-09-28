/* A native ARM64 PE probe for both PAC unwind encodings. PACIBSP and
   AUTIBSP execute as hints on the selected non-PAuth ARMv8.2 guest CPU. */
.text
.globl entry
entry:
    bl signed_outer
    adrp x9, marker
    ldr w9, [x9, :lo12:marker]
    cmp w9, #7  /* handler 1 + inner 2 + outer 4, each exactly once */
    mov w0, #0
    b.eq 1f
    mov w0, #21
1:
    adrp x16, __imp_ExitProcess
    ldr x16, [x16, :lo12:__imp_ExitProcess]
    blr x16
    brk #0xf003

.globl signed_outer
.seh_proc signed_outer
signed_outer:
    pacibsp
    .seh_pac_sign_lr
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    .seh_endprologue
    bl signed_inner
    nop  /* the return PC must be in the function body, not the epilog */
    adrp x9, marker
    add x9, x9, :lo12:marker
    ldr w10, [x9]
    add w10, w10, #4
    str w10, [x9]
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    autibsp
    .seh_pac_sign_lr
    .seh_endepilogue
    ret
    .seh_handler signed_handler, @except
    .seh_handlerdata
    .long 0
    .text
.seh_endproc

.globl signed_inner
.seh_proc signed_inner
signed_inner:
    pacibsp
    .seh_pac_sign_lr
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    .seh_endprologue
    movz w0, #0x4567
    movk w0, #0xe123, lsl #16
    mov w1, #0
    mov w2, #0
    mov x3, xzr
    adrp x16, __imp_RaiseException
    ldr x16, [x16, :lo12:__imp_RaiseException]
    blr x16
    nop  /* the exception resumes at the export trap, then returns here */
    adrp x9, marker
    add x9, x9, :lo12:marker
    ldr w10, [x9]
    add w10, w10, #2
    str w10, [x9]
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    autibsp
    .seh_pac_sign_lr
    .seh_endepilogue
    ret
.seh_endproc

/* EXCEPTION_DISPOSITION handler(ExceptionRecord*, establisher,
   ContextRecord*, DispatcherContext*). The exception is continuable. */
.globl signed_handler
signed_handler:
    ldr w8, [x0]
    movz w9, #0x4567
    movk w9, #0xe123, lsl #16
    cmp w8, w9
    b.ne 1f
    adrp x9, marker
    add x9, x9, :lo12:marker
    ldr w10, [x9]
    add w10, w10, #1
    str w10, [x9]
    mov w0, #0  /* ExceptionContinueExecution */
    ret
1:
    mov w0, #1  /* ExceptionContinueSearch */
    ret

.data
.p2align 2
marker:
    .long 0
