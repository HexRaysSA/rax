/* This whole contiguous interval is copied to an anonymous executable page.
   Its function-table record and xdata are built in other anonymous pages. */
.text
.p2align 2
.globl jit_template_start
.globl jit_template_end
.globl jit_handler
.globl jit_handler_data
.globl jit_marker_pointer
.seh_proc jit_template_start
jit_template_start:
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    .seh_endprologue
    mov x16, x0                    /* caller supplies genuine RaiseException */
    movz w0, #0x4567
    movk w0, #0xe123, lsl #16
    mov w1, #0
    mov w2, #0
    mov x3, xzr
    blr x16
    nop                            /* continuation PC remains in the body */
    mov w0, #7
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    .seh_endepilogue
    ret
    .seh_handler jit_handler, @except
    .seh_handlerdata
jit_handler_data:
    .long 0
    .text
.seh_endproc

/* EXCEPTION_DISPOSITION handler(ExceptionRecord*, establisher,
   ContextRecord*, DispatcherContext*).  The PC-relative ADR remains valid
   after this interval is copied.  Only the 64-bit marker pointer is patched. */
jit_handler:
    ldr w8, [x0]
    movz w9, #0x4567
    movk w9, #0xe123, lsl #16
    cmp w8, w9
    b.ne 1f
    adr x9, jit_marker_pointer
    ldr x9, [x9]
    cbz x9, 1f
    ldr w10, [x9]
    add w10, w10, #1
    str w10, [x9]
    mov w0, #0                    /* ExceptionContinueExecution */
    ret
1:
    mov w0, #1                    /* ExceptionContinueSearch */
    ret
.p2align 3
jit_marker_pointer:
    .quad 0
jit_template_end:
