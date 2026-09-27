/* Real guest search scopes. No CRT language-personality helper is imported.
   The inner handler resumes a continuable RaiseException; outer never returns. */
#if defined(_M_IX86)
.text
.macro scoped name, handler
.globl _\name
_\name:
    pushl %ebx
    subl $8, %esp
    movl %fs:0, %eax
    movl %eax, 0(%esp)
    movl $_\handler, 4(%esp)
    movl %esp, %fs:0
    movl 16(%esp), %ebx
    calll *%ebx
    movl 0(%esp), %eax
    movl %eax, %fs:0
    addl $8, %esp
    popl %ebx
    retl
.endm
scoped outer_call, outer_handler
scoped inner_call, inner_handler
scoped unwind_call, unwind_handler
#elif defined(_M_X64)
.text
.macro scoped name, handler, unwind=0
.globl \name
.seh_proc \name
\name:
    pushq %rbx
    .seh_pushreg %rbx
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    movq %rcx, %rbx
    callq *%rbx
    nop /* Saved return PC must be in the body, not a recognized epilog. */
    addq $32, %rsp
    popq %rbx
    retq
    .if \unwind
    .seh_handler \handler, @except, @unwind
    .else
    .seh_handler \handler, @except
    .endif
    .seh_handlerdata
    .long 0
    .text
.seh_endproc
.endm
scoped outer_call, outer_handler
scoped inner_call, inner_handler
scoped unwind_call, unwind_handler, 1
#elif defined(_M_ARM64)
.text
.macro scoped name, handler, unwind=0
.globl \name
.seh_proc \name
\name:
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    .seh_endprologue
    blr x0
    nop /* Body return PC remains eligible for EH/UH handler dispatch. */
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    .seh_endepilogue
    ret
    .if \unwind
    .seh_handler \handler, @except, @unwind
    .else
    .seh_handler \handler, @except
    .endif
    .seh_handlerdata
    .long 0
    .text
.seh_endproc
.endm
scoped outer_call, outer_handler
scoped inner_call, inner_handler
scoped unwind_call, unwind_handler, 1
#endif
