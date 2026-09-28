/* Entire range [dyn_template,dyn_template_end) is copied into guest-owned
   VirtualAlloc storage. All internal references are PC-relative or base-relative.
   No .seh_proc: the JIT function has no static PE .pdata entry. */
.text
.p2align 4
.globl dyn_template
dyn_template:
.globl dyn_code
dyn_code:
    pushq %rbx
    subq $48, %rsp
    /* Four x64 home slots occupy RSP+0..31 at the nested call. */
    movq %rcx, 32(%rsp)
    movabsq $0x51a7c00e51a7c00e, %rbx
    movq %rbx, 40(%rsp)
    movl $0xe1234567, %ecx
    xorl %edx, %edx       /* continuable exception, Flags = 0 */
    xorl %r8d, %r8d       /* NumberOfArguments = 0 */
    xorl %r9d, %r9d       /* Arguments = NULL */
    callq *dyn_raise_ptr(%rip)
    movl $0x42, %eax
    addq $48, %rsp
    popq %rbx
    retq
.globl dyn_code_end
dyn_code_end:

/* UNWIND_INFO: version 1, UNW_FLAG_EHANDLER; prolog 5 bytes;
   two unwind slots; no frame pointer. Ordered by descending prolog offset.
   At code+5: UWOP_ALLOC_SMALL, OpInfo=5 -> 5*8+8 = 48 bytes.
   At code+1: UWOP_PUSH_NONVOL, register RBX=3. */
.p2align 2
.globl dyn_unwind
dyn_unwind:
    .byte 0x09, 0x05, 0x02, 0x00
    .byte 0x05, 0x52
    .byte 0x01, 0x30
    .long dyn_handler - dyn_template

.p2align 3
.globl dyn_raise_ptr
dyn_raise_ptr:
    .quad 0               /* patched to imported RaiseException target */
.globl dyn_marker_ptr
dyn_marker_ptr:
    .quad 0               /* patched to guest C marker address */

.p2align 4
dyn_handler:
    /* EXCEPTION_DISPOSITION handler(ExceptionRecord*, EstablisherFrame,
       ContextRecord*, DispatcherContext*). The no-frame-register establisher
       is dynamic RSP after the prolog, where [RSP+32] and [RSP+40] were set. */
    cmpl $0xe1234567, (%rcx)
    jne .Lsearch
    testl $1, 4(%rcx)
    jne .Lsearch
    movq dyn_marker_ptr(%rip), %r10
    cmpq %r10, 32(%rdx)
    jne .Lbad_frame
    movabsq $0x51a7c00e51a7c00e, %r11
    cmpq %r11, 40(%rdx)
    jne .Lbad_frame
    addl $1, (%r10)
    xorl %eax, %eax       /* ExceptionContinueExecution = 0 */
    retq
.Lbad_frame:
    movl $0xbad, (%r10)
    xorl %eax, %eax       /* resume, then entry reports exit 15 */
    retq
.Lsearch:
    movl $1, %eax        /* ExceptionContinueSearch = 1 */
    retq

.p2align 4
.globl dyn_template_end
dyn_template_end:
