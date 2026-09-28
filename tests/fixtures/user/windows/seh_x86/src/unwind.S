/* PE32 x86 RtlUnwind target-continuation and SEH-chain witness.
   A normal return from RtlUnwind is distinguishable from the landing pad. */
.text
.globl _entry
_entry:
    pushl %ebp
    movl %esp, %ebp
    subl $32, %esp

    /* Outer = [EBP-8, EBP), inner = [EBP-16, EBP-8). */
    movl %fs:0, %eax
    movl %eax, -8(%ebp)
    movl $_outer_handler, -4(%ebp)
    leal -8(%ebp), %eax
    movl %eax, %fs:0
    movl %eax, -16(%ebp)
    movl $_inner_handler, -12(%ebp)
    leal -16(%ebp), %eax
    movl %eax, %fs:0

    pushl $0x12345678            /* ReturnValue */
    pushl $0                     /* ExceptionRecord */
    pushl $_landing              /* TargetIp */
    leal -8(%ebp), %eax
    pushl %eax                   /* TargetFrame = outer */
    calll *__imp__RtlUnwind@16
    pushl $17                    /* The call must never return. */
    calll *__imp__ExitProcess@4

_landing:
    cmpl $0x12345678, %eax
    jne _bad_return_value
    cmpl $1, _handler_count
    jne _bad_callback
    movl %fs:0, %edx
    leal -8(%ebp), %ecx
    cmpl %ecx, %edx
    jne _bad_chain_head
    leal -32(%ebp), %edx
    cmpl %edx, %esp
    jne _bad_stack_pointer
    pushl $0
    calll *__imp__ExitProcess@4

_bad_return_value:
    pushl $18
    calll *__imp__ExitProcess@4
_bad_callback:
    pushl $19
    calll *__imp__ExitProcess@4
_bad_chain_head:
    pushl $20
    calll *__imp__ExitProcess@4
_bad_stack_pointer:
    pushl $21
    calll *__imp__ExitProcess@4

/* EXCEPTION_DISPOSITION __cdecl handler(record, frame, context, dispatcher). */
_inner_handler:
    movl 4(%esp), %edx
    testl $2, 4(%edx)             /* EXCEPTION_UNWINDING */
    jz _bad_handler_flags
    incl _handler_count
    movl $1, %eax                /* ExceptionContinueSearch */
    retl
_bad_handler_flags:
    movl $0xff, _handler_count
    movl $1, %eax
    retl

_outer_handler:
    movl $0xfe, _handler_count  /* Target frame must not be unwound. */
    movl $1, %eax
    retl

.data
.p2align 2
_handler_count:
    .long 0
