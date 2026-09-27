/* Snapshot through public instructions, before any compiler-generated work.
 * Restore the caller's entire floating-point state after the checked snapshot.
 * The scalar arithmetic witness occurs AFTER the raw post-reset snapshot. */
#if defined(_M_IX86)
.intel_syntax noprefix
.text
.globl _fp_snapshot
_fp_snapshot:
    push ebx
    push esi
    push edi
    push ebp
    mov esi, dword ptr [esp + 20]
    mov edi, dword ptr [esp + 24]
    mov ebp, dword ptr [esp + 28]
    mov ebx, dword ptr [esp + 32]
    mov eax, dword ptr [esp + 36]
    fxsave [eax]
    fxrstor [esi]
    fxsave [edi]
    call ebx
    fxsave [ebp]
    mov eax, dword ptr [esp + 40]
    fld1
    fld1
    faddp st(1), st(0)
    fstp dword ptr [eax]
    mov eax, dword ptr [esp + 36]
    fxrstor [eax]
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret
.globl _fp_local_reset
_fp_local_reset:
    fninit
    mov eax, offset bootstrap_local_cw
    fldcw word ptr [eax]
    ldmxcsr [bootstrap_local_mxcsr]
    ret
.section .rdata,"dr"
.p2align 2
bootstrap_local_cw: .short 0x023F
.p2align 2
bootstrap_local_mxcsr: .long 0x1F80
#elif defined(_M_X64)
.intel_syntax noprefix
.text
.globl fp_snapshot
fp_snapshot:
    push rbx
    push rsi
    push rdi
    push rbp
    sub rsp, 40
    mov rsi, rcx
    mov rdi, rdx
    mov rbp, r8
    mov rbx, r9
    mov rax, qword ptr [rsp + 112]
    fxsave64 [rax]
    fxrstor64 [rsi]
    fxsave64 [rdi]
    call rbx
    fxsave64 [rbp]
    mov eax, 0x3FC00000
    movd xmm0, eax
    addss xmm0, xmm0
    movd eax, xmm0
    mov rcx, qword ptr [rsp + 120]
    mov dword ptr [rcx], eax
    mov rax, qword ptr [rsp + 112]
    fxrstor64 [rax]
    add rsp, 40
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret
.globl fp_local_reset
fp_local_reset:
    ldmxcsr [rip + bootstrap_local_mxcsr]
    ret
.section .rdata,"dr"
.p2align 2
bootstrap_local_mxcsr: .long 0x1F80
#elif defined(_M_ARM64)
.text
.macro save_fp base
    stp q0, q1, [\base, #0]
    stp q2, q3, [\base, #32]
    stp q4, q5, [\base, #64]
    stp q6, q7, [\base, #96]
    stp q8, q9, [\base, #128]
    stp q10, q11, [\base, #160]
    stp q12, q13, [\base, #192]
    stp q14, q15, [\base, #224]
    stp q16, q17, [\base, #256]
    stp q18, q19, [\base, #288]
    stp q20, q21, [\base, #320]
    stp q22, q23, [\base, #352]
    stp q24, q25, [\base, #384]
    stp q26, q27, [\base, #416]
    stp q28, q29, [\base, #448]
    stp q30, q31, [\base, #480]
    mrs x9, FPCR
    str x9, [\base, #512]
    mrs x9, FPSR
    str x9, [\base, #520]
    mrs x9, NZCV
    str x9, [\base, #528]
.endm
.macro load_fp base
    ldp q0, q1, [\base, #0]
    ldp q2, q3, [\base, #32]
    ldp q4, q5, [\base, #64]
    ldp q6, q7, [\base, #96]
    ldp q8, q9, [\base, #128]
    ldp q10, q11, [\base, #160]
    ldp q12, q13, [\base, #192]
    ldp q14, q15, [\base, #224]
    ldp q16, q17, [\base, #256]
    ldp q18, q19, [\base, #288]
    ldp q20, q21, [\base, #320]
    ldp q22, q23, [\base, #352]
    ldp q24, q25, [\base, #384]
    ldp q26, q27, [\base, #416]
    ldp q28, q29, [\base, #448]
    ldp q30, q31, [\base, #480]
    ldr x9, [\base, #512]
    msr FPCR, x9
    ldr x9, [\base, #520]
    msr FPSR, x9
    ldr x9, [\base, #528]
    msr NZCV, x9
.endm
.globl fp_snapshot
fp_snapshot:
    stp x29, x30, [sp, #-80]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x23, x4
    mov x24, x5
    save_fp x23
    load_fp x19
    save_fp x20
    blr x22
    save_fp x21
    fmov s0, #1.0
    fadd s0, s0, s0
    fmov w9, s0
    str w9, [x24]
    load_fp x23
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
.globl fp_local_reset
fp_local_reset:
    mov x8, #0
    msr FPCR, x8
    msr FPSR, x8
    ret
#endif
