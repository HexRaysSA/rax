//! AVX-only YMM0-YMM15 wrapper for the native x86 entry trampoline.
//!
//! The inner trampoline remains authoritative for GPRs, RFLAGS, MXCSR, MMX,
//! and host-state sanitization. In vector mode three it deliberately skips
//! AVX-512 ZMM/K instructions; this wrapper imports and exports only the
//! architectural low 256 bits addressable by the admitted replay families.
//! Upper ZMM halves and all opmask registers remain in `GuestRegs`.

use super::GuestRegs;

macro_rules! x86_enter_native_ymm16_wrapper {
    ($global:literal, $type_directive:literal, $label:literal, $call:literal) => {
        core::arch::global_asm!(
            ".text",
            ".p2align 4",
            $global,
            $type_directive,
            $label,
            "push rbx", // preserve callee-saved host RBX and align the inner call
            "mov rbx, rsi",
            "vmovdqu ymm0,  [rbx+RAX_YMM_ZMM_OFFSET]",
            "vmovdqu ymm1,  [rbx+RAX_YMM_ZMM_OFFSET+64]",
            "vmovdqu ymm2,  [rbx+RAX_YMM_ZMM_OFFSET+128]",
            "vmovdqu ymm3,  [rbx+RAX_YMM_ZMM_OFFSET+192]",
            "vmovdqu ymm4,  [rbx+RAX_YMM_ZMM_OFFSET+256]",
            "vmovdqu ymm5,  [rbx+RAX_YMM_ZMM_OFFSET+320]",
            "vmovdqu ymm6,  [rbx+RAX_YMM_ZMM_OFFSET+384]",
            "vmovdqu ymm7,  [rbx+RAX_YMM_ZMM_OFFSET+448]",
            "vmovdqu ymm8,  [rbx+RAX_YMM_ZMM_OFFSET+512]",
            "vmovdqu ymm9,  [rbx+RAX_YMM_ZMM_OFFSET+576]",
            "vmovdqu ymm10, [rbx+RAX_YMM_ZMM_OFFSET+640]",
            "vmovdqu ymm11, [rbx+RAX_YMM_ZMM_OFFSET+704]",
            "vmovdqu ymm12, [rbx+RAX_YMM_ZMM_OFFSET+768]",
            "vmovdqu ymm13, [rbx+RAX_YMM_ZMM_OFFSET+832]",
            "vmovdqu ymm14, [rbx+RAX_YMM_ZMM_OFFSET+896]",
            "vmovdqu ymm15, [rbx+RAX_YMM_ZMM_OFFSET+960]",
            $call,
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET],     ymm0",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+64],  ymm1",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+128], ymm2",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+192], ymm3",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+256], ymm4",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+320], ymm5",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+384], ymm6",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+448], ymm7",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+512], ymm8",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+576], ymm9",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+640], ymm10",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+704], ymm11",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+768], ymm12",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+832], ymm13",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+896], ymm14",
            "vmovdqu [rbx+RAX_YMM_ZMM_OFFSET+960], ymm15",
            "vzeroupper",
            "pop rbx",
            "ret",
            ".set RAX_YMM_ZMM_OFFSET, {zmm_offset}",
            zmm_offset = const core::mem::offset_of!(GuestRegs, zmm),
        );
    };
}

#[cfg(target_vendor = "apple")]
x86_enter_native_ymm16_wrapper!(
    ".globl _rax_smir_enter_native_ymm16",
    "",
    "_rax_smir_enter_native_ymm16:",
    "call _rax_smir_enter_native"
);

#[cfg(all(not(target_vendor = "apple"), not(windows)))]
x86_enter_native_ymm16_wrapper!(
    ".globl rax_smir_enter_native_ymm16",
    ".type rax_smir_enter_native_ymm16,@function",
    "rax_smir_enter_native_ymm16:",
    "call rax_smir_enter_native"
);

// COFF symbol definition: storage class 2 (external), type 32 (function).
#[cfg(windows)]
x86_enter_native_ymm16_wrapper!(
    ".globl rax_smir_enter_native_ymm16",
    ".def rax_smir_enter_native_ymm16\n.scl 2\n.type 32\n.endef",
    "rax_smir_enter_native_ymm16:",
    "call rax_smir_enter_native"
);

// System V argument registers on every host, as for `rax_smir_enter_native`.
unsafe extern "sysv64" {
    fn rax_smir_enter_native_ymm16(entry: *const u8, state: *mut GuestRegs);
}

pub(super) unsafe fn enter_native_ymm16(entry: *const u8, state: *mut GuestRegs) {
    // SAFETY: the caller enforces the same trusted-lowered-code contract as
    // `ExecMem::run`; vector mode three additionally guarantees AVX support.
    unsafe { rax_smir_enter_native_ymm16(entry, state) };
}
