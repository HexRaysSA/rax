//! Native execution runtime for SMIR-lowered blocks (the JIT back end's
//! "executor"). This is the bridge that takes the x86-64 machine code produced
//! by [`crate::smir::lower::x86_64::X86_64Lowerer`] and actually runs it on the
//! host CPU, marshalling guest register state in and out.
//!
//! Gated behind the `smir-jit` feature. Two host backends are provided:
//!  * x86-64: entry trampoline `rax_smir_enter_native` (hand-written x86-64
//!    assembly) marshalling the x86 [`GuestRegs`] file in/out.
//!  * aarch64: entry trampoline `rax_a64_enter_native` (AArch64 assembly)
//!    marshalling the [`Aarch64GuestRegs`] file in/out.
//!  * RISC-V on x86-64/AArch64: a state-backed native entry point that reads
//!    and writes [`RiscVGuestRegs`] directly.
//! The first two paths rely on the lowerer's 1:1 identity register map (guest
//! GPR `N` ⇒ the same-named host GPR), so their only marshalling is once on
//! entry and once on exit.
//!
//! The x86-64 path is validated bit-exact against KVM by the differential
//! harness in `tests/suites/differential/x86_64/fuzz.rs` (`smir_native_*` tests). The AArch64 path is
//! validated against the AArch64 interpreter.

#![cfg(feature = "smir-jit")]

use super::{
    X86_GUEST_AC_FLAG_OFFSET, X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CALL_FN_OFFSET,
    X86_GUEST_CONTROL_WRITE_FN_OFFSET, X86_GUEST_CPL_OFFSET, X86_GUEST_CPUID_FN_OFFSET,
    X86_GUEST_CPUID_SSE4A_OFFSET, X86_GUEST_CPUID_TBM_OFFSET, X86_GUEST_CPUID_VP2INTERSECT_OFFSET,
    X86_GUEST_CPUID_XEON_PHI_AVX512_OFFSET, X86_GUEST_CPUID_XOP_OFFSET, X86_GUEST_CR0_OFFSET,
    X86_GUEST_CR2_OFFSET, X86_GUEST_CR3_OFFSET, X86_GUEST_CR4_OFFSET, X86_GUEST_CR8_OFFSET,
    X86_GUEST_CS_L_OFFSET, X86_GUEST_CTX_OFFSET, X86_GUEST_DR0_OFFSET, X86_GUEST_DR1_OFFSET,
    X86_GUEST_DR2_OFFSET, X86_GUEST_DR3_OFFSET, X86_GUEST_DR6_OFFSET, X86_GUEST_DR7_OFFSET,
    X86_GUEST_EFER_OFFSET, X86_GUEST_EXIT_PC_OFFSET, X86_GUEST_FS_BASE_OFFSET, X86_GUEST_GPR_COUNT,
    X86_GUEST_GS_BASE_OFFSET, X86_GUEST_K_OFFSET, X86_GUEST_KERNEL_GS_BASE_OFFSET,
    X86_GUEST_LOAD_FN_OFFSET, X86_GUEST_MM_OFFSET, X86_GUEST_MMX_ACTIVE_OFFSET,
    X86_GUEST_MSR_FN_OFFSET, X86_GUEST_MXCSR_OFFSET, X86_GUEST_PAIR_LOAD_FN_OFFSET,
    X86_GUEST_PAIR_STORE_FN_OFFSET, X86_GUEST_PKRU_OFFSET, X86_GUEST_RFLAGS_OFFSET,
    X86_GUEST_STORE_FN_OFFSET, X86_GUEST_TR_TYPE_OFFSET, X86_GUEST_TSC_ADJUST_OFFSET,
    X86_GUEST_TSC_AUX_OFFSET, X86_GUEST_TSC_FN_OFFSET, X86_GUEST_VEC_LOAD_FN_OFFSET,
    X86_GUEST_VEC_STORE_FN_OFFSET, X86_GUEST_VECTOR_ACTIVE_OFFSET, X86_GUEST_X87_TAG_WORD_OFFSET,
    X86_GUEST_XCR0_OFFSET, X86_GUEST_XGETBV1_OFFSET, X86_GUEST_ZMM_OFFSET, X86_HOST_MXCSR_OFFSET,
    X86_STATE_PTR_AT_RBP,
};

// ---- module tree (auto-split) ----
#[cfg(test)]
mod jit_gate_tests;
mod trampolines;
pub use trampolines::*;
mod x86_guest_regs;
pub use x86_guest_regs::*;
mod x86_atomic_rmw;
pub use x86_atomic_rmw::*;
#[cfg(target_arch = "x86_64")]
mod x86_ymm_trampoline;

/// Apple I-cache invalidation (libSystem). Required after writing a `MAP_JIT`
/// region and before executing it: on AArch64 the instruction cache is not
/// coherent with the data cache, so freshly written code may otherwise execute
/// stale bytes.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
}

#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
fn running_under_rosetta() -> bool {
    static TRANSLATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRANSLATED.get_or_init(|| {
        let mut translated = 0i32;
        let mut size = core::mem::size_of_val(&translated);
        let result = unsafe {
            libc::sysctlbyname(
                c"sysctl.proc_translated".as_ptr(),
                (&mut translated as *mut i32).cast(),
                &mut size,
                core::ptr::null_mut(),
                0,
            )
        };
        result == 0 && translated == 1
    })
}

/// Rosetta does not preserve unmasked MXCSR mask bits across native execution;
/// keep the unmasked-vector fast path on physical x86-64 hosts only.
#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_native_unmasked_mxcsr_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        !running_under_rosetta()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// compiler-rt instruction-cache flush (Linux/aarch64), same purpose as the
/// Apple `sys_icache_invalidate` above.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" {
    fn __clear_cache(start: *mut core::ffi::c_char, end: *mut core::ffi::c_char);
}

/// AArch64-host identity-map register file.
///
/// The native entry trampoline maps the architectural X/V register images into
/// matching host registers. The same host ABI is also used by the constrained
/// x86-on-AArch64 bridge, whose additional dynamic feature state is appended
/// after the architecture-neutral exit metadata. NZCV is stored in
/// architectural PSTATE position (bits 31:28); the remaining bits are
/// preserved as zero for now.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aarch64GuestRegs {
    /// X0-X30.
    pub x: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// PSTATE.NZCV in bits 31:28.
    pub nzcv: u64,
    /// Floating-point control register.
    pub fpcr: u64,
    /// Floating-point status register.
    pub fpsr: u64,
    /// V0-V31 as low/high u64 pairs.
    pub v: [u64; 64],
    /// Opaque context pointer passed as arg0 to AArch64 memory helpers.
    pub ctx: u64,
    /// Address of the load helper
    /// `extern "C" fn(ctx, addr, size, signed) -> (value, ok)`. The 16-byte
    /// return is an AAPCS64 two-eightbyte value: `value` in x0, `ok` (non-zero
    /// on success) in x1. The identity-map AArch64 lowerer's `Load` call-out
    /// fault-bails (records the faulting PC and exits to the interpreter) when
    /// `ok == 0` — so a `#[repr(C)] { value: u64, ok: u64 }` return is required
    /// for precise fault restart (analogous to the x86 helper's RAX:RDX).
    pub load_fn: u64,
    /// Address of `extern "C" fn(ctx, addr, value, size) -> ok` (non-zero on
    /// success; `ok == 0` fault-bails like the load helper).
    pub store_fn: u64,
    /// Address armed by the last load-exclusive.
    pub exclusive_addr: u64,
    /// Byte size armed by the last load-exclusive.
    pub exclusive_size: u64,
    /// Non-zero when the exclusive monitor is armed.
    pub exclusive_valid: u64,
    /// Address of the vector-load helper
    /// `extern "C" fn(state: *mut Aarch64GuestRegs, addr, dst_idx, size) -> ok`.
    /// It reads `size` bytes from guest memory (via `state.ctx`), zero-pads to 16
    /// bytes, and writes them into `state.v[2*dst_idx..]`; the lowered code then
    /// reloads the destination V register from that slot. Reusing `v[]` as the
    /// transfer scratch avoids a separate buffer.
    pub vec_load_fn: u64,
    /// Address of the vector-store helper
    /// `extern "C" fn(state, addr, src_idx, size) -> ok`: reads `state.v[2*src_idx..]`
    /// (which the lowered code has just written from the source V register) and
    /// stores `size` bytes to guest memory.
    pub vec_store_fn: u64,
    /// Native-region exit metadata. Bit 0 records that an exit occurred; the
    /// remaining bits carry architecture-specific state changes that cannot be
    /// represented by `pc` alone (currently AArch32 CPSR.T interworking).
    pub exit_flags: u64,
    /// Dynamic Intel APX enable state for admitted x86-on-AArch64 regions.
    /// Ordinary AArch64 and AArch32 guests leave this zero and cannot admit
    /// x86-specific feature guards through their native gates.
    pub x86_apx_enabled: u64,
    /// Dynamic AMD TBM enable state for admitted x86-on-AArch64 regions.
    pub x86_tbm_enabled: u64,
    /// Non-zero when the bridged x86 guest is in protected, non-virtual-8086
    /// 64-bit mode. Architectural compatibility-mode TBM deoptimizes because
    /// the strict x86-64 lifter models long-mode XOP.W and address defaults.
    pub x86_tbm_mode_valid: u64,
}

impl Default for Aarch64GuestRegs {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            v: [0; 64],
            ctx: 0,
            load_fn: 0,
            store_fn: 0,
            exclusive_addr: 0,
            exclusive_size: 0,
            exclusive_valid: 0,
            vec_load_fn: 0,
            vec_store_fn: 0,
            exit_flags: 0,
            x86_apx_enabled: 0,
            x86_tbm_enabled: 0,
            x86_tbm_mode_valid: 0,
        }
    }
}

impl Aarch64GuestRegs {
    pub const X0_OFFSET: i32 = 0;
    pub const SP_OFFSET: i32 = 31 * 8;
    pub const PC_OFFSET: i32 = 32 * 8;
    pub const NZCV_OFFSET: i32 = 33 * 8;
    pub const FPCR_OFFSET: i32 = 34 * 8;
    pub const FPSR_OFFSET: i32 = 35 * 8;
    pub const V_OFFSET: i32 = 36 * 8;
    pub const CTX_OFFSET: i32 = Self::V_OFFSET + 64 * 8;
    pub const LOAD_FN_OFFSET: i32 = Self::CTX_OFFSET + 8;
    pub const STORE_FN_OFFSET: i32 = Self::LOAD_FN_OFFSET + 8;
    pub const EXCLUSIVE_ADDR_OFFSET: i32 = Self::STORE_FN_OFFSET + 8;
    pub const EXCLUSIVE_SIZE_OFFSET: i32 = Self::EXCLUSIVE_ADDR_OFFSET + 8;
    pub const EXCLUSIVE_VALID_OFFSET: i32 = Self::EXCLUSIVE_SIZE_OFFSET + 8;
    pub const VEC_LOAD_FN_OFFSET: i32 = Self::EXCLUSIVE_VALID_OFFSET + 8;
    pub const VEC_STORE_FN_OFFSET: i32 = Self::VEC_LOAD_FN_OFFSET + 8;
    pub const EXIT_FLAGS_OFFSET: i32 = Self::VEC_STORE_FN_OFFSET + 8;
    pub const X86_APX_ENABLED_OFFSET: i32 = Self::EXIT_FLAGS_OFFSET + 8;
    pub const X86_TBM_ENABLED_OFFSET: i32 = Self::X86_APX_ENABLED_OFFSET + 8;
    pub const X86_TBM_MODE_VALID_OFFSET: i32 = Self::X86_TBM_ENABLED_OFFSET + 8;

    /// A native exit, rather than an ordinary `Return`, recorded `pc`.
    pub const EXIT_VALID: u64 = 1 << 0;
    /// The AArch32 exit selected Thumb state.
    pub const EXIT_AARCH32_T: u64 = 1 << 1;
    /// [`Self::EXIT_AARCH32_T`] contains a CPSR.T update.
    pub const EXIT_AARCH32_T_VALID: u64 = 1 << 2;
}

/// AArch32 scalar register file used by the A32-on-AArch64 identity JIT.
///
/// A32 r0-r15 map to host W0-W15 for admitted register-only regions.  CPSR is
/// retained in its complete architectural representation; only NZCV (bits
/// 31:28) is imported into host PSTATE and merged back after execution.  The
/// remaining CPSR fields (Q, GE, endianness, interrupt masks, T, and mode) are
/// stable across a scalar native region except that a validated interworking
/// exit can explicitly replace T from the branch target's low bit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch32GuestRegs {
    /// A32 r0-r15, with r15 holding the dispatcher PC snapshot.
    pub r: [u32; 16],
    /// Complete AArch32 CPSR.
    pub cpsr: u32,
}

/// Control-flow result from an A32-on-AArch64 native region.
///
/// `exited` distinguishes a valid exit to guest address zero from an ordinary
/// SMIR `Return`; `pc` is the zero-extended 32-bit dispatcher target when an
/// exit occurred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch32NativeExit {
    pub exited: bool,
    pub pc: u64,
}

/// Runtime-helper configuration for an AArch32 region lowered through the
/// AArch64 identity trampoline.
///
/// The callbacks use the same AAPCS64 contract as [`Aarch64GuestRegs`]. The
/// load helper returns a `#[repr(C)] { value: u64, ok: u64 }`; the store helper
/// returns non-zero on success. A zero `ok` value exits the region at the
/// faulting SMIR operation without committing its destination or writeback.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch32MemHelpers {
    /// Opaque helper context pointer.
    pub ctx: u64,
    /// Address of `extern "C" fn(ctx, addr, size, signed) -> (value, ok)`.
    pub load_fn: u64,
    /// Address of `extern "C" fn(ctx, addr, value, size) -> ok`.
    pub store_fn: u64,
}

pub use super::cross::riscv_x86_64_abi::{
    RISCV_FP_RESULT_INVALID, RiscVAtomicCasStatus, RiscVAtomicOpCode, RiscVFpOpCode,
    RiscVIntCryptoOpCode, RiscVMemoryOrderCode,
};

/// Two-register SysV result of [`RiscVGuestRegs::cas_fn`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiscVAtomicCasResult {
    pub old: u64,
    /// [`RiscVAtomicCasStatus`] encoded as a `u64`.
    pub status: u64,
}

/// Two-register SysV result for atomic RMW and exclusive-access helpers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiscVAtomicResult {
    pub value: u64,
    /// One for a completed access and zero for a guest-memory fault.
    pub access_success: u64,
}

/// Two-register SysV result of [`RiscVGuestRegs::load_fn`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiscVLoadResult {
    pub value: u64,
    /// One for a completed access and zero for a guest-memory fault.
    pub success: u64,
}

/// Two-register native-ABI result of [`RiscVGuestRegs::fp_fn`].
///
/// A valid operation returns the raw destination in `value` and the updated
/// FCSR in `fcsr_status`. An illegal operation or rounding mode returns
/// [`RISCV_FP_RESULT_INVALID`] in `fcsr_status`; generated code then traps
/// without committing either destination.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiscVFpResult {
    pub value: u64,
    pub fcsr_status: u64,
}

/// State ABI for RISC-V SMIR lowered to an x86-64 or AArch64 host.
///
/// The state-backed cross-lowerer accesses every field through the first native
/// ABI argument (RDI under x86-64 SysV; X0 under AAPCS64). All scalar fields use
/// eight-byte slots, including `fcsr`, so the layout is identical for RV32 and
/// RV64. Helper signatures follow the host ABI: x86-64 SysV or AAPCS64.
/// Atomic helpers share `ctx` and implement one indivisible transaction per
/// call. Integer-crypto and scalar-FP helpers are pure. `vector_fn(state, insn,
/// xlen)` returns exact success as one; every other status must leave both this
/// state and guest memory unchanged.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiscVGuestRegs {
    /// Integer registers x0-x31.  The lowerer hard-wires reads of x0 to zero and
    /// discards writes, independently of this backing slot.
    pub x: [u64; 32],
    /// Floating-point registers f0-f31 as raw IEEE-754/NaN-boxed bits.
    pub f: [u64; 32],
    /// Program counter at dispatcher re-entry.
    pub pc: u64,
    /// FCSR in bits 7:0; upper bits are reserved and kept zero by the guest ISA.
    pub fcsr: u64,
    /// Native exit classification: 0=return/branch, 1=trap, 2=syscall,
    /// 3=breakpoint.
    pub exit_reason: u64,
    /// Opaque memory-helper context.
    pub ctx: u64,
    /// Address of `extern "sysv64" fn(ctx, addr, size, signed) -> {value, success}`.
    pub load_fn: u64,
    /// Address of `extern "sysv64" fn(ctx, addr, value, size) -> success`.
    /// Returning zero must leave guest memory unchanged.
    pub store_fn: u64,
    /// `extern "sysv64" fn(ctx, addr, operand, size, op_code, order_code) ->
    /// {old, access_success}`.
    pub atomic_rmw_fn: u64,
    /// `extern "sysv64" fn(ctx, addr, expected, new, size, order_code) ->
    /// {old, status}`, where status is [`RiscVAtomicCasStatus`].
    pub cas_fn: u64,
    /// `extern "sysv64" fn(ctx, addr, expected_lo, expected_hi, new_lo,
    /// new_hi, success_order_code, failure_order_code, out_old_hi) ->
    /// {old_lo, status}`. `out_old_hi` receives the high word only for a
    /// completed access.
    pub cas_pair_fn: u64,
    /// `extern "sysv64" fn(ctx, addr, size) -> {value, access_success}`;
    /// establishes a reservation on success.
    pub load_exclusive_fn: u64,
    /// `extern "sysv64" fn(ctx, addr, value, size) ->
    /// {reservation_success, access_success}`.
    pub store_exclusive_fn: u64,
    /// `extern "sysv64" fn(ctx)`; clears the reservation without storing.
    pub clear_exclusive_fn: u64,
    /// `extern "sysv64" fn(op_code, src1, src2, imm, xlen) -> value`.
    pub int_crypto_fn: u64,
    /// `extern "sysv64" fn(op_code, rm, fcsr, a, b, c) -> {value, fcsr_status}`.
    pub fp_fn: u64,
    /// Raw 128-bit RVV register file, v0-v31.
    pub v: [[u8; 16]; 32],
    /// RVV vector length CSR (`vl`).
    pub vl: u64,
    /// RVV vector type CSR (`vtype`).
    pub vtype: u64,
    /// RVV vector restart CSR (`vstart`).
    pub vstart: u64,
    /// RVV fixed-point control/status CSR (`vcsr`).
    pub vcsr: u64,
    /// `extern "sysv64" fn(state, insn, xlen) -> success`.
    /// Non-success must be transactional with respect to state and memory.
    pub vector_fn: u64,
    /// Zcmt jump-vector-table CSR. Bits 5:0 are the WARL mode field and are
    /// zero for the only currently defined mode.
    pub jvt: u64,
}

impl Default for RiscVGuestRegs {
    fn default() -> Self {
        Self {
            x: [0; 32],
            f: [0; 32],
            pc: 0,
            fcsr: 0,
            exit_reason: 0,
            ctx: 0,
            load_fn: 0,
            store_fn: 0,
            atomic_rmw_fn: 0,
            cas_fn: 0,
            cas_pair_fn: 0,
            load_exclusive_fn: 0,
            store_exclusive_fn: 0,
            clear_exclusive_fn: 0,
            int_crypto_fn: 0,
            fp_fn: 0,
            v: [[0; 16]; 32],
            vl: 0,
            vtype: 0,
            vstart: 0,
            vcsr: 0,
            vector_fn: 0,
            jvt: 0,
        }
    }
}

impl RiscVGuestRegs {
    pub const X_OFFSET: i32 = 0;
    pub const F_OFFSET: i32 = 32 * 8;
    pub const PC_OFFSET: i32 = Self::F_OFFSET + 32 * 8;
    pub const FCSR_OFFSET: i32 = Self::PC_OFFSET + 8;
    pub const EXIT_REASON_OFFSET: i32 = Self::FCSR_OFFSET + 8;
    pub const CTX_OFFSET: i32 = Self::EXIT_REASON_OFFSET + 8;
    pub const LOAD_FN_OFFSET: i32 = Self::CTX_OFFSET + 8;
    pub const STORE_FN_OFFSET: i32 = Self::LOAD_FN_OFFSET + 8;
    pub const ATOMIC_RMW_FN_OFFSET: i32 = Self::STORE_FN_OFFSET + 8;
    pub const CAS_FN_OFFSET: i32 = Self::ATOMIC_RMW_FN_OFFSET + 8;
    pub const CAS_PAIR_FN_OFFSET: i32 = Self::CAS_FN_OFFSET + 8;
    pub const LOAD_EXCLUSIVE_FN_OFFSET: i32 = Self::CAS_PAIR_FN_OFFSET + 8;
    pub const STORE_EXCLUSIVE_FN_OFFSET: i32 = Self::LOAD_EXCLUSIVE_FN_OFFSET + 8;
    pub const CLEAR_EXCLUSIVE_FN_OFFSET: i32 = Self::STORE_EXCLUSIVE_FN_OFFSET + 8;
    pub const INT_CRYPTO_FN_OFFSET: i32 = Self::CLEAR_EXCLUSIVE_FN_OFFSET + 8;
    pub const FP_FN_OFFSET: i32 = Self::INT_CRYPTO_FN_OFFSET + 8;
    pub const V_OFFSET: i32 = Self::FP_FN_OFFSET + 8;
    pub const VL_OFFSET: i32 = Self::V_OFFSET + 32 * 16;
    pub const VTYPE_OFFSET: i32 = Self::VL_OFFSET + 8;
    pub const VSTART_OFFSET: i32 = Self::VTYPE_OFFSET + 8;
    pub const VCSR_OFFSET: i32 = Self::VSTART_OFFSET + 8;
    pub const VECTOR_FN_OFFSET: i32 = Self::VCSR_OFFSET + 8;
    pub const JVT_OFFSET: i32 = Self::VECTOR_FN_OFFSET + 8;
}

// enter_native(rdi = entry ptr, rsi = *mut GuestRegs):
//   preserve host callee-saved -> load guest GPRs+RFLAGS and, for an admitted
//   vector region, ZMM0-ZMM31+K0-K7 into the identical host regs -> `call` the
//   block -> store the live architectural state back into GuestRegs.
// RSP (gpr[4]) is NOT loaded — the block runs on the host stack (it owns no
// guest stack). Alignment: 6 callee pushes (48) + `sub rsp,24` (72 total) leaves
// rsp 16-aligned at the `call`.
#[cfg(target_arch = "x86_64")]
macro_rules! x86_enter_native_trampoline {
    ($global:literal, $type_directive:literal, $label:literal) => {
        core::arch::global_asm!(
            ".text",
            ".p2align 4",
            $global,
            $type_directive,
            $label,
            "push rbp",
            "push rbx",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "sub rsp, 24", // [rsp]=entry [rsp+8]=state [rsp+16]=pad ; rsp 16-aligned
            "mov [rsp], rdi",
            "mov [rsp+8], rsi",
            // Preserve host FP control/status before any guest state is loaded.
            // Helper call boundaries use the saved copy while executing Rust.
            "stmxcsr [rsi+2444]",
            // Vector state is optional. The branch executes before guest RFLAGS
            // are installed, so its CMP cannot perturb architectural flags.
            "cmp qword ptr [rsi+2432], 0",
            "je 2f",
            // Mode three delegates YMM0-YMM15 to the outer AVX-only wrapper.
            // This trampoline still owns guest/host MXCSR switching.
            "cmp qword ptr [rsi+2432], 3",
            "je 9f",
            "vmovdqu64 zmm0,  [rsi+320]",
            "vmovdqu64 zmm1,  [rsi+384]",
            "vmovdqu64 zmm2,  [rsi+448]",
            "vmovdqu64 zmm3,  [rsi+512]",
            "vmovdqu64 zmm4,  [rsi+576]",
            "vmovdqu64 zmm5,  [rsi+640]",
            "vmovdqu64 zmm6,  [rsi+704]",
            "vmovdqu64 zmm7,  [rsi+768]",
            "vmovdqu64 zmm8,  [rsi+832]",
            "vmovdqu64 zmm9,  [rsi+896]",
            "vmovdqu64 zmm10, [rsi+960]",
            "vmovdqu64 zmm11, [rsi+1024]",
            "vmovdqu64 zmm12, [rsi+1088]",
            "vmovdqu64 zmm13, [rsi+1152]",
            "vmovdqu64 zmm14, [rsi+1216]",
            "vmovdqu64 zmm15, [rsi+1280]",
            "vmovdqu64 zmm16, [rsi+1344]",
            "vmovdqu64 zmm17, [rsi+1408]",
            "vmovdqu64 zmm18, [rsi+1472]",
            "vmovdqu64 zmm19, [rsi+1536]",
            "vmovdqu64 zmm20, [rsi+1600]",
            "vmovdqu64 zmm21, [rsi+1664]",
            "vmovdqu64 zmm22, [rsi+1728]",
            "vmovdqu64 zmm23, [rsi+1792]",
            "vmovdqu64 zmm24, [rsi+1856]",
            "vmovdqu64 zmm25, [rsi+1920]",
            "vmovdqu64 zmm26, [rsi+1984]",
            "vmovdqu64 zmm27, [rsi+2048]",
            "vmovdqu64 zmm28, [rsi+2112]",
            "vmovdqu64 zmm29, [rsi+2176]",
            "vmovdqu64 zmm30, [rsi+2240]",
            "vmovdqu64 zmm31, [rsi+2304]",
            "cmp qword ptr [rsi+2432], 2",
            "je 5f",
            "kmovq k0, [rsi+2368]",
            "kmovq k1, [rsi+2376]",
            "kmovq k2, [rsi+2384]",
            "kmovq k3, [rsi+2392]",
            "kmovq k4, [rsi+2400]",
            "kmovq k5, [rsi+2408]",
            "kmovq k6, [rsi+2416]",
            "kmovq k7, [rsi+2424]",
            "jmp 6f",
            "5:",
            "kmovw k0, word ptr [rsi+2368]",
            "kmovw k1, word ptr [rsi+2376]",
            "kmovw k2, word ptr [rsi+2384]",
            "kmovw k3, word ptr [rsi+2392]",
            "kmovw k4, word ptr [rsi+2400]",
            "kmovw k5, word ptr [rsi+2408]",
            "kmovw k6, word ptr [rsi+2416]",
            "kmovw k7, word ptr [rsi+2424]",
            "6:",
            "9:",
            "ldmxcsr [rsi+2440]",
            "2:",
            // MMX state is independent of the AVX-512 vector path. MOVQ itself
            // enters host MMX state; the matching exit path always executes
            // EMMS after exporting MM0-MM7.
            "cmp qword ptr [rsi+2600], 0",
            "je 4f",
            "movq mm0, qword ptr [rsi+2536]",
            "movq mm1, qword ptr [rsi+2544]",
            "movq mm2, qword ptr [rsi+2552]",
            "movq mm3, qword ptr [rsi+2560]",
            "movq mm4, qword ptr [rsi+2568]",
            "movq mm5, qword ptr [rsi+2576]",
            "movq mm6, qword ptr [rsi+2584]",
            "movq mm7, qword ptr [rsi+2592]",
            "4:",
            "mov rax, [rsi+256]", // RFLAGS
            // Never import guest TF/NT/AC into host CPL3 execution. DF remains
            // live because native string lowering implements guest direction.
            "and rax, -0x44101", // ~0x44100: clear TF(0x100)+NT(0x4000)+AC(0x40000)
            "push rax",
            "popfq",
            "mov rax, [rsi+0]",
            "mov rcx, [rsi+8]",
            "mov rdx, [rsi+16]",
            "mov rbx, [rsi+24]",
            "mov rbp, [rsi+40]",
            "mov rdi, [rsi+56]",
            "mov r8,  [rsi+64]",
            "mov r9,  [rsi+72]",
            "mov r10, [rsi+80]",
            "mov r11, [rsi+88]",
            "mov r12, [rsi+96]",
            "mov r13, [rsi+104]",
            "mov r14, [rsi+112]",
            "mov r15, [rsi+120]",
            "mov rsi, [rsi+48]", // rsi last (was the base pointer)
            "call [rsp]",
            "push rax",          // save guest RAX ; state now at [rsp+16]
            "mov rax, [rsp+16]", // rax = *mut GuestRegs
            "mov [rax+8],   rcx",
            "mov [rax+16],  rdx",
            "mov [rax+24],  rbx",
            "mov [rax+40],  rbp",
            "mov [rax+48],  rsi",
            "mov [rax+56],  rdi",
            "mov [rax+64],  r8",
            "mov [rax+72],  r9",
            "mov [rax+80],  r10",
            "mov [rax+88],  r11",
            "mov [rax+96],  r12",
            "mov [rax+104], r13",
            "mov [rax+112], r14",
            "mov [rax+120], r15",
            "pushfq",
            "pop rcx",
            // Native execution owns only the six arithmetic status flags.
            // Preserve every other host-safe bit from the guest image: userspace
            // cannot import guest IF/IOPL through POPFQ, and exporting the raw
            // host image would otherwise inject host control state into the
            // guest. AC remains clear here because its guest value lives in the
            // dedicated ac_flag shadow.
            "mov rdx, [rax+256]",
            "and rcx, 0x8D5",    // CF|PF|AF|ZF|SF|OF
            "and rdx, -0x408D6", // complement of (0x8D5|AC)
            "or rcx, rdx",
            "mov [rax+256], rcx",
            // Guest flags are captured above, so the vector-active test can no
            // longer alter the state returned to the emulator.
            "cmp qword ptr [rax+2432], 0",
            "je 3f",
            // The outer AVX-only wrapper exports YMM0-YMM15 after this call.
            "cmp qword ptr [rax+2432], 3",
            "je 9f",
            "vmovdqu64 [rax+320],  zmm0",
            "vmovdqu64 [rax+384],  zmm1",
            "vmovdqu64 [rax+448],  zmm2",
            "vmovdqu64 [rax+512],  zmm3",
            "vmovdqu64 [rax+576],  zmm4",
            "vmovdqu64 [rax+640],  zmm5",
            "vmovdqu64 [rax+704],  zmm6",
            "vmovdqu64 [rax+768],  zmm7",
            "vmovdqu64 [rax+832],  zmm8",
            "vmovdqu64 [rax+896],  zmm9",
            "vmovdqu64 [rax+960],  zmm10",
            "vmovdqu64 [rax+1024], zmm11",
            "vmovdqu64 [rax+1088], zmm12",
            "vmovdqu64 [rax+1152], zmm13",
            "vmovdqu64 [rax+1216], zmm14",
            "vmovdqu64 [rax+1280], zmm15",
            "vmovdqu64 [rax+1344], zmm16",
            "vmovdqu64 [rax+1408], zmm17",
            "vmovdqu64 [rax+1472], zmm18",
            "vmovdqu64 [rax+1536], zmm19",
            "vmovdqu64 [rax+1600], zmm20",
            "vmovdqu64 [rax+1664], zmm21",
            "vmovdqu64 [rax+1728], zmm22",
            "vmovdqu64 [rax+1792], zmm23",
            "vmovdqu64 [rax+1856], zmm24",
            "vmovdqu64 [rax+1920], zmm25",
            "vmovdqu64 [rax+1984], zmm26",
            "vmovdqu64 [rax+2048], zmm27",
            "vmovdqu64 [rax+2112], zmm28",
            "vmovdqu64 [rax+2176], zmm29",
            "vmovdqu64 [rax+2240], zmm30",
            "vmovdqu64 [rax+2304], zmm31",
            "cmp qword ptr [rax+2432], 2",
            "je 7f",
            "kmovq [rax+2368], k0",
            "kmovq [rax+2376], k1",
            "kmovq [rax+2384], k2",
            "kmovq [rax+2392], k3",
            "kmovq [rax+2400], k4",
            "kmovq [rax+2408], k5",
            "kmovq [rax+2416], k6",
            "kmovq [rax+2424], k7",
            "jmp 8f",
            "7:",
            "kmovw word ptr [rax+2368], k0",
            "kmovw word ptr [rax+2376], k1",
            "kmovw word ptr [rax+2384], k2",
            "kmovw word ptr [rax+2392], k3",
            "kmovw word ptr [rax+2400], k4",
            "kmovw word ptr [rax+2408], k5",
            "kmovw word ptr [rax+2416], k6",
            "kmovw word ptr [rax+2424], k7",
            "8:",
            "9:",
            "stmxcsr [rax+2440]",
            "3:",
            // Export the complete guest MMX file before returning the host x87
            // unit to the empty-tag state required after MMX use.
            "cmp qword ptr [rax+2600], 0",
            "je 4f",
            "movq qword ptr [rax+2536], mm0",
            "movq qword ptr [rax+2544], mm1",
            "movq qword ptr [rax+2552], mm2",
            "movq qword ptr [rax+2560], mm3",
            "movq qword ptr [rax+2568], mm4",
            "movq qword ptr [rax+2576], mm5",
            "movq qword ptr [rax+2584], mm6",
            "movq qword ptr [rax+2592], mm7",
            "emms",
            "4:",
            "ldmxcsr [rax+2444]",
            // Sanitize HOST EFLAGS before returning to Rust. Entry already masks
            // TF/NT/AC, while guest DF remains live for native string semantics. Clear
            // DF and reassert the complete host-safety mask here: DF reverses host `rep`
            // string operations, AC can raise #AC/SIGBUS on unaligned host accesses, TF
            // would single-step, and NT is not host-process state. Arithmetic flags are
            // caller-saved scratch the host re-derives, so they need no restoration.
            "pushfq",
            "and qword ptr [rsp], -0x44501", // ~0x44500: clear TF(0x100)+DF(0x400)+NT(0x4000)+AC(0x40000)
            "popfq",
            "mov rcx, [rsp]", // saved guest RAX
            "mov [rax+0], rcx",
            "add rsp, 8",  // pop saved RAX
            "add rsp, 24", // pop locals
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp",
            "ret",
        );
    };
}

#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
x86_enter_native_trampoline!(
    ".globl _rax_smir_enter_native",
    "",
    "_rax_smir_enter_native:"
);

#[cfg(all(target_arch = "x86_64", not(target_vendor = "apple")))]
x86_enter_native_trampoline!(
    ".globl rax_smir_enter_native",
    ".type rax_smir_enter_native,@function",
    "rax_smir_enter_native:"
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn rax_smir_enter_native(entry: *const u8, state: *mut GuestRegs);
}

// rax_a64_enter_native(x0 = entry ptr, x1 = *mut Aarch64GuestRegs):
//   Identity-mapped AArch64-on-AArch64 entry trampoline. Saves the host
//   callee-saved GPRs (x19-x30), loads guest X0-X17/X19-X27/X29 + NZCV from the
//   struct into the identical host registers, runs the block on the HOST stack,
//   then stores the live host registers back into the struct.
//
//   Reserved host registers (NOT mapped to guest, must be left untouched by the
//   block — the clobber gate enforces this):
//     x28 = persistent *mut Aarch64GuestRegs (so exit stubs can `str <pc>,[x28,#PC]`)
//     x30 = link register / return into this trampoline (block ends with `ret`)
//     x18 = platform register (reserved by the macOS ABI; never clobber)
//     sp  = host stack (guest SP is not loaded; SP-relative guest code deopts)
//   Guest x18/x28/x30 round-trip untouched (their struct slots are preserved).
//
//   Frame (112 bytes, 16-aligned): [sp+0..88] host x19..x30, [sp+96] entry.
//   Both `_rax_a64_enter_native` (Mach-O) and `rax_a64_enter_native` (ELF) are
//   defined so the C symbol resolves on macOS and Linux alike.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".p2align 2",
    ".globl _rax_a64_enter_native",
    ".globl rax_a64_enter_native",
    "_rax_a64_enter_native:",
    "rax_a64_enter_native:",
    "sub sp, sp, #112",
    "stp x19, x20, [sp, #0]",
    "stp x21, x22, [sp, #16]",
    "stp x23, x24, [sp, #32]",
    "stp x25, x26, [sp, #48]",
    "stp x27, x28, [sp, #64]",
    "stp x29, x30, [sp, #80]",
    "str x0, [sp, #96]",   // stash entry (guest x0 is about to overwrite host x0)
    "mov x28, x1",         // x28 = regs ptr, reserved for the duration of the block
    "ldr w9, [x28, #264]", // NZCV (offset 33*8); load before guest x9 below
    "msr nzcv, x9",
    "ldp x0, x1, [x28, #0]",
    "ldp x2, x3, [x28, #16]",
    "ldp x4, x5, [x28, #32]",
    "ldp x6, x7, [x28, #48]",
    "ldp x8, x9, [x28, #64]",
    "ldp x10, x11, [x28, #80]",
    "ldp x12, x13, [x28, #96]",
    "ldp x14, x15, [x28, #112]",
    "ldp x16, x17, [x28, #128]",
    // skip x18 (offset 144) — reserved platform register
    "ldr x19, [x28, #152]",
    "ldr x20, [x28, #160]",
    "ldr x21, [x28, #168]",
    "ldr x22, [x28, #176]",
    "ldr x23, [x28, #184]",
    "ldr x24, [x28, #192]",
    "ldr x25, [x28, #200]",
    "ldr x26, [x28, #208]",
    "ldr x27, [x28, #216]",
    // skip x28 (offset 224) — holds the regs ptr
    "ldr x29, [x28, #232]",
    // skip x30 (offset 240) — reserved link register
    "ldr x30, [sp, #96]", // x30 = entry; blr sets x30 = return addr below
    "blr x30",
    "stp x0, x1, [x28, #0]",
    "stp x2, x3, [x28, #16]",
    "stp x4, x5, [x28, #32]",
    "stp x6, x7, [x28, #48]",
    "stp x8, x9, [x28, #64]",
    "stp x10, x11, [x28, #80]",
    "stp x12, x13, [x28, #96]",
    "stp x14, x15, [x28, #112]",
    "stp x16, x17, [x28, #128]",
    "str x19, [x28, #152]",
    "str x20, [x28, #160]",
    "str x21, [x28, #168]",
    "str x22, [x28, #176]",
    "str x23, [x28, #184]",
    "str x24, [x28, #192]",
    "str x25, [x28, #200]",
    "str x26, [x28, #208]",
    "str x27, [x28, #216]",
    "str x29, [x28, #232]",
    "mrs x9, nzcv", // x9 already stored above; reuse as scratch
    "str x9, [x28, #264]",
    "ldp x19, x20, [sp, #0]",
    "ldp x21, x22, [sp, #16]",
    "ldp x23, x24, [sp, #32]",
    "ldp x25, x26, [sp, #48]",
    "ldp x27, x28, [sp, #64]",
    "ldp x29, x30, [sp, #80]",
    "add sp, sp, #112",
    "ret",
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn rax_a64_enter_native(entry: *const u8, regs: *mut Aarch64GuestRegs);
}

// rax_a64_enter_native_fp(x0 = entry, x1 = *mut Aarch64GuestRegs):
//   Like rax_a64_enter_native but ALSO marshals V0-V31 + FPCR/FPSR, for regions
//   that use scalar FP / SIMD. Saves the host AAPCS64 callee-saved low-64 of
//   V8-V15 and the host FPCR/FPSR (restored on exit so guest rounding never
//   leaks into host float code). Same GPR/NZCV/reserved-register contract as the
//   scalar trampoline. Frame: 192 B (x19-x30 @0..88, entry @96, host_fpcr @104,
//   host_fpsr @112, d8-d15 @120..184). Aarch64GuestRegs.v is [u64;64] @288, so
//   Vn occupies bytes 288 + n*16 (q-register pairs, imm7 = byteoffset/16).
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".p2align 2",
    ".globl _rax_a64_enter_native_fp",
    ".globl rax_a64_enter_native_fp",
    "_rax_a64_enter_native_fp:",
    "rax_a64_enter_native_fp:",
    "sub sp, sp, #192",
    "stp x19, x20, [sp, #0]",
    "stp x21, x22, [sp, #16]",
    "stp x23, x24, [sp, #32]",
    "stp x25, x26, [sp, #48]",
    "stp x27, x28, [sp, #64]",
    "stp x29, x30, [sp, #80]",
    "str x0, [sp, #96]",      // stash entry
    "stp d8, d9, [sp, #120]", // save host callee-saved V8-V15 (low 64)
    "stp d10, d11, [sp, #136]",
    "stp d12, d13, [sp, #152]",
    "stp d14, d15, [sp, #168]",
    "mrs x9, fpcr", // save host FPCR/FPSR
    "str x9, [sp, #104]",
    "mrs x9, fpsr",
    "str x9, [sp, #112]",
    "mov x28, x1",         // x28 = regs ptr
    "ldr w9, [x28, #272]", // guest FPCR -> host (honor guest rounding)
    "msr fpcr, x9",
    "ldr w9, [x28, #280]", // guest FPSR
    "msr fpsr, x9",
    "ldr w9, [x28, #264]", // NZCV
    "msr nzcv, x9",
    "ldp x0, x1, [x28, #0]",
    "ldp x2, x3, [x28, #16]",
    "ldp x4, x5, [x28, #32]",
    "ldp x6, x7, [x28, #48]",
    "ldp x8, x9, [x28, #64]",
    "ldp x10, x11, [x28, #80]",
    "ldp x12, x13, [x28, #96]",
    "ldp x14, x15, [x28, #112]",
    "ldp x16, x17, [x28, #128]",
    "ldr x19, [x28, #152]",
    "ldr x20, [x28, #160]",
    "ldr x21, [x28, #168]",
    "ldr x22, [x28, #176]",
    "ldr x23, [x28, #184]",
    "ldr x24, [x28, #192]",
    "ldr x25, [x28, #200]",
    "ldr x26, [x28, #208]",
    "ldr x27, [x28, #216]",
    "ldr x29, [x28, #232]",
    "ldp q0, q1, [x28, #288]", // load guest V0-V31
    "ldp q2, q3, [x28, #320]",
    "ldp q4, q5, [x28, #352]",
    "ldp q6, q7, [x28, #384]",
    "ldp q8, q9, [x28, #416]",
    "ldp q10, q11, [x28, #448]",
    "ldp q12, q13, [x28, #480]",
    "ldp q14, q15, [x28, #512]",
    "ldp q16, q17, [x28, #544]",
    "ldp q18, q19, [x28, #576]",
    "ldp q20, q21, [x28, #608]",
    "ldp q22, q23, [x28, #640]",
    "ldp q24, q25, [x28, #672]",
    "ldp q26, q27, [x28, #704]",
    "ldp q28, q29, [x28, #736]",
    "ldp q30, q31, [x28, #768]",
    "ldr x30, [sp, #96]", // entry
    "blr x30",
    "stp q0, q1, [x28, #288]", // store guest V0-V31
    "stp q2, q3, [x28, #320]",
    "stp q4, q5, [x28, #352]",
    "stp q6, q7, [x28, #384]",
    "stp q8, q9, [x28, #416]",
    "stp q10, q11, [x28, #448]",
    "stp q12, q13, [x28, #480]",
    "stp q14, q15, [x28, #512]",
    "stp q16, q17, [x28, #544]",
    "stp q18, q19, [x28, #576]",
    "stp q20, q21, [x28, #608]",
    "stp q22, q23, [x28, #640]",
    "stp q24, q25, [x28, #672]",
    "stp q26, q27, [x28, #704]",
    "stp q28, q29, [x28, #736]",
    "stp q30, q31, [x28, #768]",
    "stp x0, x1, [x28, #0]",
    "stp x2, x3, [x28, #16]",
    "stp x4, x5, [x28, #32]",
    "stp x6, x7, [x28, #48]",
    "stp x8, x9, [x28, #64]",
    "stp x10, x11, [x28, #80]",
    "stp x12, x13, [x28, #96]",
    "stp x14, x15, [x28, #112]",
    "stp x16, x17, [x28, #128]",
    "str x19, [x28, #152]",
    "str x20, [x28, #160]",
    "str x21, [x28, #168]",
    "str x22, [x28, #176]",
    "str x23, [x28, #184]",
    "str x24, [x28, #192]",
    "str x25, [x28, #200]",
    "str x26, [x28, #208]",
    "str x27, [x28, #216]",
    "str x29, [x28, #232]",
    "mrs x9, nzcv",
    "str x9, [x28, #264]",
    "mrs x9, fpcr", // guest FPCR out (MSR FPCR inside region may update it)
    "str x9, [x28, #272]",
    "mrs x9, fpsr", // guest FPSR (accumulated exception flags) out
    "str x9, [x28, #280]",
    "ldr x9, [sp, #104]", // restore host FPCR/FPSR
    "msr fpcr, x9",
    "ldr x9, [sp, #112]",
    "msr fpsr, x9",
    "ldp d8, d9, [sp, #120]", // restore host V8-V15
    "ldp d10, d11, [sp, #136]",
    "ldp d12, d13, [sp, #152]",
    "ldp d14, d15, [sp, #168]",
    "ldp x19, x20, [sp, #0]",
    "ldp x21, x22, [sp, #16]",
    "ldp x23, x24, [sp, #32]",
    "ldp x25, x26, [sp, #48]",
    "ldp x27, x28, [sp, #64]",
    "ldp x29, x30, [sp, #80]",
    "add sp, sp, #192",
    "ret",
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn rax_a64_enter_native_fp(entry: *const u8, regs: *mut Aarch64GuestRegs);
}

/// Byte offset of `GuestRegs.exit_pc` (after `gpr[32]` + `rflags`). An exit stub
/// writes the resume guest PC here via the state pointer.
pub const EXIT_PC_OFFSET: i32 = X86_GUEST_EXIT_PC_OFFSET;

/// Offset of the `*mut GuestRegs` state pointer relative to a lowered block's
/// frame pointer (RBP), under the `rax_smir_enter_native` trampoline's stack
/// layout: the trampoline does `sub rsp,24; [rsp+8]=state` before `call`, and
/// the block's prologue `push rbp; mov rbp,rsp` lands RBP 24 bytes below that
/// slot — so `[rbp+24]` holds the state pointer throughout the block. An exit
/// stub loads it from here to record `exit_pc` (no reserved guest register).
pub const STATE_PTR_AT_RBP: i32 = X86_STATE_PTR_AT_RBP;

/// Byte offset of `GuestRegs.ctx` (the memory-helper context pointer).
pub const CTX_OFFSET: i32 = X86_GUEST_CTX_OFFSET;
/// Byte offset of `GuestRegs.load_fn` (the memory-load helper address).
pub const LOAD_FN_OFFSET: i32 = X86_GUEST_LOAD_FN_OFFSET;
/// Byte offset of `GuestRegs.store_fn` (the memory-store helper address).
pub const STORE_FN_OFFSET: i32 = X86_GUEST_STORE_FN_OFFSET;
/// Byte offset of `GuestRegs.fs_base` (the FS segment base for `fs:` operands).
pub const FS_BASE_OFFSET: i32 = X86_GUEST_FS_BASE_OFFSET;
/// Byte offset of `GuestRegs.gs_base` (the GS segment base for `gs:` operands).
pub const GS_BASE_OFFSET: i32 = X86_GUEST_GS_BASE_OFFSET;
/// Byte offset of `GuestRegs.call_fn` (the lift-through-calls helper address).
pub const CALL_FN_OFFSET: i32 = X86_GUEST_CALL_FN_OFFSET;

/// W^X executable memory holding a finalized lowered block. Maps RW, copies the
/// code in, then flips to RX. Drop normally unmaps it; x86-64 code running under
/// Rosetta retains an inaccessible virtual-address reservation to prevent stale
/// translated-code aliasing.
pub struct ExecMem {
    ptr: *mut u8,
    len: usize,
}

impl ExecMem {
    /// Map `code` into a fresh W^X region and make it executable.
    ///
    /// The mechanism is host-specific: x86-64 (and any non-aarch64 unix) map RW,
    /// copy, then `mprotect` to RX. Apple-Silicon macOS uses a `MAP_JIT` region
    /// with `pthread_jit_write_protect_np` toggling plus an explicit I-cache
    /// invalidate. Linux/aarch64 maps RW→RX and flushes via `__clear_cache`.
    pub fn new(code: &[u8]) -> Result<Self, ExecMemError> {
        if code.is_empty() {
            return Err(ExecMemError::Empty);
        }
        let len = (code.len() + 0xFFF) & !0xFFF;
        let ptr = Self::map_code(code, len)?;
        Ok(ExecMem { ptr, len })
    }

    /// Address range of the executable mapping, for async-signal-safe JIT
    /// crash diagnostics. The returned span includes page-alignment padding.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn mapping_bounds(&self) -> (*const u8, usize) {
        (self.ptr.cast_const(), self.len)
    }

    /// RW map → copy → `mprotect` RX. Used on x86-64 and any non-aarch64 Unix.
    #[cfg(not(target_arch = "aarch64"))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
        if unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            return Err(ExecMemError::Mprotect);
        }
        Ok(ptr)
    }

    /// Apple-Silicon macOS: a `MAP_JIT` RWX region. Writing it requires the
    /// calling thread to be in *write* mode (`pthread_jit_write_protect_np(0)`);
    /// after the copy we flip back to *execute* mode and invalidate the I-cache
    /// for the written range. The thread is left in execute mode, so even if a
    /// different thread later runs the block (`ExecMem` is `Send`/`Sync`) it sees
    /// executable pages. The toggle is thread-local; a thread that never wrote
    /// JIT memory is already in execute mode by default.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe {
            libc::pthread_jit_write_protect_np(0);
            core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
            libc::pthread_jit_write_protect_np(1);
            sys_icache_invalidate(ptr as *mut core::ffi::c_void, len);
        }
        Ok(ptr)
    }

    /// Linux/aarch64: RW map → copy → `mprotect` RX → `__clear_cache`.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn map_code(code: &[u8], len: usize) -> Result<*mut u8, ExecMemError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
        if unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            return Err(ExecMemError::Mprotect);
        }
        unsafe {
            __clear_cache(
                ptr as *mut core::ffi::c_char,
                ptr.add(len) as *mut core::ffi::c_char,
            )
        };
        Ok(ptr)
    }

    /// Execute the block at `entry_offset` (the lowerer's `LowerResult.entry_offset`),
    /// marshalling `regs` in and reading the result back out.
    ///
    /// # Safety
    /// The caller must guarantee that the code was produced by a trusted lowerer
    /// for an identity-register-mapped block that does not require a guest stack
    /// (RSP is not loaded — the block runs on the host stack).
    #[cfg(target_arch = "x86_64")]
    pub fn run(&self, entry_offset: usize, regs: &mut GuestRegs) {
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        if regs.vector_active == X86_VECTOR_STATE_YMM16 {
            unsafe {
                x86_ymm_trampoline::enter_native_ymm16(entry, regs as *mut GuestRegs);
            }
        } else {
            unsafe { rax_smir_enter_native(entry, regs as *mut GuestRegs) };
        }
    }

    /// Execute a state-backed AArch64-on-x86 lowered block.
    ///
    /// # Safety
    /// The mapped code must use the `extern "C" fn(*mut Aarch64GuestRegs)` ABI
    /// and preserve the host ABI. The AArch64 state-backed lowerer emits leaf
    /// functions using only caller-saved registers plus an RBP frame.
    pub fn run_aarch64(&self, entry_offset: usize, regs: &mut Aarch64GuestRegs) {
        type Entry = unsafe extern "C" fn(*mut Aarch64GuestRegs);
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        let entry: Entry = unsafe { core::mem::transmute(entry) };
        unsafe { entry(regs as *mut Aarch64GuestRegs) };
    }

    /// Execute a state-backed RISC-V-on-x86-64 lowered block.
    ///
    /// # Safety
    /// The mapped code must have been emitted for the
    /// `extern "sysv64" fn(*mut RiscVGuestRegs)` ABI and must preserve it.
    #[cfg(target_arch = "x86_64")]
    pub fn run_riscv(&self, entry_offset: usize, regs: &mut RiscVGuestRegs) {
        type Entry = unsafe extern "sysv64" fn(*mut RiscVGuestRegs);
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        let entry: Entry = unsafe { core::mem::transmute(entry) };
        unsafe { entry(regs as *mut RiscVGuestRegs) };
    }

    /// Execute a state-backed RISC-V-on-AArch64 lowered block.
    ///
    /// # Safety
    /// The mapped code must have been emitted for the
    /// `extern "C" fn(*mut RiscVGuestRegs)` AAPCS64 ABI and must preserve it.
    #[cfg(target_arch = "aarch64")]
    pub fn run_riscv(&self, entry_offset: usize, regs: &mut RiscVGuestRegs) {
        type Entry = unsafe extern "C" fn(*mut RiscVGuestRegs);
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        let entry: Entry = unsafe { core::mem::transmute(entry) };
        unsafe { entry(regs as *mut RiscVGuestRegs) };
    }

    /// Execute an identity-register-mapped AArch64 block on an AArch64 host.
    ///
    /// The block was lowered by `Aarch64Lowerer` under the 1:1 identity map
    /// (guest `Xn` ⇒ host `Xn`). [`rax_a64_enter_native`] marshals guest GPRs +
    /// NZCV from `regs` into the identical host registers, runs the block on the
    /// host stack, then writes the results back. Guest X18/X28/X30/SP are not
    /// mapped (reserved: platform / state-pointer / link / host-stack), so the
    /// block must not use them — enforced by the clobber gate.
    ///
    /// # Safety
    /// `entry_offset` must point at a block produced by a trusted AArch64
    /// identity lowerer that obeys the reserved-register contract above.
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch64_identity(&self, entry_offset: usize, regs: &mut Aarch64GuestRegs) {
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        unsafe { rax_a64_enter_native(entry, regs as *mut Aarch64GuestRegs) };
    }

    /// Execute an admitted register-only AArch32 region on an AArch64 host.
    ///
    /// The native block uses the same identity mapping as the AArch64 scalar
    /// trampoline, but every architectural value is narrowed to 32 bits at the
    /// ABI boundary.  [`is_aarch32_aarch64_native_clobber_safe_excluding`]
    /// guarantees that the block cannot observe AArch64-only registers, host
    /// SP, or the guest PC pipeline value.
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch32_identity(&self, entry_offset: usize, regs: &mut Aarch32GuestRegs) {
        let _ = self.run_aarch32_identity_until_exit(entry_offset, regs);
    }

    /// Execute an admitted register-only AArch32 control-flow region.
    ///
    /// This is the control-flow-aware form of [`Self::run_aarch32_identity`].
    /// It returns the guest PC recorded by a native exit. This compatibility
    /// form cannot distinguish an exit to guest address zero from an ordinary
    /// empty `Return`; use [`Self::run_aarch32_identity_exit`] when that
    /// distinction matters. The function must be lowered with matching exit
    /// metadata and modes.
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch32_identity_until_exit(
        &self,
        entry_offset: usize,
        regs: &mut Aarch32GuestRegs,
    ) -> u64 {
        self.run_aarch32_identity_exit(entry_offset, regs).pc
    }

    /// Execute an admitted AArch32 control-flow region and return an
    /// unambiguous exit record. Unlike [`Self::run_aarch32_identity_until_exit`],
    /// this distinguishes an exit to address zero from an ordinary return.
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch32_identity_exit(
        &self,
        entry_offset: usize,
        regs: &mut Aarch32GuestRegs,
    ) -> Aarch32NativeExit {
        self.run_aarch32_identity_configured(entry_offset, regs, None)
    }

    /// Execute an admitted AArch32 region with MMU memory-helper call-outs.
    ///
    /// Returns the guest PC recorded by a helper fault or native frontier exit;
    /// zero means that a self-contained region returned without recording an
    /// exit. The caller must lower the region with memory helpers enabled and
    /// 32-bit helper-address arithmetic.
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch32_identity_with_mem(
        &self,
        entry_offset: usize,
        regs: &mut Aarch32GuestRegs,
        helpers: Aarch32MemHelpers,
    ) -> u64 {
        self.run_aarch32_identity_configured(entry_offset, regs, Some(helpers))
            .pc
    }

    #[cfg(target_arch = "aarch64")]
    fn run_aarch32_identity_configured(
        &self,
        entry_offset: usize,
        regs: &mut Aarch32GuestRegs,
        helpers: Option<Aarch32MemHelpers>,
    ) -> Aarch32NativeExit {
        const NZCV: u32 = 0xf000_0000;
        const CPSR_T: u32 = 1 << 5;

        let mut state = Aarch64GuestRegs::default();
        for (dst, src) in state.x[..16].iter_mut().zip(regs.r) {
            *dst = u64::from(src);
        }
        state.nzcv = u64::from(regs.cpsr & NZCV);
        if let Some(helpers) = helpers {
            state.ctx = helpers.ctx;
            state.load_fn = helpers.load_fn;
            state.store_fn = helpers.store_fn;
        }
        self.run_aarch64_identity(entry_offset, &mut state);
        for (dst, src) in regs.r.iter_mut().zip(state.x[..16].iter()) {
            *dst = *src as u32;
        }
        regs.cpsr = (regs.cpsr & !NZCV) | (state.nzcv as u32 & NZCV);
        if state.exit_flags & Aarch64GuestRegs::EXIT_AARCH32_T_VALID != 0 {
            regs.cpsr &= !CPSR_T;
            if state.exit_flags & Aarch64GuestRegs::EXIT_AARCH32_T != 0 {
                regs.cpsr |= CPSR_T;
            }
        }
        Aarch32NativeExit {
            exited: state.exit_flags & Aarch64GuestRegs::EXIT_VALID != 0,
            pc: state.pc,
        }
    }

    /// As [`Self::run_aarch64_identity`] but for a region that uses scalar FP /
    /// SIMD: additionally marshals V0-V31 + FPCR/FPSR through the FP trampoline.
    /// Used only for regions whose ops touch V registers (the integer path keeps
    /// the cheaper GPR-only trampoline).
    ///
    /// # Safety
    /// As [`Self::run_aarch64_identity`].
    #[cfg(target_arch = "aarch64")]
    pub fn run_aarch64_identity_fp(&self, entry_offset: usize, regs: &mut Aarch64GuestRegs) {
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        unsafe { rax_a64_enter_native_fp(entry, regs as *mut Aarch64GuestRegs) };
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        if running_under_rosetta() {
            // Rosetta can retain a translated block after munmap and reuse it
            // if another thread immediately receives the same executable
            // virtual address. Keep the address reserved for this process while
            // releasing its physical pages, which prevents stale-code aliasing.
            unsafe {
                libc::mprotect(self.ptr as *mut libc::c_void, self.len, libc::PROT_NONE);
                libc::madvise(self.ptr as *mut libc::c_void, self.len, libc::MADV_DONTNEED);
            }
            return;
        }
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

// SAFETY: an ExecMem owns a private W^X mapping of immutable native code. After
// construction the bytes never change, and execution only reads them; the
// owning vcpu is the sole accessor. Sending the mapping to another thread (when
// a vcpu migrates) or sharing &ExecMem for read-only execution is therefore
// sound. The raw pointer alone makes ExecMem !Send/!Sync by default.
unsafe impl Send for ExecMem {}
unsafe impl Sync for ExecMem {}

/// Errors mapping/executing a lowered block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMemError {
    /// Empty code buffer.
    Empty,
    /// `mmap` failed.
    Mmap,
    /// `mprotect` to RX failed.
    Mprotect,
}

impl core::fmt::Display for ExecMemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecMemError::Empty => write!(f, "empty code buffer"),
            ExecMemError::Mmap => write!(f, "mmap failed"),
            ExecMemError::Mprotect => write!(f, "mprotect to RX failed"),
        }
    }
}

impl std::error::Error for ExecMemError {}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    // Hand-assembled `mov eax, 0x2a ; ret` — proves ExecMem (W^X map) and the
    // enter_native trampoline marshal a result back out, independent of the
    // lowerer. The lowerer-driven end-to-end paths live in
    // tests/suites/differential/x86_64/fuzz.rs.
    #[test]
    fn exec_mem_runs_raw_block() {
        let code = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        regs.rflags = 0x2;
        mem.run(0, &mut regs);
        assert_eq!(regs.gpr[0], 0x2a, "RAX should be 0x2a");
    }

    // RAX = RBX + RCX, exercising guest-GPR marshal IN as well as OUT.
    //   lea eax,[rbx+rcx] won't preserve 64-bit; use: mov rax,rbx; add rax,rcx; ret
    #[test]
    fn exec_mem_marshals_inputs() {
        // 48 89 D8        mov rax, rbx
        // 48 01 C8        add rax, rcx
        // C3              ret
        let code = [0x48, 0x89, 0xD8, 0x48, 0x01, 0xC8, 0xC3];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        regs.gpr[3] = 40; // RBX
        regs.gpr[1] = 2; // RCX
        regs.rflags = 0x2;
        mem.run(0, &mut regs);
        assert_eq!(regs.gpr[0], 42, "RAX should be RBX+RCX");
    }

    #[test]
    fn x86_entry_trampoline_merges_only_status_flags_into_guest_rflags() {
        // mov eax,0x7fffffff; add eax,1; ret. The ADD deterministically leaves
        // PF=AF=SF=OF=1 and CF=ZF=0. Host IF is always set in userspace and
        // cannot be cleared by POPFQ at CPL3, so exporting raw host RFLAGS
        // would incorrectly inject IF into the guest image.
        let code = [
            0xB8, 0xFF, 0xFF, 0xFF, 0x7F, // mov eax,0x7fffffff
            0x83, 0xC0, 0x01, // add eax,1
            0xC3, // ret
        ];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        const STATUS: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
        const RESULT_STATUS: u64 = (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11);
        const AC: u64 = 1 << 18;
        let initial = 0x2 | (1 << 0) | (1 << 6) | AC | (1 << 21);
        let mut regs = GuestRegs {
            rflags: initial,
            ..GuestRegs::default()
        };

        mem.run(0, &mut regs);

        assert_eq!(regs.rflags, (initial & !(STATUS | AC)) | RESULT_STATUS);
    }

    #[test]
    fn x86_entry_trampoline_never_imports_guest_tf_nt_or_ac() {
        // Capture the actual host RFLAGS visible at native-block entry into the
        // otherwise-unused tsc_fn slot. The block uses the standard lowerer
        // prologue so [rbp+24] resolves the trampoline's GuestRegs pointer.
        let mut code = vec![
            0x55, // push rbp
            0x48,
            0x89,
            0xE5, // mov rbp,rsp
            0x50, // push rax
            0x9C, // pushfq
            0x59, // pop rcx
            0x48,
            0x8B,
            0x45,
            X86_STATE_PTR_AT_RBP as u8, // mov rax,[rbp+24]
            0x48,
            0x89,
            0x88, // mov [rax+disp32],rcx
        ];
        code.extend_from_slice(&(X86_GUEST_TSC_FN_OFFSET as u32).to_le_bytes());
        code.extend_from_slice(&[
            0x58, // pop rax
            0x48, 0x89, 0xEC, // mov rsp,rbp
            0x5D, // pop rbp
            0xC3, // ret
        ]);

        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        const TF: u64 = 1 << 8;
        const DF: u64 = 1 << 10;
        const NT: u64 = 1 << 14;
        const AC: u64 = 1 << 18;
        regs.rflags = 0x2 | TF | DF | NT | AC;
        regs.ac_flag = 1;
        mem.run(0, &mut regs);

        assert_eq!(regs.tsc_fn & (TF | NT | AC), 0);
        assert_ne!(
            regs.tsc_fn & DF,
            0,
            "guest DF remains a native semantic input"
        );
        assert_eq!(regs.ac_flag, 1, "guest AC shadow must survive host masking");
    }

    // General-exit stub: a block (with the lowerer's `push rbp; mov rbp,rsp`
    // prologue) records its resume PC into exit_pc by loading the state pointer
    // from the trampoline frame into a push/pop-saved
    // scratch — no reserved guest register, runs under the existing trampoline.
    #[test]
    fn exec_mem_exit_pc_via_stub() {
        let mut code = vec![
            0x55, // push rbp
            0x48,
            0x89,
            0xE5, // mov rbp, rsp
            0x50, // push rax (scratch)
            0x48,
            0x8B,
            0x45,
            X86_STATE_PTR_AT_RBP as u8, // mov rax, [rbp+state_ptr]
            0xC7,
            0x80,
        ];
        code.extend_from_slice(&(X86_GUEST_EXIT_PC_OFFSET as u32).to_le_bytes());
        code.extend_from_slice(&0x1234_abcdu32.to_le_bytes());
        code.extend_from_slice(&[0xC7, 0x80]);
        code.extend_from_slice(&((X86_GUEST_EXIT_PC_OFFSET + 4) as u32).to_le_bytes());
        code.extend_from_slice(&0u32.to_le_bytes());
        code.extend_from_slice(&[
            0x58, // pop rax
            0x48, 0x89, 0xEC, // mov rsp, rbp
            0x5D, // pop rbp
            0xC3, // ret
        ]);
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        regs.gpr[0] = 0xCAFE; // guest RAX must pass through (scratch restored)
        regs.rflags = 0x2;
        mem.run(0, &mut regs);
        assert_eq!(
            regs.exit_pc, 0x1234_abcd,
            "exit_pc recorded via frame state ptr"
        );
        assert_eq!(regs.gpr[0], 0xCAFE, "guest RAX restored after scratch use");
    }

    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{
        ArchReg, Condition, FunctionId, OpWidth, SrcOperand, VReg, X86Reg,
    };
    use crate::smir::ir::{FunctionBuilder, Terminator, TrapKind};

    fn rax() -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Rax))
    }
    fn rcx() -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::Rcx))
    }

    #[test]
    fn clobber_gate_passes_pure_arch_block() {
        let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
        b.push_op(
            0x1000,
            OpKind::Add {
                dst: rax(),
                src1: rax(),
                src2: SrcOperand::Reg(rcx()),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        b.set_terminator(Terminator::Return { values: vec![] });
        assert!(is_native_clobber_safe(&b.finish()));
    }

    #[test]
    fn clobber_gate_rejects_virtual_temp() {
        let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
        let tmp = b.alloc_vreg(); // VReg::Virtual
        b.push_op(
            0x1000,
            OpKind::Add {
                dst: tmp, // writes a virtual temporary -> would clobber a guest GPR
                src1: rax(),
                src2: SrcOperand::Reg(rcx()),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        b.set_terminator(Terminator::Return { values: vec![] });
        assert!(!is_native_clobber_safe(&b.finish()));
    }

    #[test]
    fn clobber_gate_excludes_exit_blocks() {
        // entry: add rax,rcx (arch) → Branch to exit_blk
        // exit_blk: writes a VIRTUAL temp, then Trap (a frontier the JIT skips).
        let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
        let exit_blk = b.create_block(0x2000);
        b.push_op(
            0x1000,
            OpKind::Add {
                dst: rax(),
                src1: rax(),
                src2: SrcOperand::Reg(rcx()),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        b.set_terminator(Terminator::Branch { target: exit_blk });
        b.switch_to_block(exit_blk);
        let tmp = b.alloc_vreg();
        b.push_op(
            0x2000,
            OpKind::Add {
                dst: tmp, // virtual temp — only safe because this block is skipped
                src1: rax(),
                src2: SrcOperand::Reg(rcx()),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        b.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });
        let func = b.finish();

        assert!(
            !is_native_clobber_safe(&func),
            "exit block's virtual write trips the strict gate"
        );
        let mut exits = std::collections::HashMap::new();
        exits.insert(exit_blk, 0x2000u64);
        assert!(
            is_native_clobber_safe_excluding(&func, &exits, false),
            "excluding the (skipped) exit block, the executed region is safe"
        );
    }

    #[test]
    fn clobber_gate_exempts_folded_testcondition() {
        let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
        let t_blk = b.create_block(0x2000);
        let f_blk = b.create_block(0x3000);
        let cond = b.alloc_vreg();
        b.push_op(
            0x1000,
            OpKind::Sub {
                dst: rcx(),
                src1: rcx(),
                src2: SrcOperand::imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );
        // Trailing TestCondition feeding the CondBranch: lowerer folds it, never
        // materializing `cond`, so the gate must treat the block as safe.
        b.push_op(
            0x1003,
            OpKind::TestCondition {
                dst: cond,
                cond: Condition::Ne,
            },
        );
        b.set_terminator(Terminator::CondBranch {
            cond,
            true_target: t_blk,
            false_target: f_blk,
        });
        b.switch_to_block(t_blk);
        b.set_terminator(Terminator::Return { values: vec![] });
        b.switch_to_block(f_blk);
        b.set_terminator(Terminator::Return { values: vec![] });
        assert!(is_native_clobber_safe(&b.finish()));
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_aarch64 {
    use super::*;

    // movz x0, #42 ; ret  → proves the MAP_JIT W^X mapping executes and the
    // identity trampoline marshals a result register back out, independent of
    // the lowerer. This is the AArch64 analogue of `exec_mem_runs_raw_block`.
    #[test]
    fn exec_mem_runs_raw_block_aarch64() {
        // d2800540 movz x0, #42 ; d65f03c0 ret
        let code: [u8; 8] = [0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        mem.run_aarch64_identity(0, &mut regs);
        assert_eq!(regs.x[0], 42, "X0 should be 42");
    }

    #[test]
    fn aarch32_exit_result_distinguishes_ordinary_return() {
        let code = 0xd65f_03c0u32.to_le_bytes(); // ret
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch32GuestRegs::default();
        let result = mem.run_aarch32_identity_exit(0, &mut regs);
        assert_eq!(
            result,
            Aarch32NativeExit {
                exited: false,
                pc: 0
            }
        );
    }

    // add x0, x1, x2 ; ret  → guest GPR marshal IN as well as OUT.
    #[test]
    fn exec_mem_marshals_inputs_aarch64() {
        // 8b020020 add x0, x1, x2 ; d65f03c0 ret
        let code: [u8; 8] = [0x20, 0x00, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.x[1] = 40;
        regs.x[2] = 2;
        mem.run_aarch64_identity(0, &mut regs);
        assert_eq!(regs.x[0], 42, "X0 should be X1+X2");
    }

    // Exercise the high callee-saved guest registers (x19..x29) round-trip,
    // since the trampoline loads/stores those via single ldr/str (not the ldp
    // pairs used for x0..x17).
    #[test]
    fn exec_mem_high_regs_roundtrip_aarch64() {
        // 8b150293 add x19, x20, x21 ; aa1303e0 mov x0, x19 ; d65f03c0 ret
        let code: [u8; 12] = [
            0x93, 0x02, 0x15, 0x8b, 0xe0, 0x03, 0x13, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.x[20] = 100;
        regs.x[21] = 23;
        mem.run_aarch64_identity(0, &mut regs);
        assert_eq!(regs.x[19], 123, "X19 = X20 + X21");
        assert_eq!(regs.x[0], 123, "X0 = X19");
    }

    // subs x0, x1, x1 ; ret  → NZCV marshals out (5-5=0 sets Z and C).
    #[test]
    fn exec_mem_nzcv_roundtrip_aarch64() {
        // eb010020 subs x0, x1, x1 ; d65f03c0 ret
        let code: [u8; 8] = [0x20, 0x00, 0x01, 0xeb, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.x[1] = 5;
        mem.run_aarch64_identity(0, &mut regs);
        assert_eq!(regs.x[0], 0, "5 - 5 = 0");
        assert_ne!(regs.nzcv & (1 << 30), 0, "Z (bit 30) set on zero result");
        assert_ne!(regs.nzcv & (1 << 29), 0, "C (bit 29) set: no borrow");
        assert_eq!(regs.nzcv & (1 << 31), 0, "N (bit 31) clear");
    }

    // FP trampoline: V-register + FPCR/FPSR marshaling. fadd d0,d1,d2 reads the
    // low 64 bits (f64) of V1,V2 and writes V0; this proves run_aarch64_identity_fp
    // marshals the SIMD/FP register file in and out.
    #[test]
    fn exec_mem_fp_marshals_v_regs_aarch64() {
        // 1e622820 fadd d0, d1, d2 ; d65f03c0 ret
        let code: [u8; 8] = [0x20, 0x28, 0x62, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.v[2] = (2.0_f64).to_bits(); // V1 low (d1)
        regs.v[4] = (3.0_f64).to_bits(); // V2 low (d2)
        mem.run_aarch64_identity_fp(0, &mut regs);
        assert_eq!(f64::from_bits(regs.v[0]), 5.0, "V0 = V1 + V2 (f64)");
    }

    fn read_host_fpcr() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, fpcr",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    #[test]
    fn exec_mem_fp_trampoline_roundtrips_fpcr_aarch64() {
        // d51b4400 msr fpcr, x0 ; d65f03c0 ret
        let code: [u8; 8] = [0x00, 0x44, 0x1b, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.x[0] = 0x00c0_0000;
        let host_fpcr = read_host_fpcr();

        mem.run_aarch64_identity_fp(0, &mut regs);

        assert_eq!(regs.fpcr & 0xffff_ffff, 0x00c0_0000);
        assert_eq!(read_host_fpcr(), host_fpcr, "host FPCR must be restored");
    }

    // The FP trampoline must still marshal GPRs/NZCV exactly like the scalar one.
    #[test]
    fn exec_mem_fp_trampoline_preserves_gprs_aarch64() {
        // 8b020020 add x0, x1, x2 ; d65f03c0 ret
        let code: [u8; 8] = [0x20, 0x00, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.x[1] = 40;
        regs.x[2] = 2;
        regs.x[25] = 0x1234_5678; // callee-saved guest reg must round-trip
        mem.run_aarch64_identity_fp(0, &mut regs);
        assert_eq!(regs.x[0], 42);
        assert_eq!(regs.x[25], 0x1234_5678);
    }

    // NZCV marshals IN: cset x0 reads the Z flag we seed in the struct.
    // cseteq x0  ==  csinc x0, xzr, xzr, ne  →  x0 = (Z==1) ? 1 : 0.
    #[test]
    fn exec_mem_nzcv_marshals_in_aarch64() {
        // 9a9f17e0 cset x0, eq ; d65f03c0 ret
        let code: [u8; 8] = [0xe0, 0x17, 0x9f, 0x9a, 0xc0, 0x03, 0x5f, 0xd6];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = Aarch64GuestRegs::default();
        regs.nzcv = 1 << 30; // Z set
        mem.run_aarch64_identity(0, &mut regs);
        assert_eq!(regs.x[0], 1, "cset eq reads the seeded Z flag");
    }
}
