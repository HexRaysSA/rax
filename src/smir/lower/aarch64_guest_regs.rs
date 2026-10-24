//! Stable-prefix AArch64 native register-state ABI.

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
    /// Opaque scoped context for state-backed PAuth/instruction helpers.
    pub pauth_context: u64,
    /// `extern "C" fn(state, phase, raw, pc, features) -> ok`. Zero declines
    /// before execution; the callback records exact errors in its context.
    pub pauth_fn: u64,
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
            pauth_context: 0,
            pauth_fn: 0,
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

    pub const PAUTH_CONTEXT_OFFSET: i32 = Self::X86_TBM_MODE_VALID_OFFSET + 8;
    pub const PAUTH_FN_OFFSET: i32 = Self::PAUTH_CONTEXT_OFFSET + 8;

    /// A native exit, rather than an ordinary `Return`, recorded `pc`.
    pub const EXIT_VALID: u64 = 1 << 0;
    /// The AArch32 exit selected Thumb state.
    pub const EXIT_AARCH32_T: u64 = 1 << 1;
    /// [`Self::EXIT_AARCH32_T`] contains a CPSR.T update.
    pub const EXIT_AARCH32_T_VALID: u64 = 1 << 2;
}
