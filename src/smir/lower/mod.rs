//! SMIR lowering - code generation from SMIR to native machine code.
//!
//! This module provides the infrastructure for lowering SMIR IR to native
//! machine code for various target architectures.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │   SmirFunction  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Register Alloc  │  (VReg → PhysReg mapping)
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Lowering     │  (SMIR Op → Machine Instructions)
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   CodeBuffer    │  (Raw machine code bytes)
//! └─────────────────┘
//! ```

pub mod aarch64;
pub mod cross;
pub mod regalloc;
/// Native execution runtime for lowered blocks (the JIT executor). Present with
/// the `smir-jit` feature on x86-64 and aarch64 hosts.
#[cfg(feature = "smir-jit")]
pub mod runtime;
#[cfg(test)]
mod validation;
pub mod x86_64;

// Compatibility aliases for the former flat lowering layout.
pub use cross::aarch64_guest_to_x86_64_host as aarch64_x86;
pub use x86_64::avx10;

use std::collections::HashMap;

use crate::smir::ir::SmirFunction;
use crate::smir::ir::types::{BlockId, GuestAddr};

/// Number of x86-64 guest GPR slots in the native JIT register file. APX adds
/// R16-R31, which are state-backed because the host has no physical EGPRs.
/// Architectural bit-offset term folded into a JIT memory-helper address.
///
/// `BT`/`BTS`/`BTR`/`BTC` with a register bit offset address a bit *string*:
/// the accessed element is
/// `base + ((sign_extend(index) >> shift_right) << shift_left)`, which no
/// [`types::Address`] can express.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86JitBitOffsetTerm {
    /// Architectural GPR encoding holding the bit offset.
    pub index: u8,
    /// Operand width the offset is sign-extended from.
    pub from_width: crate::smir::ir::types::OpWidth,
    /// `log2(bits per element)`: 4, 5 or 6.
    pub shift_right: u8,
    /// `log2(bytes per element)`: 1, 2 or 3.
    pub shift_left: u8,
}

pub const X86_GUEST_GPR_COUNT: usize = 32;
/// Byte offset of `GuestRegs.rflags`.
pub const X86_GUEST_RFLAGS_OFFSET: i32 = (X86_GUEST_GPR_COUNT as i32) * 8;
/// Byte offset of `GuestRegs.exit_pc`.
pub const X86_GUEST_EXIT_PC_OFFSET: i32 = X86_GUEST_RFLAGS_OFFSET + 8;
/// Byte offset of `GuestRegs.ctx`.
pub const X86_GUEST_CTX_OFFSET: i32 = X86_GUEST_EXIT_PC_OFFSET + 8;
/// Byte offset of `GuestRegs.load_fn`.
pub const X86_GUEST_LOAD_FN_OFFSET: i32 = X86_GUEST_CTX_OFFSET + 8;
/// Byte offset of `GuestRegs.store_fn`.
pub const X86_GUEST_STORE_FN_OFFSET: i32 = X86_GUEST_LOAD_FN_OFFSET + 8;
/// Byte offset of `GuestRegs.fs_base`.
pub const X86_GUEST_FS_BASE_OFFSET: i32 = X86_GUEST_STORE_FN_OFFSET + 8;
/// Byte offset of `GuestRegs.gs_base`.
pub const X86_GUEST_GS_BASE_OFFSET: i32 = X86_GUEST_FS_BASE_OFFSET + 8;
/// Byte offset of `GuestRegs.call_fn`.
pub const X86_GUEST_CALL_FN_OFFSET: i32 = X86_GUEST_GS_BASE_OFFSET + 8;
/// Byte offset of `GuestRegs.zmm` (32 architectural 512-bit vector registers).
pub const X86_GUEST_ZMM_OFFSET: i32 = X86_GUEST_CALL_FN_OFFSET + 8;
/// Byte offset of `GuestRegs.k` (eight 64-bit AVX-512 opmask registers).
pub const X86_GUEST_K_OFFSET: i32 = X86_GUEST_ZMM_OFFSET + 32 * 64;
/// Byte offset of `GuestRegs.vector_active`.
pub const X86_GUEST_VECTOR_ACTIVE_OFFSET: i32 = X86_GUEST_K_OFFSET + 8 * 8;
/// Byte offset of the guest architectural MXCSR value.
pub const X86_GUEST_MXCSR_OFFSET: i32 = X86_GUEST_VECTOR_ACTIVE_OFFSET + 8;
/// Byte offset of the host MXCSR value saved by the native trampoline.
pub const X86_HOST_MXCSR_OFFSET: i32 = X86_GUEST_MXCSR_OFFSET + 4;
/// Byte offset of the guest IA32_TSC_AUX value consumed by RDPID.
pub const X86_GUEST_TSC_AUX_OFFSET: i32 = X86_HOST_MXCSR_OFFSET + 4;
/// Byte offset of the guest PKRU value consumed by RDPKRU/WRPKRU.
pub const X86_GUEST_PKRU_OFFSET: i32 = X86_GUEST_TSC_AUX_OFFSET + 4;
/// Byte offset of the guest XCR0 value consumed by XGETBV.
/// `tsc_aux` and `pkru` are adjacent 32-bit fields, preserving u64 alignment.
pub const X86_GUEST_XCR0_OFFSET: i32 = X86_GUEST_TSC_AUX_OFFSET + 8;
/// Byte offset of the guest XGETBV(ECX=1) XINUSE bitmap.
pub const X86_GUEST_XGETBV1_OFFSET: i32 = X86_GUEST_XCR0_OFFSET + 8;
/// Byte offset of guest CR4, whose OSXSAVE bit gates XGETBV.
pub const X86_GUEST_CR4_OFFSET: i32 = X86_GUEST_XGETBV1_OFFSET + 8;
/// Byte offset of guest CR0, whose PE bit participates in XSETBV privilege checks.
pub const X86_GUEST_CR0_OFFSET: i32 = X86_GUEST_CR4_OFFSET + 8;
/// Byte offset of the effective current privilege level used by guarded system
/// instructions. Virtual-8086 mode is represented as CPL3.
pub const X86_GUEST_CPL_OFFSET: i32 = X86_GUEST_CR0_OFFSET + 8;
/// Byte offset of the emulator's APX enable policy used to validate XCR0.APX_F.
pub const X86_GUEST_APX_ENABLED_OFFSET: i32 = X86_GUEST_CPL_OFFSET + 8;
/// Byte offset of the helper-backed vector-load function pointer.
pub const X86_GUEST_VEC_LOAD_FN_OFFSET: i32 = X86_GUEST_APX_ENABLED_OFFSET + 8;
/// Byte offset of the helper-backed vector-store function pointer.
pub const X86_GUEST_VEC_STORE_FN_OFFSET: i32 = X86_GUEST_VEC_LOAD_FN_OFFSET + 8;
/// Byte offset of the helper-backed APX POP2 function pointer.
pub const X86_GUEST_PAIR_LOAD_FN_OFFSET: i32 = X86_GUEST_VEC_STORE_FN_OFFSET + 8;
/// Byte offset of the helper-backed APX PUSH2 function pointer.
pub const X86_GUEST_PAIR_STORE_FN_OFFSET: i32 = X86_GUEST_PAIR_LOAD_FN_OFFSET + 8;
/// Byte offset of the eight architectural MMX registers.
///
/// This state is appended after the established helper ABI so the hard-coded
/// GPR/ZMM/K/MXCSR trampoline offsets remain stable.
pub const X86_GUEST_MM_OFFSET: i32 = X86_GUEST_PAIR_STORE_FN_OFFSET + 8;
/// Byte offset of the native-MMX marshalling discriminator.
pub const X86_GUEST_MMX_ACTIVE_OFFSET: i32 = X86_GUEST_MM_OFFSET + 8 * 8;
/// Byte offset of the guest architectural x87 tag word.
///
/// MMX instructions set this to zero at their precise SMIR `EnterMmx` point;
/// the host `EMMS` executed by the trampoline is host-state cleanup only.
pub const X86_GUEST_X87_TAG_WORD_OFFSET: i32 = X86_GUEST_MMX_ACTIVE_OFFSET + 8;
/// Byte offset of the deterministic guest-CPUID evaluator function pointer.
pub const X86_GUEST_CPUID_FN_OFFSET: i32 = X86_GUEST_X87_TAG_WORD_OFFSET + 8;
/// Byte offset of the guest Xeon Phi AVX-512 enumeration policy.
pub const X86_GUEST_CPUID_XEON_PHI_AVX512_OFFSET: i32 = X86_GUEST_CPUID_FN_OFFSET + 8;
/// Byte offset of the guest AVX512_VP2INTERSECT enumeration policy.
pub const X86_GUEST_CPUID_VP2INTERSECT_OFFSET: i32 = X86_GUEST_CPUID_XEON_PHI_AVX512_OFFSET + 8;
/// Byte offset of the guest SSE4A enumeration policy.
pub const X86_GUEST_CPUID_SSE4A_OFFSET: i32 = X86_GUEST_CPUID_VP2INTERSECT_OFFSET + 8;
/// Byte offset of the guest IA32_KERNEL_GS_BASE value used by SWAPGS.
pub const X86_GUEST_KERNEL_GS_BASE_OFFSET: i32 = X86_GUEST_CPUID_SSE4A_OFFSET + 8;
/// Byte offset of the emulated guest timestamp-counter helper pointer.
pub const X86_GUEST_TSC_FN_OFFSET: i32 = X86_GUEST_KERNEL_GS_BASE_OFFSET + 8;
/// Byte offset of the guest RFLAGS.AC shadow. Native execution must keep host
/// AC clear, so this field is authoritative for the guest bit.
pub const X86_GUEST_AC_FLAG_OFFSET: i32 = X86_GUEST_TSC_FN_OFFSET + 8;
/// Byte offset of guest CR2. Newly modeled control-register state is appended
/// so every established helper/trampoline field retains its existing offset.
pub const X86_GUEST_CR2_OFFSET: i32 = X86_GUEST_AC_FLAG_OFFSET + 8;
/// Byte offset of guest CR3.
pub const X86_GUEST_CR3_OFFSET: i32 = X86_GUEST_CR2_OFFSET + 8;
/// Byte offset of guest CR8.
pub const X86_GUEST_CR8_OFFSET: i32 = X86_GUEST_CR3_OFFSET + 8;
/// Byte offset of guest DR0. Debug-register state is appended so every
/// established helper/trampoline field retains its existing offset.
pub const X86_GUEST_DR0_OFFSET: i32 = X86_GUEST_CR8_OFFSET + 8;
/// Byte offset of guest DR1.
pub const X86_GUEST_DR1_OFFSET: i32 = X86_GUEST_DR0_OFFSET + 8;
/// Byte offset of guest DR2.
pub const X86_GUEST_DR2_OFFSET: i32 = X86_GUEST_DR1_OFFSET + 8;
/// Byte offset of guest DR3.
pub const X86_GUEST_DR3_OFFSET: i32 = X86_GUEST_DR2_OFFSET + 8;
/// Byte offset of guest DR6.
pub const X86_GUEST_DR6_OFFSET: i32 = X86_GUEST_DR3_OFFSET + 8;
/// Byte offset of guest DR7.
pub const X86_GUEST_DR7_OFFSET: i32 = X86_GUEST_DR6_OFFSET + 8;
/// Byte offset of guest IA32_EFER. Appended to preserve every established
/// native helper and trampoline offset.
pub const X86_GUEST_EFER_OFFSET: i32 = X86_GUEST_DR7_OFFSET + 8;
/// Byte offset of the current code-segment L-bit snapshot.
pub const X86_GUEST_CS_L_OFFSET: i32 = X86_GUEST_EFER_OFFSET + 8;
/// Byte offset of the current task-register descriptor type.
pub const X86_GUEST_TR_TYPE_OFFSET: i32 = X86_GUEST_CS_L_OFFSET + 8;
/// Byte offset of the helper-backed MOV-to-control-register function pointer.
pub const X86_GUEST_CONTROL_WRITE_FN_OFFSET: i32 = X86_GUEST_TR_TYPE_OFFSET + 8;
/// Byte offset of the helper-backed RDMSR/WRMSR function pointer.
pub const X86_GUEST_MSR_FN_OFFSET: i32 = X86_GUEST_CONTROL_WRITE_FN_OFFSET + 8;
/// Byte offset of IA32_TSC_ADJUST.
pub const X86_GUEST_TSC_ADJUST_OFFSET: i32 = X86_GUEST_MSR_FN_OFFSET + 8;
/// Byte offsets of system-call and SYSENTER MSR state.
pub const X86_GUEST_STAR_OFFSET: i32 = X86_GUEST_TSC_ADJUST_OFFSET + 8;
pub const X86_GUEST_LSTAR_OFFSET: i32 = X86_GUEST_STAR_OFFSET + 8;
pub const X86_GUEST_CSTAR_OFFSET: i32 = X86_GUEST_LSTAR_OFFSET + 8;
pub const X86_GUEST_FMASK_OFFSET: i32 = X86_GUEST_CSTAR_OFFSET + 8;
pub const X86_GUEST_SYSENTER_CS_OFFSET: i32 = X86_GUEST_FMASK_OFFSET + 8;
pub const X86_GUEST_SYSENTER_ESP_OFFSET: i32 = X86_GUEST_SYSENTER_CS_OFFSET + 8;
pub const X86_GUEST_SYSENTER_EIP_OFFSET: i32 = X86_GUEST_SYSENTER_ESP_OFFSET + 8;
/// Byte offset of the helper-backed deterministic RDPMC evaluator. Appended so
/// every pre-existing native helper/state field retains its established ABI.
pub const X86_GUEST_PMC_FN_OFFSET: i32 = X86_GUEST_SYSENTER_EIP_OFFSET + 8;
/// Byte offset of the helper-backed SGDT/SIDT store function. Appended so all
/// pre-existing native helper/state fields retain their established ABI.
pub const X86_GUEST_DESCRIPTOR_STORE_FN_OFFSET: i32 = X86_GUEST_PMC_FN_OFFSET + 8;
/// Byte offset of the helper-backed LGDT/LIDT load function. Appended so all
/// pre-existing native helper/state fields retain their established ABI.
pub const X86_GUEST_DESCRIPTOR_LOAD_FN_OFFSET: i32 = X86_GUEST_DESCRIPTOR_STORE_FN_OFFSET + 8;
/// Byte offset of the helper-backed system/segment-selector reader. Appended so
/// all pre-existing native helper/state fields retain their established ABI.
pub const X86_GUEST_SYSTEM_SELECTOR_FN_OFFSET: i32 = X86_GUEST_DESCRIPTOR_LOAD_FN_OFFSET + 8;
/// Byte offset of the helper-backed LLDT/LTR, MOV-Sreg, and POP-FS/GS selector
/// loader. Appended so all pre-existing native helper/state fields retain their
/// established ABI.
pub const X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET: i32 = X86_GUEST_SYSTEM_SELECTOR_FN_OFFSET + 8;
/// Offset of [`runtime::GuestRegs::far_jump_fn`]. Appended to keep all prior
/// helper ABI offsets stable.
pub const X86_GUEST_FAR_JUMP_FN_OFFSET: i32 = X86_GUEST_SYSTEM_SELECTOR_LOAD_FN_OFFSET + 8;
/// Offset of [`runtime::GuestRegs::far_call_fn`]. Appended to preserve every
/// pre-existing helper ABI offset.
pub const X86_GUEST_FAR_CALL_FN_OFFSET: i32 = X86_GUEST_FAR_JUMP_FN_OFFSET + 8;
/// Offset of [`runtime::GuestRegs::far_return_fn`]. Appended to preserve every
/// pre-existing helper ABI offset.
pub const X86_GUEST_FAR_RETURN_FN_OFFSET: i32 = X86_GUEST_FAR_CALL_FN_OFFSET + 8;
/// Offset of [`runtime::GuestRegs::interrupt_flags`]. The shadow carries guest
/// IF/IOPL/VM/VIF/VIP outside host RFLAGS and is appended to preserve every
/// pre-existing helper ABI offset.
pub const X86_GUEST_INTERRUPT_FLAGS_OFFSET: i32 = X86_GUEST_FAR_RETURN_FN_OFFSET + 8;
/// Offset of the helper-backed CLI evaluator function pointer.
pub const X86_GUEST_CLI_FN_OFFSET: i32 = X86_GUEST_INTERRUPT_FLAGS_OFFSET + 8;
/// Offset of [`runtime::GuestRegs::interrupt_inhibit`]. The value is zero or
/// one and carries the emulator-private STI/MOV-SS maskable-interrupt shadow
/// across a native handoff.
pub const X86_GUEST_INTERRUPT_INHIBIT_OFFSET: i32 = X86_GUEST_CLI_FN_OFFSET + 8;
/// Offset of the helper-backed STI evaluator function pointer.
pub const X86_GUEST_STI_FN_OFFSET: i32 = X86_GUEST_INTERRUPT_INHIBIT_OFFSET + 8;
/// Offset of the append-only INVLPG helper pointer.
pub const X86_GUEST_INVLPG_FN_OFFSET: i32 = X86_GUEST_STI_FN_OFFSET + 8;
/// Offset of the append-only SYSENTER/SYSEXIT transition helper pointer.
pub const X86_GUEST_FAST_SYSTEM_TRANSFER_FN_OFFSET: i32 = X86_GUEST_INVLPG_FN_OFFSET + 8;
/// Offset of the append-only INVPCID helper pointer.
pub const X86_GUEST_INVPCID_FN_OFFSET: i32 = X86_GUEST_FAST_SYSTEM_TRANSFER_FN_OFFSET + 8;
/// Offset of the append-only nonarchitectural vector-memory transfer scratch.
///
/// `misc_enable`, `pat`, `umwait_control`, `xmm_state_active`, and
/// `mxcsr_state_active` occupy the five intervening 8-byte fields.
pub const X86_GUEST_VECTOR_SCRATCH_OFFSET: i32 = X86_GUEST_INVPCID_FN_OFFSET + 6 * 8;
/// Offset of the append-only guest TBM enumeration policy.
pub const X86_GUEST_CPUID_TBM_OFFSET: i32 = X86_GUEST_VECTOR_SCRATCH_OFFSET + 8 * 8;
/// Offset of the append-only guest XOP enumeration policy.
pub const X86_GUEST_CPUID_XOP_OFFSET: i32 = X86_GUEST_CPUID_TBM_OFFSET + 8;
/// Offset of the append-only original-VEX CMPccXADD transaction helper.
pub const X86_GUEST_CMPCCXADD_FN_OFFSET: i32 = X86_GUEST_CPUID_XOP_OFFSET + 8;
/// Offset of the append-only helper-backed port-I/O evaluator.
pub const X86_GUEST_IO_FN_OFFSET: i32 = X86_GUEST_CMPCCXADD_FN_OFFSET + 8;
/// Offset of the append-only packed port-I/O request/result channel.
pub const X86_GUEST_IO_REQUEST_OFFSET: i32 = X86_GUEST_IO_FN_OFFSET + 8;
/// Offset of the append-only helper-backed x86 ENTER transaction.
pub const X86_GUEST_ENTER_FN_OFFSET: i32 = X86_GUEST_IO_REQUEST_OFFSET + 8;
/// Offset of the append-only helper-backed PUSHF/POPF transaction.
pub const X86_GUEST_STACK_FLAGS_FN_OFFSET: i32 = X86_GUEST_ENTER_FN_OFFSET + 8;
/// Offset of the complete post-POPF architectural RFLAGS image.
pub const X86_GUEST_STACK_FLAGS_RFLAGS_OFFSET: i32 = X86_GUEST_STACK_FLAGS_FN_OFFSET + 8;
/// Offset of the post-POPF complete-RFLAGS override-valid marker.
pub const X86_GUEST_STACK_FLAGS_RFLAGS_VALID_OFFSET: i32 = X86_GUEST_STACK_FLAGS_RFLAGS_OFFSET + 8;
/// Offset of the append-only x87 control word state.
pub const X86_GUEST_X87_CONTROL_WORD_OFFSET: i32 = X86_GUEST_STACK_FLAGS_RFLAGS_VALID_OFFSET + 8;
/// Offset of the append-only x87 status word state.
pub const X86_GUEST_X87_STATUS_WORD_OFFSET: i32 = X86_GUEST_X87_CONTROL_WORD_OFFSET + 8;
/// Offset of the append-only last x87 data-operand pointer.
pub const X86_GUEST_X87_DATA_PTR_OFFSET: i32 = X86_GUEST_X87_STATUS_WORD_OFFSET + 8;
/// Offset of the append-only last x87 instruction pointer.
pub const X86_GUEST_X87_INSTR_PTR_OFFSET: i32 = X86_GUEST_X87_DATA_PTR_OFFSET + 8;
/// Offset of the append-only last x87 opcode.
pub const X86_GUEST_X87_LAST_OPCODE_OFFSET: i32 = X86_GUEST_X87_INSTR_PTR_OFFSET + 8;
/// Offset of the append-only x87 call-through synchronization marker.
pub const X86_GUEST_X87_STATE_ACTIVE_OFFSET: i32 = X86_GUEST_X87_LAST_OPCODE_OFFSET + 8;
/// Offset of the append-only direct-engine x87 physical payload image.
pub const X86_GUEST_X87_PAYLOAD_OFFSET: i32 = X86_GUEST_X87_STATE_ACTIVE_OFFSET + 8;
/// Offset of the append-only x87 payload call-through synchronization marker.
pub const X86_GUEST_X87_PAYLOAD_ACTIVE_OFFSET: i32 = X86_GUEST_X87_PAYLOAD_OFFSET + 8 * 8;
/// Offset of the append-only native VSIB partial-completion frontier marker.
pub const X86_GUEST_VSIB_FRONTIER_LANE_PLUS_ONE_OFFSET: i32 =
    X86_GUEST_X87_PAYLOAD_ACTIVE_OFFSET + 8;
/// Offset of the append-only native VSIB dynamic instruction ordinal.
pub const X86_GUEST_VSIB_INSTRUCTION_ORDINAL_OFFSET: i32 =
    X86_GUEST_VSIB_FRONTIER_LANE_PLUS_ONE_OFFSET + 8;
/// Internal `vec_load_fn` destination namespace for
/// [`runtime::GuestRegs::vector_scratch`]. Architectural ZMM indices remain
/// exactly 0..=31. For `vec_store_fn`, this tag names an unmasked scratch
/// store and the following seven tags select K1..K7 for sparse 2-byte-lane
/// scratch stores. `vec_load_fn` continues to reject every value above 32.
pub(crate) const X86_JIT_VECTOR_SCRATCH_INDEX: u32 = 32;
/// First `vec_store_fn` tag in the masked-word scratch namespace. Adding a
/// nonzero architectural mask index selects K1..K7 without extending the
/// append-only helper ABI.
pub(crate) const X86_JIT_VECTOR_MASKED_WORD_SCRATCH_BASE: u32 = X86_JIT_VECTOR_SCRATCH_INDEX;
/// Last valid `vec_store_fn` tag in the masked-word scratch namespace.
pub(crate) const X86_JIT_VECTOR_MASKED_WORD_SCRATCH_LAST: u32 =
    X86_JIT_VECTOR_MASKED_WORD_SCRATCH_BASE + 7;
/// Offset of the `*mut GuestRegs` state pointer in the native block frame.
pub const X86_STATE_PTR_AT_RBP: i32 = 24;

/// Internal selector-loader helper namespace reserved for VERR/VERW. The tag
/// combines selector ID 3 with far-pointer width code 3, both invalid for every
/// selector-load operation, while staying below the loader's established
/// unknown-bit boundary at bit 15.
pub(crate) const X86_SELECTOR_VERIFY_HELPER_TAG: u32 = 0x600C;
pub(crate) const X86_SELECTOR_VERIFY_HELPER_MEMORY: u32 = 1;
pub(crate) const X86_SELECTOR_VERIFY_HELPER_APX: u32 = 1 << 1;
pub(crate) const X86_SELECTOR_VERIFY_HELPER_WRITE: u32 = 1 << 5;
pub(crate) const X86_SELECTOR_VERIFY_HELPER_OPTION_MASK: u32 = X86_SELECTOR_VERIFY_HELPER_MEMORY
    | X86_SELECTOR_VERIFY_HELPER_APX
    | X86_SELECTOR_VERIFY_HELPER_WRITE;

/// Internal selector-loader helper namespace for LAR/LSL. Bit 16 lies beyond
/// every legacy selector-load encoding and the existing bit-15 malformed-shape
/// boundary. Options encode source class, APX, query kind, destination GPR,
/// and destination width; every other bit remains fail-closed.
pub(crate) const X86_SELECTOR_QUERY_HELPER_TAG: u32 = 1 << 16;
pub(crate) const X86_SELECTOR_QUERY_HELPER_MEMORY: u32 = 1;
pub(crate) const X86_SELECTOR_QUERY_HELPER_APX: u32 = 1 << 1;
pub(crate) const X86_SELECTOR_QUERY_HELPER_LIMIT: u32 = 1 << 2;
pub(crate) const X86_SELECTOR_QUERY_HELPER_DST_SHIFT: u32 = 3;
pub(crate) const X86_SELECTOR_QUERY_HELPER_DST_MASK: u32 =
    0x1F << X86_SELECTOR_QUERY_HELPER_DST_SHIFT;
pub(crate) const X86_SELECTOR_QUERY_HELPER_WIDTH_SHIFT: u32 = 8;
pub(crate) const X86_SELECTOR_QUERY_HELPER_WIDTH_MASK: u32 =
    0x3 << X86_SELECTOR_QUERY_HELPER_WIDTH_SHIFT;
pub(crate) const X86_SELECTOR_QUERY_HELPER_OPTION_MASK: u32 = X86_SELECTOR_QUERY_HELPER_MEMORY
    | X86_SELECTOR_QUERY_HELPER_APX
    | X86_SELECTOR_QUERY_HELPER_LIMIT
    | X86_SELECTOR_QUERY_HELPER_DST_MASK
    | X86_SELECTOR_QUERY_HELPER_WIDTH_MASK;

// ============================================================================
// Lowerer Trait
// ============================================================================

/// Trait for lowering SMIR to native machine code
pub trait SmirLowerer: Send {
    /// Target architecture name
    fn target_arch(&self) -> &'static str;

    /// Lower an entire function to machine code
    fn lower_function(&mut self, func: &SmirFunction) -> Result<LowerResult, LowerError>;

    /// Get the generated code buffer
    fn code_buffer(&self) -> &CodeBuffer;

    /// Finalize and get the executable code
    fn finalize(&mut self) -> Result<Vec<u8>, LowerError>;
}

// ============================================================================
// Lower Result
// ============================================================================

/// Result of lowering a function
#[derive(Clone, Debug)]
pub struct LowerResult {
    /// Size of generated code in bytes
    pub code_size: usize,

    /// Entry point offset within the code buffer
    pub entry_offset: usize,

    /// Block offsets (BlockId -> offset in code)
    pub block_offsets: HashMap<BlockId, usize>,

    /// Relocations that need to be applied
    pub relocations: Vec<Relocation>,

    /// Stack frame size required
    pub stack_size: usize,
}

// ============================================================================
// Relocation
// ============================================================================

/// A relocation that needs to be applied after code generation
#[derive(Clone, Debug)]
pub struct Relocation {
    /// Offset in the code buffer where the relocation applies
    pub offset: usize,

    /// Kind of relocation
    pub kind: RelocKind,

    /// Target of the relocation
    pub target: RelocTarget,
}

/// Relocation kind
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    /// PC-relative 8-bit displacement (for short jumps)
    PcRel8,

    /// PC-relative 32-bit displacement (for jumps and calls)
    PcRel32,

    /// Absolute 64-bit address
    Abs64,

    /// Absolute 32-bit address
    Abs32,
}

/// Relocation target
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelocTarget {
    /// Target is a block within the same function
    Block(BlockId),

    /// Target is a guest address (for indirect branches)
    GuestAddr(GuestAddr),

    /// Target is an external symbol
    External(String),

    /// Target is a runtime helper function
    Runtime(RuntimeHelper),
}

/// Runtime helper functions that lowered code may call
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelper {
    /// Memory read helper
    MemRead8,
    MemRead16,
    MemRead32,
    MemRead64,

    /// Memory write helper
    MemWrite8,
    MemWrite16,
    MemWrite32,
    MemWrite64,

    /// Syscall handler
    Syscall,

    /// Exception handler
    Exception,

    /// Division by zero handler
    DivByZero,

    /// Debug breakpoint handler
    Breakpoint,

    /// Lookup jump target for indirect branches
    LookupTarget,
}

// ============================================================================
// Code Buffer
// ============================================================================

/// Buffer for emitting machine code
#[derive(Clone, Debug, Default)]
pub struct CodeBuffer {
    /// The raw code bytes
    data: Vec<u8>,

    /// Current write position
    pos: usize,

    /// Labels (name -> offset)
    labels: HashMap<String, usize>,

    /// Pending fixups (offset -> label name)
    fixups: Vec<(usize, String, RelocKind)>,
}

impl CodeBuffer {
    /// Create a new code buffer
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a code buffer with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        CodeBuffer {
            data: Vec::with_capacity(capacity),
            pos: 0,
            labels: HashMap::new(),
            fixups: Vec::new(),
        }
    }

    /// Current position in the buffer
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Total length of emitted code
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the raw code bytes
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the raw code bytes as a slice (alias for data())
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the code bytes
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Emit a single byte
    pub fn emit_u8(&mut self, byte: u8) {
        if self.pos >= self.data.len() {
            self.data.push(byte);
        } else {
            self.data[self.pos] = byte;
        }
        self.pos += 1;
    }

    /// Emit a 16-bit value (little-endian)
    pub fn emit_u16(&mut self, value: u16) {
        self.emit_u8(value as u8);
        self.emit_u8((value >> 8) as u8);
    }

    /// Emit a 32-bit value (little-endian)
    pub fn emit_u32(&mut self, value: u32) {
        self.emit_u8(value as u8);
        self.emit_u8((value >> 8) as u8);
        self.emit_u8((value >> 16) as u8);
        self.emit_u8((value >> 24) as u8);
    }

    /// Emit a 64-bit value (little-endian)
    pub fn emit_u64(&mut self, value: u64) {
        self.emit_u32(value as u32);
        self.emit_u32((value >> 32) as u32);
    }

    /// Emit a signed 8-bit value
    pub fn emit_i8(&mut self, value: i8) {
        self.emit_u8(value as u8);
    }

    /// Emit a signed 32-bit value
    pub fn emit_i32(&mut self, value: i32) {
        self.emit_u32(value as u32);
    }

    /// Emit raw bytes
    pub fn emit_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.emit_u8(b);
        }
    }

    /// Define a label at the current position
    pub fn define_label(&mut self, name: impl Into<String>) {
        self.labels.insert(name.into(), self.pos);
    }

    /// Get label offset
    pub fn label_offset(&self, name: &str) -> Option<usize> {
        self.labels.get(name).copied()
    }

    /// Record a fixup to be applied later
    pub fn record_fixup(&mut self, label: impl Into<String>, kind: RelocKind) {
        self.fixups.push((self.pos, label.into(), kind));
    }

    /// Apply all recorded fixups
    pub fn apply_fixups(&mut self) -> Result<(), LowerError> {
        for (offset, label, kind) in self.fixups.clone() {
            let target = self
                .labels
                .get(&label)
                .ok_or_else(|| LowerError::UndefinedLabel {
                    label: label.clone(),
                })?;

            match kind {
                RelocKind::PcRel8 => {
                    let rel = (*target as i64) - (offset as i64) - 1;
                    if rel < -128 || rel > 127 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target,
                        });
                    }
                    self.data[offset] = rel as i8 as u8;
                }
                RelocKind::PcRel32 => {
                    let rel = (*target as i64) - (offset as i64) - 4;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target,
                        });
                    }
                    let bytes = (rel as i32).to_le_bytes();
                    self.data[offset..offset + 4].copy_from_slice(&bytes);
                }
                RelocKind::Abs32 => {
                    let bytes = (*target as u32).to_le_bytes();
                    self.data[offset..offset + 4].copy_from_slice(&bytes);
                }
                RelocKind::Abs64 => {
                    let bytes = (*target as u64).to_le_bytes();
                    self.data[offset..offset + 8].copy_from_slice(&bytes);
                }
            }
        }
        Ok(())
    }

    /// Patch a 32-bit value at a specific offset
    pub fn patch_i32(&mut self, offset: usize, value: i32) {
        let bytes = value.to_le_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// Patch a 64-bit value at a specific offset
    pub fn patch_u64(&mut self, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        self.data[offset..offset + 8].copy_from_slice(&bytes);
    }

    /// Align to boundary (pad with NOPs or zeros)
    pub fn align(&mut self, alignment: usize, pad_byte: u8) {
        while self.pos % alignment != 0 {
            self.emit_u8(pad_byte);
        }
    }

    /// Reset the buffer
    pub fn clear(&mut self) {
        self.data.clear();
        self.pos = 0;
        self.labels.clear();
        self.fixups.clear();
    }
}

// ============================================================================
// Lower Error
// ============================================================================

/// Error during lowering
#[derive(Clone, Debug)]
pub enum LowerError {
    /// Unsupported operation
    UnsupportedOp { op: String },

    /// Unsupported operation (string-only variant)
    UnsupportedOperation(String),

    /// Register allocation failed
    RegisterAllocationFailed { reason: String },

    /// Undefined label
    UndefinedLabel { label: String },

    /// Relocation out of range
    RelocationOutOfRange { offset: usize, target: usize },

    /// Invalid operand
    InvalidOperand { op: String, operand: String },

    /// Invalid register for lowering
    InvalidRegister(String),

    /// Stack overflow (too many spills)
    StackOverflow { required: usize, limit: usize },

    /// Internal error
    Internal(String),
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LowerError::UnsupportedOp { op } => write!(f, "unsupported operation: {}", op),
            LowerError::UnsupportedOperation(op) => write!(f, "unsupported operation: {}", op),
            LowerError::RegisterAllocationFailed { reason } => {
                write!(f, "register allocation failed: {}", reason)
            }
            LowerError::UndefinedLabel { label } => write!(f, "undefined label: {}", label),
            LowerError::RelocationOutOfRange { offset, target } => {
                write!(f, "relocation out of range: {} -> {}", offset, target)
            }
            LowerError::InvalidOperand { op, operand } => {
                write!(f, "invalid operand for {}: {}", op, operand)
            }
            LowerError::InvalidRegister(reg) => {
                write!(f, "invalid register: {}", reg)
            }
            LowerError::StackOverflow { required, limit } => {
                write!(
                    f,
                    "stack overflow: need {} bytes, limit {}",
                    required, limit
                )
            }
            LowerError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for LowerError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_buffer_emit() {
        let mut buf = CodeBuffer::new();

        buf.emit_u8(0x90); // NOP
        buf.emit_u8(0xC3); // RET

        assert_eq!(buf.len(), 2);
        assert_eq!(buf.data(), &[0x90, 0xC3]);
    }

    #[test]
    fn test_code_buffer_emit_multi() {
        let mut buf = CodeBuffer::new();

        buf.emit_u32(0x12345678);
        assert_eq!(buf.data(), &[0x78, 0x56, 0x34, 0x12]); // Little-endian

        buf.emit_u64(0xDEADBEEFCAFEBABE);
        assert_eq!(buf.len(), 12);
    }

    #[test]
    fn test_code_buffer_labels() {
        let mut buf = CodeBuffer::new();

        buf.emit_u8(0x90); // Position 0
        buf.define_label("target");
        buf.emit_u8(0x90); // Position 1

        assert_eq!(buf.label_offset("target"), Some(1));
    }

    #[test]
    fn test_code_buffer_fixups() {
        let mut buf = CodeBuffer::new();

        // JMP rel32 (placeholder)
        buf.emit_u8(0xE9);
        buf.record_fixup("target", RelocKind::PcRel32);
        buf.emit_u32(0); // Placeholder

        // Some code
        buf.emit_u8(0x90);
        buf.emit_u8(0x90);

        // Target
        buf.define_label("target");
        buf.emit_u8(0xC3);

        buf.apply_fixups().unwrap();

        // Verify the jump offset was patched correctly
        // Target is at offset 7, fixup is at offset 1, so rel = 7 - 1 - 4 = 2
        let rel = i32::from_le_bytes([buf.data()[1], buf.data()[2], buf.data()[3], buf.data()[4]]);
        assert_eq!(rel, 2);
    }

    #[test]
    fn test_code_buffer_align() {
        let mut buf = CodeBuffer::new();

        buf.emit_u8(0x90);
        buf.align(4, 0x00);

        assert_eq!(buf.len(), 4);
    }
}
