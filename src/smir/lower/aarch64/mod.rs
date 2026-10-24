//! Native AArch64 code generator for SMIR.
//!
//! Supported architectural AArch64 X and V registers map to the corresponding
//! native registers, subject to the runtime's trampoline clobber checks. Private
//! virtual temporaries may be eliminated by exact instruction fusions. Unsupported
//! operations and operand forms return a lowering error for interpreter fallback.

use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    ArmDpRegShiftKind, OpKind, SmirOp, X86AdxKind, X86BlsKind, X86CountKind, X86TbmKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, AtomicOp, Avx10FP16Op, BlockId, Condition, ExtendOp, FenceKind,
    FpPrecision, FpRoundMode, MemWidth, MemoryOrder, OpWidth, ShiftOp, SignExtend, SrcOperand,
    VLaneOp, VReg, VecElementType, VecPermuteKind, VecReduceOp, VecUnaryOp, VecWidth,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

use super::{CodeBuffer, LowerError, LowerResult, Relocation, SmirLowerer};

// ---- module tree (auto-split) ----
mod advanced_simd;
pub(crate) use advanced_simd::{aarch64_neon_fusion, aarch64_neon_fusions_are_private};
mod arithmetic;
mod arithmetic_simd;
pub use arithmetic::*;
mod atomic;
pub use atomic::*;
mod bextr;
pub use bextr::*;
mod bit;
pub use bit::*;
mod blocks;
mod branch;
pub use branch::*;
mod carry_rotate;
pub use carry_rotate::*;
mod comparisons;
pub(crate) use comparisons::aarch64_cmn_shape_valid;
mod fence;
pub use fence::*;
mod flags;
pub use flags::*;
mod fp;
pub use fp::*;
mod jit;
pub use jit::*;
mod lanes;
pub(crate) use lanes::{aarch64_neon_lane_shape_valid, aarch64_vcmp_shape_valid};
mod logic;
pub use logic::*;
mod memory;
pub use memory::*;
mod misc;
pub use misc::*;
mod mov;
pub use mov::*;
mod ops;
mod pauth;
mod resize;
pub(crate) use resize::aarch64_resize_shape_valid;
mod saturating;
mod scalar_simd;
pub(crate) use saturating::aarch64_saturating_shape_valid;
pub(crate) use scalar_simd::integer_scalar_provenance_valid;
mod require_apx;
pub use require_apx::*;
mod require_tbm;
pub use require_tbm::*;
mod shift;
pub use shift::*;
mod simd;
pub use simd::*;
mod sysreg;
pub use sysreg::*;
#[cfg(test)]
mod tests;

const NZCV_N: i64 = 1_i64 << 31;
const NZCV_Z: i64 = 1_i64 << 30;
const NZCV_C: i64 = 1_i64 << 29;
const NZCV_V: i64 = 1_i64 << 28;
const NZCV_MASK: i64 = NZCV_N | NZCV_Z | NZCV_C | NZCV_V;
const FPCR_SYSREG_MASK: i64 = 0x07c8_0007;
const FPSR_SYSREG_MASK: i64 = 0xf800_009f;
const SYSREG_NZCV: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (2 << 3);
const SYSREG_FPCR: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3);
const SYSREG_FPSR: u32 = (3 << 14) | (3 << 11) | (4 << 7) | (4 << 3) | 1;

/// Host register reserved by the identity-map entry trampoline
/// (`rax_a64_enter_native`, smir::lower::runtime) to hold the persistent
/// `*mut Aarch64GuestRegs` state pointer. Native-exit and memory-helper stubs
/// dereference it; region bodies must never use guest X28 (clobber gate).
const A64_STATE_REG: u8 = 28;
/// Byte offsets into the runtime `Aarch64GuestRegs` struct (smir::lower::
/// runtime), dereferenced via the state pointer in `A64_STATE_REG` by the
/// native-exit and memory-helper stubs. Kept in sync with that struct's
/// `*_OFFSET` consts (asserted in the runtime's aarch64 tests). All are
/// multiples of 8 so they encode as scaled `emit_ldst_unsigned` imm12 offsets.
const A64_GUEST_SP_OFFSET: u32 = 248;
const A64_GUEST_PC_OFFSET: u32 = 256;
const A64_GUEST_NZCV_OFFSET: u32 = 264;
const A64_GUEST_V_OFFSET: u32 = 288;
const A64_GUEST_CTX_OFFSET: u32 = 800;
const A64_GUEST_LOAD_FN_OFFSET: u32 = 808;
const A64_GUEST_STORE_FN_OFFSET: u32 = 816;
const A64_GUEST_VEC_LOAD_FN_OFFSET: u32 = 848;
const A64_GUEST_VEC_STORE_FN_OFFSET: u32 = 856;
const A64_GUEST_EXIT_FLAGS_OFFSET: u32 = 864;
const A64_GUEST_X86_APX_ENABLED_OFFSET: u32 = A64_GUEST_EXIT_FLAGS_OFFSET + 8;
const A64_GUEST_X86_TBM_ENABLED_OFFSET: u32 = A64_GUEST_X86_APX_ENABLED_OFFSET + 8;
const A64_GUEST_X86_TBM_MODE_VALID_OFFSET: u32 = A64_GUEST_X86_TBM_ENABLED_OFFSET + 8;
const A64_EXIT_VALID: i64 = 1 << 0;
const A64_EXIT_AARCH32_T: i64 = 1 << 1;
const A64_EXIT_AARCH32_T_VALID: i64 = 1 << 2;

/// Native AArch64 lowerer for identity-mapped AArch64 scalar SMIR.
pub struct Aarch64Lowerer {
    code: CodeBuffer,
    block_offsets: HashMap<BlockId, usize>,
    branch_fixups: Vec<BranchFixup>,
    relocations: Vec<Relocation>,
    /// Frontier blocks (block id → resume guest PC) that must EXIT the native
    /// region rather than execute. Their body is replaced by a stub that
    /// records the resume PC into `Aarch64GuestRegs.pc` (via the state pointer
    /// in `A64_STATE_REG`) and returns to the entry trampoline; the interpreter
    /// then re-executes from that PC. Set via [`Self::set_native_exits`] before
    /// `lower_function`. Empty ⇒ self-contained region: terminators lower to
    /// their native guest control transfer (e.g. RET → `ret`), as used by the
    /// standalone byte/exec tests.
    native_exits: HashMap<BlockId, u64>,
    /// In-region source/target edges that cross the compiled frontier. Unlike
    /// `native_exits`, these do not replace a target block globally: only the
    /// selected edge records its resume PC and returns to the trampoline.
    native_exit_edges: HashMap<(BlockId, BlockId), u64>,
    /// When true, a direct argument-free guest call lowers as a native-region
    /// exit to its guest target after the block's link-register operation has
    /// executed. This mode requires the runtime state pointer in X28 and must
    /// be enabled only after the AArch32 structural gate validates the call.
    guest_call_exits: bool,
    /// When true, validated AArch32 BLX calls lower to dispatcher exits that
    /// additionally export the callee execution state. Register targets are
    /// consumed as W32 interworking pointers; direct targets carry an explicit
    /// Thumb-state tag in SMIR.
    guest_interworking_call_exits: bool,
    /// When true, a register indirect branch is converted to an AArch32
    /// interworking dispatcher exit: the zero-extended `(target & !1)` is
    /// recorded as PC and target bit 0 is exported as CPSR.T. This must only be
    /// enabled after the AArch32 structural gate validates the terminator.
    guest_indirect_exits: bool,
    /// When true, x86-specific dynamic guards may read the appended bridge
    /// fields in `Aarch64GuestRegs`. This mode must be paired with the strict
    /// x86-on-AArch64 native gate; ordinary AArch64/AArch32 callers leave it
    /// disabled and fail closed on x86 architectural state.
    x86_guest_state_guards: bool,
    /// When true, memory ops lower to runtime-helper call-outs (MMU-translated)
    /// instead of inline native LDR/STR against the raw guest address. Set via
    /// [`Self::set_mem_helpers`].
    mem_helpers: bool,
    /// Scoped full-state PAuth helper ABI; disabled for legacy trampolines.
    pauth_helpers: bool,
    pauth_fp_helpers: bool,
    /// Width used for helper effective-address arithmetic. AArch64 guests use
    /// the default W64 semantics; AArch32-on-AArch64 callers select W32 so
    /// additions wrap modulo 2^32 before the helper observes the address.
    mem_helper_addr_width: OpWidth,
    /// Host support for FEAT_FLAGM (`CFINV`).
    flagm_available: bool,
    /// Host support for FEAT_FLAGM2 (`AXFLAG`/`XAFLAG`).
    flagm2_available: bool,
    /// Host support for FEAT_FP16 (half-precision Advanced SIMD / scalar FP).
    fp16_available: bool,
    /// Host support for FEAT_CRC32 (CRC32C scalar instructions).
    crc_available: bool,
}

#[derive(Clone, Copy)]
struct BranchFixup {
    offset: usize,
    target: BlockId,
    kind: BranchFixupKind,
}

#[derive(Clone, Copy)]
enum BranchFixupKind {
    Uncond,
    Cond { cond: u32 },
    CompareAndBranch { rt: u8, nonzero: bool },
}

#[derive(Clone, Copy)]
enum BitTestAction {
    Test,
    Set,
    Reset,
    Toggle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CondSelectFalseOp {
    Identity,
    Increment,
    Invert,
    Negate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CondCompareSource {
    Encoded { rm_imm5: u8, immediate: bool },
    Immediate(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimdLogicOp {
    And,
    AndNot,
    Or,
    OrNot,
    Xor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimdArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
    Max,
    Min { signed: bool },
}

#[derive(Clone, Copy)]
struct SysRegInfo {
    op1: u32,
    crn: u32,
    crm: u32,
    op2: u32,
    mask: i64,
    read_width: OpWidth,
    write_width: OpWidth,
}

fn is_aarch64_fp_trampoline_vreg(vreg: &VReg) -> bool {
    matches!(
        vreg,
        VReg::Arch(ArchReg::Arm(ArmReg::V(_) | ArmReg::Fpcr | ArmReg::Fpsr))
    )
}

fn is_aarch64_fp_sysreg(reg: u32) -> bool {
    matches!(reg, SYSREG_FPCR | SYSREG_FPSR)
}

/// Return true when a native AArch64 region needs the FP/SIMD trampoline.
///
/// Besides V-register ops, direct FPCR/FPSR sysreg access must use this path so
/// guest FP state is loaded from/stored to `Aarch64GuestRegs` and host FPCR/FPSR
/// are restored before returning to Rust.
pub fn uses_aarch64_fp_trampoline(func: &SmirFunction) -> bool {
    func.blocks.iter().flat_map(|b| &b.ops).any(|op| {
        if matches!(
            op.kind,
            OpKind::ArmInstructionBegin { .. }
                | OpKind::ArmInstructionCommit { .. }
                | OpKind::ArmPauth(..)
        ) {
            // Implicit observability metadata is stored in the scoped runtime;
            // it does not make vectors live in physical host registers.
            return false;
        }
        let touches_raw_fp_sysreg = match &op.kind {
            OpKind::ReadSysReg { reg, .. } | OpKind::WriteSysReg { reg, .. } => {
                is_aarch64_fp_sysreg(*reg)
            }
            _ => false,
        };

        touches_raw_fp_sysreg
            || op.kind.dests().iter().any(is_aarch64_fp_trampoline_vreg)
            || op
                .kind
                .source_vregs()
                .iter()
                .any(is_aarch64_fp_trampoline_vreg)
    })
}

impl Default for Aarch64Lowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLowerer for Aarch64Lowerer {
    fn target_arch(&self) -> &'static str {
        "aarch64"
    }

    fn lower_function(&mut self, func: &SmirFunction) -> Result<LowerResult, LowerError> {
        if !aarch64_neon_fusions_are_private(func) {
            return Err(LowerError::UnsupportedOp {
                op: "escaping AdvSIMD temporary".to_string(),
            });
        }
        self.pauth_fp_helpers = self.pauth_helpers && uses_aarch64_fp_trampoline(func);
        self.code.clear();
        self.block_offsets.clear();
        self.branch_fixups.clear();
        self.relocations.clear();

        for block in &func.blocks {
            if self.pauth_helpers {
                crate::smir::ir::validate_aarch64_instructions(block).map_err(|operation| {
                    LowerError::UnsupportedOp {
                        op: operation.into(),
                    }
                })?;
            }
            self.lower_block(block)?;
        }
        self.fixup_branches()?;

        Ok(LowerResult {
            code_size: self.code.len(),
            entry_offset: *self.block_offsets.get(&func.entry).unwrap_or(&0),
            block_offsets: self.block_offsets.clone(),
            relocations: self.relocations.clone(),
            stack_size: 0,
        })
    }

    fn code_buffer(&self) -> &CodeBuffer {
        &self.code
    }

    fn finalize(&mut self) -> Result<Vec<u8>, LowerError> {
        Ok(self.code.as_slice().to_vec())
    }
}
