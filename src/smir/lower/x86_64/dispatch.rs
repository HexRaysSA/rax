//! Top-level per-op lowering dispatch (lower_op)

use crate::smir::lower::x86_64::*;
use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86VecAlign, X86VecMap, X86X87ControlKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, Condition, DispSize, FenceKind, FpRoundMode, GuestAddr, MemWidth,
    OpWidth, ShiftOp, SignExtend, SrcOperand, VLaneOp, VReg, VecCmpCond, VecElementType,
    VecUnaryOp, VecWidth, X86Reg,
};
use crate::smir::ir::{
    CallTarget, SmirBlock, SmirFunction, Terminator, X86InstructionBytes,
    x86_evex_native_replay_spans,
};

use crate::smir::lower::regalloc::{PhysReg, RegAlloc, RegLocation};
use crate::smir::lower::{
    CodeBuffer, LowerError, LowerResult, RelocKind, RelocTarget, Relocation, SmirLowerer,
    X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CALL_FN_OFFSET, X86_GUEST_CPL_OFFSET,
    X86_GUEST_CR0_OFFSET, X86_GUEST_CR4_OFFSET, X86_GUEST_CTX_OFFSET, X86_GUEST_EXIT_PC_OFFSET,
    X86_GUEST_FS_BASE_OFFSET, X86_GUEST_GS_BASE_OFFSET, X86_GUEST_K_OFFSET,
    X86_GUEST_LOAD_FN_OFFSET, X86_GUEST_MXCSR_OFFSET, X86_GUEST_PAIR_LOAD_FN_OFFSET,
    X86_GUEST_PAIR_STORE_FN_OFFSET, X86_GUEST_RFLAGS_OFFSET, X86_GUEST_STORE_FN_OFFSET,
    X86_GUEST_TSC_AUX_OFFSET, X86_GUEST_VEC_LOAD_FN_OFFSET, X86_GUEST_VEC_STORE_FN_OFFSET,
    X86_GUEST_X87_TAG_WORD_OFFSET, X86_GUEST_XCR0_OFFSET, X86_GUEST_XGETBV1_OFFSET,
    X86_GUEST_ZMM_OFFSET, X86_HOST_MXCSR_OFFSET, X86_STATE_PTR_AT_RBP,
};

impl X86_64Lowerer {
    /// Lower a single operation
    pub(crate) fn lower_op(&mut self, op: &crate::smir::ir::ops::SmirOp) -> Result<(), LowerError> {
        if matches!(op.x86_hint, Some(X86OpHint::ShiftGroup6)) && !x86_shift_group6_shape_valid(op)
        {
            return Err(LowerError::InvalidOperand {
                op: "legacy Group-2 /6 SAL".to_string(),
                operand: format!("invalid hinted SMIR shape: {:?}", op.kind),
            });
        }
        if self.try_lower_scalar_alu_immediate(op)? {
            return Ok(());
        }
        if matches!(op.kind, OpKind::X86Random { .. }) {
            self.lower_x86_random(op)?;
            return Ok(());
        }
        if self.lower_opmask(op)? {
            return Ok(());
        }
        if self.lower_mmx_rr(op)? {
            return Ok(());
        }
        // AVX10 owns the EVEX-native vector operations that do not have a
        // legacy scalar lowering below. Keep this dispatch in the production
        // path so the dedicated encoder is exercised by normal JIT lowering,
        // not only by its module-local unit tests.
        self.lower_op_data_movement(op)
    }
}
