//! x86_64 code generator for SMIR.
//!
//! This module lowers SMIR IR to native x86_64 machine code.

pub mod avx10;

use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86TbmKind, X86VecAlign, X86VecMap,
    X86X87ControlKind,
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

use super::regalloc::{PhysReg, RegAlloc, RegLocation};
use super::{
    CodeBuffer, LowerError, LowerResult, RelocKind, RelocTarget, Relocation, SmirLowerer,
    X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CALL_FN_OFFSET, X86_GUEST_CMPCCXADD_FN_OFFSET,
    X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET, X86_GUEST_CR4_OFFSET, X86_GUEST_CTX_OFFSET,
    X86_GUEST_EXIT_PC_OFFSET, X86_GUEST_FS_BASE_OFFSET, X86_GUEST_GS_BASE_OFFSET,
    X86_GUEST_K_OFFSET, X86_GUEST_LOAD_FN_OFFSET, X86_GUEST_MXCSR_OFFSET,
    X86_GUEST_PAIR_LOAD_FN_OFFSET, X86_GUEST_PAIR_STORE_FN_OFFSET, X86_GUEST_RFLAGS_OFFSET,
    X86_GUEST_STORE_FN_OFFSET, X86_GUEST_TSC_AUX_OFFSET, X86_GUEST_VEC_LOAD_FN_OFFSET,
    X86_GUEST_VEC_STORE_FN_OFFSET, X86_GUEST_X87_TAG_WORD_OFFSET, X86_GUEST_XCR0_OFFSET,
    X86_GUEST_XGETBV1_OFFSET, X86_GUEST_ZMM_OFFSET, X86_HOST_MXCSR_OFFSET, X86_STATE_PTR_AT_RBP,
};

// ---- module tree (auto-split) ----
mod ac;
pub use ac::*;
#[cfg(feature = "smir-jit")]
mod ah_flags;
mod alignment_ac;
pub use alignment_ac::*;
#[cfg(feature = "smir-jit")]
mod aes_memory_source;
mod alu;
mod avx_ymm16_state;
pub use alu::*;
mod bit_offset;
pub use bit_offset::*;
mod common;
pub use common::*;
mod control;
pub use control::*;
mod clts;
mod legacy_high_byte_replay;
mod native_replay;
pub use clts::*;
mod cli;
pub use cli::*;
mod cmpxchg;
pub use cmpxchg::*;
#[cfg(feature = "smir-jit")]
mod cmpccxadd;
#[cfg(feature = "smir-jit")]
pub use cmpccxadd::*;
mod sti;
pub use sti::*;
#[cfg(feature = "smir-jit")]
mod stack_flags;
#[cfg(feature = "smir-jit")]
pub(crate) use stack_flags::*;
mod cpuid;
mod state_backed_replay;
mod xadd;
pub use cpuid::*;
pub(crate) use xadd::*;
mod descriptor_table;
pub use descriptor_table::*;
#[cfg(feature = "smir-jit")]
mod enter;
#[cfg(feature = "smir-jit")]
pub(crate) use enter::*;
#[cfg(feature = "smir-jit")]
mod leave;
#[cfg(feature = "smir-jit")]
pub(crate) use leave::*;
#[cfg(feature = "smir-jit")]
mod evex_alignr_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_bf16_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_broadcast_interleave_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_broadcast_logic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_broadcast_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_bw_shuffle_madd_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_chunk_insert_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_chunk_shuffle_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_compress_memory_destination;
#[cfg(feature = "smir-jit")]
mod evex_dbpsadbw_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_duplicate_move_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_expand_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_extract_memory_destination;
#[cfg(feature = "smir-jit")]
mod evex_fixup_imm_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fma3_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_four_dot_product_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_four_fma_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp16_arithmetic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp16_complex_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp16_narrow_memory_destination;
#[cfg(feature = "smir-jit")]
mod evex_fp_arithmetic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp_class_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp_flag_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp_interleave_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_fp_shuffle_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_full_permute_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_gfni_affine_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_gfni_multiply_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_half_move_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_arithmetic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_interleave_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_mask_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_minmax_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_narrow_memory_destination;
#[cfg(feature = "smir-jit")]
mod evex_integer_pack_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_integer_unary_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_lane_shuffle_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_logic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_mask_blend_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_masked_logic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_movntdqa_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_multishift_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_abs_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_extend_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_fp16_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_fp_unary_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_funnel_shift_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_move_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_rotate_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_shift_imm_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_packed_variable_shift_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_psadbw_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_range_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_fp_arithmetic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_fp_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_fp_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_fp_to_int_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_fp_unary_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_insert_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_int_to_fp_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scalar_memory_source_common;
#[cfg(feature = "smir-jit")]
mod evex_scalar_move_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_scale_f_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_shared_count_shift_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_ternary_logic_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_two_table_permute_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_variable_permute_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_vector_align_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_vp2intersect_memory_source;
#[cfg(feature = "smir-jit")]
mod evex_vpshufbitqmb_memory_source;
mod evex_vsib_memory;
mod invlpg;
#[cfg(feature = "smir-jit")]
mod jit_vector_memory_replay;
pub use invlpg::*;
mod invpcid;
pub use invpcid::*;
#[cfg(feature = "smir-jit")]
mod io;
#[cfg(feature = "smir-jit")]
pub(crate) use io::*;
mod dispatch;
pub use dispatch::*;
mod emitter;
mod fsgsbase;
pub use fsgsbase::*;
mod far_jump;
pub use far_jump::*;
mod far_call;
pub use far_call::*;
mod far_return;
pub use far_return::*;
mod flag_control;
pub(crate) use flag_control::*;
mod fast_system_transfer;
pub use fast_system_transfer::*;
mod monitor_mwait;
pub use monitor_mwait::*;
mod mmx_movd_q;
pub use mmx_movd_q::*;
mod mxcsr;
pub use mxcsr::*;
mod opmask;
pub use opmask::*;
mod waitpkg;
pub use waitpkg::*;
mod msr;
pub use msr::*;
mod pkru;
pub use pkru::*;
mod require_apx;
pub use require_apx::*;
mod require_sse4a;
pub use require_sse4a::*;
mod require_tbm;
pub use require_tbm::*;
mod require_xop;
pub use require_xop::*;
mod read_control;
pub use read_control::*;
mod read_debug;
pub use read_debug::*;
mod rdpid;
pub(crate) use rdpid::*;
mod write_debug;
pub use write_debug::*;
mod write_control;
pub use write_control::*;
mod serialize;
pub use serialize::*;
mod selector;
pub use selector::*;
mod shift_group6;
pub(crate) use shift_group6::*;
mod smsw;
pub use smsw::*;
mod swapgs;
pub use swapgs::*;
mod timing;
pub use timing::*;
mod ops;
pub use emitter::*;
pub(crate) use ops::x86_x87_state_shape_valid;
mod jit;
mod jit_scalar_alu_rmw;
mod jit_scalar_alu_source;
mod scalar_alu_immediate;
pub(crate) use scalar_alu_immediate::{
    X86ScalarAluImmediate, scalar_alu_immediate_is_encodable, x86_scalar_alu_immediate_candidate,
    x86_scalar_alu_immediate_shape, x86_scalar_alu_immediate_valid,
};
mod jit_scalar_memory;
pub use jit::*;
#[cfg(feature = "smir-jit")]
mod jit_mul;
#[cfg(feature = "smir-jit")]
pub use jit_mul::*;
#[cfg(feature = "smir-jit")]
mod jit_bmi;
#[cfg(feature = "smir-jit")]
pub use jit_bmi::*;
#[cfg(feature = "smir-jit")]
mod jit_shift;
#[cfg(feature = "smir-jit")]
pub use jit_shift::*;
#[cfg(feature = "smir-jit")]
mod jit_tbm;
#[cfg(feature = "smir-jit")]
pub use jit_tbm::*;
mod jit_crc32;
pub use jit_crc32::*;
mod jit_call;
pub use jit_call::*;
mod jit_memory_address;
pub use jit_memory_address::*;
mod jit_memory_value;
mod lmsw;
pub use lmsw::*;
mod mem_state_compare;
pub use mem_state_compare::*;
#[cfg(feature = "smir-jit")]
mod push_value;
#[cfg(feature = "smir-jit")]
pub use push_value::*;
mod memory;
pub use memory::*;
#[cfg(feature = "smir-jit")]
mod movbe_memory;
#[cfg(feature = "smir-jit")]
pub use movbe_memory::*;
#[cfg(feature = "smir-jit")]
mod movrs_memory;
#[cfg(feature = "smir-jit")]
pub use movrs_memory::*;
mod mmx_helpers;
pub use mmx_helpers::*;
#[cfg(feature = "smir-jit")]
mod mmx_memory_source;
#[cfg(feature = "smir-jit")]
pub use mmx_memory_source::*;
mod misc;
pub use misc::*;
mod native_stack_safety;
mod simd;
pub use simd::*;
mod sse4a;
pub use sse4a::*;
mod xop;
pub use xop::*;
mod state;
pub use state::*;
mod state_extend;
pub(crate) use state_extend::*;
mod random;
pub(crate) use random::*;
mod state_tbm;
mod state_xchg;
pub use state_tbm::*;
mod state_alu;
pub use state_alu::*;
mod state_lea;
pub use state_lea::*;
mod state_multiply;
pub(crate) use state_multiply::*;
mod state_mulx;
pub use state_mulx::*;
mod state_address;
pub use state_address::*;
mod vbit_select;
mod vector_helpers;
pub use vbit_select::*;
mod vector_compare;
pub use vector_compare::*;
#[cfg(feature = "smir-jit")]
mod vector_maskmov;
#[cfg(feature = "smir-jit")]
pub use vector_maskmov::*;
#[cfg(test)]
mod tests;
#[cfg(feature = "smir-jit")]
mod vbit_select_memory_source;
#[cfg(feature = "smir-jit")]
mod vector_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_alignr_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_binary_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_broadcast_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_cross_lane_128_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_duplicate_move_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_estimate_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_extract_memory_destination;
#[cfg(feature = "smir-jit")]
mod vex_fma4_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_fp16_narrow_memory_destination;
#[cfg(feature = "smir-jit")]
mod vex_fp_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_fp_dot_product_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_fp_flag_compare_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_fp_shuffle_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_gfni_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_half_move_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_immediate_blend_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_immediate_permute_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_lane_shuffle_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_masked_memory;
#[cfg(feature = "smir-jit")]
mod vex_movntdqa_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_mpsadbw_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_ne_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_packed_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_packed_extend_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_packed_string_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_ptest_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_round_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_scalar_convert_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_scalar_fp_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_scalar_insert_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_scalar_integer_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_sm3_sm4_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_sqrt_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_unary_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_variable_blend_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_variable_permute_memory_source;
#[cfg(feature = "smir-jit")]
mod vex_vpermil2_memory_source;
#[cfg(feature = "smir-jit")]
mod vpclmulqdq_memory_source;
#[cfg(feature = "smir-jit")]
mod xop_memory_source;
mod xsetbv;
pub(crate) use xsetbv::*;

fn x86_state_backed_arch_gpr(reg: &VReg) -> bool {
    matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some_and(|index| index >= 16 || matches!(index, 4 | 5)))
}

pub(crate) fn x86_state_backed_gpr_cmove_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::CMove { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_cmove_valid(op: &SmirOp) -> bool {
    let gpr_index = |reg: &VReg| match reg {
        VReg::Arch(ArchReg::X86(x86)) => x86.gpr_index(),
        _ => None,
    };
    let state_backed = |index: u8| index >= 16 || matches!(index, 4 | 5);

    matches!(
        &op.kind,
        OpKind::CMove {
            dst,
            src,
            cond,
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if x86_state_backed_gpr_cmove_candidate(op)
            && op.x86_hint.is_none()
            && *cond != Condition::Always
            && gpr_index(dst).is_some()
            && gpr_index(src).is_some()
            && (gpr_index(dst).is_some_and(state_backed)
                || gpr_index(src).is_some_and(state_backed))
    )
}

pub(crate) fn x86_state_backed_gpr_setcc_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::SetCC { dst, .. } if x86_state_backed_arch_gpr(dst)
    )
}

pub(crate) fn x86_state_backed_gpr_setcc_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::SetCC {
            dst,
            cond,
            width: OpWidth::W8 | OpWidth::W64,
        } if x86_state_backed_gpr_setcc_candidate(op)
            && op.x86_hint.is_none()
            && *cond != Condition::Always
            && matches!(dst, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some())
    )
}

pub(crate) fn x86_state_backed_gpr_not_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Not { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_not_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Not {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if x86_state_backed_gpr_not_candidate(op)
            && op.x86_hint.is_none()
            && dst.gpr_index().is_some()
            && src.gpr_index().is_some()
    )
}

pub(crate) fn x86_state_backed_gpr_neg_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Neg { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_neg_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Neg {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::All,
        } if x86_state_backed_gpr_neg_candidate(op)
            && op.x86_hint.is_none()
            && dst.gpr_index().is_some()
            && src.gpr_index().is_some()
    )
}

pub(crate) fn x86_state_backed_gpr_inc_dec_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Inc { dst, src, .. } | OpKind::Dec { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_inc_dec_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Inc {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::All,
        }
        | OpKind::Dec {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::All,
        } if x86_state_backed_gpr_inc_dec_candidate(op)
            && op.x86_hint.is_none()
            && dst.gpr_index().is_some()
            && src.gpr_index().is_some()
    )
}

pub(crate) fn x86_state_backed_gpr_rotate_candidate(op: &SmirOp) -> bool {
    let state_amount = |amount: &SrcOperand| matches!(amount, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));

    matches!(
        &op.kind,
        OpKind::Rol {
            dst, src, amount, ..
        }
        | OpKind::Ror {
            dst, src, amount, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || state_amount(amount)
    )
}

pub(crate) fn x86_state_backed_gpr_rotate_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let amount_valid = |amount: &SrcOperand| {
        matches!(amount, SrcOperand::Imm(_))
            || matches!(amount, SrcOperand::Reg(reg) if arch_gpr(reg))
    };
    let rotate_flags = FlagSet::CF.union(FlagSet::OF);
    let flags_valid = |flags: &FlagUpdate| {
        matches!(flags, FlagUpdate::None | FlagUpdate::All)
            || matches!(flags, FlagUpdate::Specific(set) if *set == rotate_flags)
    };

    x86_state_backed_gpr_rotate_candidate(op)
        && op.x86_hint.is_none()
        && match &op.kind {
            OpKind::Rol {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags,
            }
            | OpKind::Ror {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags,
            } => arch_gpr(dst) && arch_gpr(src) && amount_valid(amount) && flags_valid(flags),
            _ => false,
        }
}

pub(crate) fn x86_state_backed_gpr_shift_candidate(op: &SmirOp) -> bool {
    let state_amount = |amount: &SrcOperand| matches!(amount, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));

    matches!(
        &op.kind,
        OpKind::Shl {
            dst, src, amount, ..
        }
        | OpKind::Shr {
            dst, src, amount, ..
        }
        | OpKind::Sar {
            dst, src, amount, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || state_amount(amount)
    )
}

pub(crate) fn x86_state_backed_gpr_shift_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let amount_valid = |amount: &SrcOperand| {
        matches!(amount, SrcOperand::Imm(_))
            || matches!(amount, SrcOperand::Reg(reg) if arch_gpr(reg))
    };

    x86_state_backed_gpr_shift_candidate(op)
        && op.x86_hint.is_none()
        && match &op.kind {
            OpKind::Shl {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
            }
            | OpKind::Shr {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
            }
            | OpKind::Sar {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
            } => arch_gpr(dst) && arch_gpr(src) && amount_valid(amount),
            _ => false,
        }
}

pub(crate) fn x86_state_backed_gpr_carry_rotate_candidate(op: &SmirOp) -> bool {
    let state_amount = |amount: &SrcOperand| matches!(amount, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());

    matches!(
        &op.kind,
        OpKind::Rcl {
            dst, src, amount, ..
        }
        | OpKind::Rcr {
            dst, src, amount, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || state_amount(amount)
            // The identity-map fast path is exact only for the literal
            // count-one shape. Route every other architectural-GPR form
            // through the existing deterministic CF/OF state-backed merge.
            || (arch_gpr(dst) && arch_gpr(src) && !matches!(amount, SrcOperand::Imm(1)))
    )
}

pub(crate) fn x86_state_backed_gpr_carry_rotate_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let amount_valid = |amount: &SrcOperand| {
        matches!(amount, SrcOperand::Imm(_))
            || matches!(amount, SrcOperand::Reg(reg) if arch_gpr(reg))
    };
    let rotate_flags = FlagSet::CF.union(FlagSet::OF);
    let flags_valid = |flags: &FlagUpdate| {
        matches!(flags, FlagUpdate::None | FlagUpdate::All)
            || matches!(flags, FlagUpdate::Specific(set) if *set == rotate_flags)
    };

    x86_state_backed_gpr_carry_rotate_candidate(op)
        && op.x86_hint.is_none()
        && match &op.kind {
            OpKind::Rcl {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags,
            }
            | OpKind::Rcr {
                dst,
                src,
                amount,
                width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags,
            } => arch_gpr(dst) && arch_gpr(src) && amount_valid(amount) && flags_valid(flags),
            _ => false,
        }
}

pub(crate) fn x86_state_backed_gpr_double_shift_candidate(op: &SmirOp) -> bool {
    let state_amount = |amount: &SrcOperand| matches!(amount, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));
    let needs_subword_guard = |width: OpWidth, amount: &SrcOperand| {
        width == OpWidth::W16
            && match amount {
                SrcOperand::Imm(value) => (*value as u64 & 0x1f) > 16,
                SrcOperand::Reg(_) => true,
                _ => false,
            }
    };

    match &op.kind {
        OpKind::Shld {
            dst,
            src,
            amount,
            width,
            ..
        }
        | OpKind::Shrd {
            dst,
            src,
            amount,
            width,
            ..
        } => {
            x86_state_backed_arch_gpr(dst)
                || x86_state_backed_arch_gpr(src)
                || state_amount(amount)
                || needs_subword_guard(*width, amount)
        }
        OpKind::X86NddDoubleShift {
            dst,
            base,
            fill,
            amount,
            width,
            ..
        } => {
            x86_state_backed_arch_gpr(dst)
                || x86_state_backed_arch_gpr(base)
                || x86_state_backed_arch_gpr(fill)
                || state_amount(amount)
                || needs_subword_guard(*width, amount)
        }
        _ => false,
    }
}

pub(crate) fn x86_state_backed_gpr_double_shift_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let amount_valid = |amount: &SrcOperand| {
        matches!(amount, SrcOperand::Imm(_))
            || matches!(amount, SrcOperand::Reg(reg) if arch_gpr(reg))
    };
    let ndd_amount_valid = |amount: &SrcOperand| {
        matches!(amount, SrcOperand::Imm(_))
            || matches!(
                amount,
                SrcOperand::Reg(VReg::Arch(ArchReg::X86(X86Reg::Rcx)))
            )
    };

    x86_state_backed_gpr_double_shift_candidate(op)
        && op.x86_hint.is_none()
        && match &op.kind {
            OpKind::Shld {
                dst,
                src,
                amount,
                width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
            }
            | OpKind::Shrd {
                dst,
                src,
                amount,
                width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
            } => arch_gpr(dst) && arch_gpr(src) && amount_valid(amount),
            OpKind::X86NddDoubleShift {
                dst,
                base,
                fill,
                amount,
                width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                flags: FlagUpdate::None | FlagUpdate::All,
                ..
            } => arch_gpr(dst) && arch_gpr(base) && arch_gpr(fill) && ndd_amount_valid(amount),
            _ => false,
        }
}

pub(crate) fn x86_state_backed_gpr_count_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86Count { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_count_valid(op: &SmirOp) -> bool {
    let OpKind::X86Count {
        dst: VReg::Arch(ArchReg::X86(dst)),
        src: VReg::Arch(ArchReg::X86(src)),
        width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        kind,
        flags,
    } = &op.kind
    else {
        return false;
    };
    let defined = match kind {
        X86CountKind::Popcnt => FlagSet::ALL_X86,
        X86CountKind::Tzcnt | X86CountKind::Lzcnt => FlagSet::CF.union(FlagSet::ZF),
    };

    x86_state_backed_gpr_count_candidate(op)
        && op.x86_hint.is_none()
        && dst.gpr_index().is_some()
        && src.gpr_index().is_some()
        && flags.as_set().difference(defined).is_empty()
}

pub(crate) fn x86_state_backed_gpr_bit_scan_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Bsf { dst, src, .. } | OpKind::Bsr { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_bit_scan_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Bsf {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::Specific(FlagSet::ZF),
        }
        | OpKind::Bsr {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::Specific(FlagSet::ZF),
        } if x86_state_backed_gpr_bit_scan_candidate(op)
            && op.x86_hint.is_none()
            && dst.gpr_index().is_some()
            && src.gpr_index().is_some()
    )
}

pub(crate) fn x86_state_backed_gpr_bit_test_candidate(op: &SmirOp) -> bool {
    let state_index = |index: &SrcOperand| matches!(index, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));

    match &op.kind {
        OpKind::Bt { src, index, .. } => x86_state_backed_arch_gpr(src) || state_index(index),
        OpKind::Bts {
            dst, src, index, ..
        }
        | OpKind::Btr {
            dst, src, index, ..
        }
        | OpKind::Btc {
            dst, src, index, ..
        } => x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src) || state_index(index),
        _ => false,
    }
}

pub(crate) fn x86_state_backed_gpr_bit_test_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let index_valid = |index: &SrcOperand| {
        matches!(index, SrcOperand::Imm(_) | SrcOperand::Imm64(_))
            || matches!(index, SrcOperand::Reg(reg) if arch_gpr(reg))
    };
    let width_valid = |width: &OpWidth| matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64);

    x86_state_backed_gpr_bit_test_candidate(op)
        && op.x86_hint.is_none()
        && match &op.kind {
            OpKind::Bt { src, index, width } => {
                arch_gpr(src) && index_valid(index) && width_valid(width)
            }
            OpKind::Bts {
                dst,
                src,
                index,
                width,
            }
            | OpKind::Btr {
                dst,
                src,
                index,
                width,
            }
            | OpKind::Btc {
                dst,
                src,
                index,
                width,
            } => dst == src && arch_gpr(dst) && index_valid(index) && width_valid(width),
            _ => false,
        }
}

pub(crate) fn x86_state_backed_gpr_crc32_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Crc32C { dst, crc, data, .. }
            if x86_state_backed_arch_gpr(dst)
                || x86_state_backed_arch_gpr(crc)
                || x86_state_backed_arch_gpr(data)
    )
}

pub(crate) fn x86_state_backed_gpr_crc32_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());

    x86_state_backed_gpr_crc32_candidate(op)
        && op.x86_hint.is_none()
        && matches!(
                &op.kind,
                OpKind::Crc32C {
                    dst,
                    crc,
                    data,
                    data_width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
                } if dst == crc && arch_gpr(dst) && arch_gpr(data)
        )
}

pub(crate) fn x86_state_backed_gpr_and_not_candidate(op: &SmirOp) -> bool {
    let state_src2 =
        |src2: &SrcOperand| matches!(src2, SrcOperand::Reg(reg) if x86_state_backed_arch_gpr(reg));

    matches!(
        &op.kind,
        OpKind::AndNot {
            dst, src1, src2, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src1)
            || state_src2(src2)
    )
}

pub(crate) fn x86_state_backed_gpr_and_not_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let defined = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);

    x86_state_backed_gpr_and_not_candidate(op)
        && op.x86_hint.is_none()
        && matches!(
            &op.kind,
            OpKind::AndNot {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width: OpWidth::W32 | OpWidth::W64,
                flags,
            } if arch_gpr(dst)
                && arch_gpr(src1)
                && arch_gpr(src2)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(defined))
        )
}

pub(crate) fn x86_state_backed_gpr_bextr_bzhi_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Bextr {
            dst, src, control, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || x86_state_backed_arch_gpr(control)
    ) || matches!(
        &op.kind,
        OpKind::Bzhi {
            dst, src, index, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || x86_state_backed_arch_gpr(index)
    )
}

pub(crate) fn x86_state_backed_gpr_bextr_bzhi_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let bextr_flags = FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF);
    let bzhi_flags = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);

    if !x86_state_backed_gpr_bextr_bzhi_candidate(op) || op.x86_hint.is_some() {
        return false;
    }

    match &op.kind {
        OpKind::Bextr {
            dst,
            src,
            control,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
        } => {
            arch_gpr(dst)
                && arch_gpr(src)
                && (arch_gpr(control) || matches!(control, VReg::Imm(_)))
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(bextr_flags))
        }
        OpKind::Bzhi {
            dst,
            src,
            index,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
        } => {
            arch_gpr(dst)
                && arch_gpr(src)
                && arch_gpr(index)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(bzhi_flags))
        }
        _ => false,
    }
}

pub(crate) fn x86_state_backed_gpr_bls_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86Bls { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_bls_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let defined = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);

    x86_state_backed_gpr_bls_candidate(op)
        && op.x86_hint.is_none()
        && matches!(
            &op.kind,
            OpKind::X86Bls {
                dst,
                src,
                width: OpWidth::W32 | OpWidth::W64,
                flags,
                ..
            } if arch_gpr(dst)
                && arch_gpr(src)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(defined))
        )
}

pub(crate) fn x86_state_backed_gpr_tbm_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86Tbm { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_tbm_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    let defined = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);

    x86_state_backed_gpr_tbm_candidate(op)
        && op.x86_hint.is_none()
        && matches!(
            &op.kind,
            OpKind::X86Tbm {
                dst,
                src,
                width: OpWidth::W32 | OpWidth::W64,
                flags,
                ..
            } if arch_gpr(dst)
                && arch_gpr(src)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(defined))
        )
}

pub(crate) fn x86_state_backed_gpr_adx_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86Adx {
            dst, src1, src2, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src1)
            || x86_state_backed_arch_gpr(src2)
    )
}

pub(crate) fn x86_state_backed_gpr_adx_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());

    let OpKind::X86Adx {
        dst,
        src1,
        src2,
        width: OpWidth::W32 | OpWidth::W64,
        kind,
        flags,
    } = &op.kind
    else {
        return false;
    };
    let output = match kind {
        X86AdxKind::Adcx => FlagSet::CF,
        X86AdxKind::Adox => FlagSet::OF,
    };

    x86_state_backed_gpr_adx_candidate(op)
        && op.x86_hint.is_none()
        && arch_gpr(dst)
        && arch_gpr(src1)
        && arch_gpr(src2)
        && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(output))
}

pub(crate) fn x86_state_backed_gpr_pdep_pext_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Pdep {
            dst, src, mask, ..
        }
        | OpKind::Pext {
            dst, src, mask, ..
        } if x86_state_backed_arch_gpr(dst)
            || x86_state_backed_arch_gpr(src)
            || x86_state_backed_arch_gpr(mask)
    )
}

pub(crate) fn x86_state_backed_gpr_pdep_pext_valid(op: &SmirOp) -> bool {
    let arch_gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());

    x86_state_backed_gpr_pdep_pext_candidate(op)
        && op.x86_hint.is_none()
        && matches!(
            &op.kind,
            OpKind::Pdep {
                dst,
                src,
                mask,
                width: OpWidth::W32 | OpWidth::W64,
            }
            | OpKind::Pext {
                dst,
                src,
                mask,
                width: OpWidth::W32 | OpWidth::W64,
            } if arch_gpr(dst) && arch_gpr(src) && arch_gpr(mask)
        )
}

pub(crate) fn x86_state_backed_gpr_bswap_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Bswap { dst, src, .. }
            if x86_state_backed_arch_gpr(dst) || x86_state_backed_arch_gpr(src)
    )
}

pub(crate) fn x86_state_backed_gpr_bswap_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Bswap {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src: VReg::Arch(ArchReg::X86(src)),
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if x86_state_backed_gpr_bswap_candidate(op)
            && op.x86_hint.is_none()
            && dst.gpr_index().is_some()
            && src.gpr_index().is_some()
    )
}

pub(crate) fn x86_state_backed_gpr_xchg_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Xchg { reg1, reg2, .. }
            if x86_state_backed_arch_gpr(reg1) || x86_state_backed_arch_gpr(reg2)
    )
}

pub(crate) fn x86_state_backed_gpr_xchg_valid(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::Xchg {
            reg1: VReg::Arch(ArchReg::X86(reg1)),
            reg2: VReg::Arch(ArchReg::X86(reg2)),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if x86_state_backed_gpr_xchg_candidate(op)
            && op.x86_hint.is_none()
            && reg1.gpr_index().is_some()
            && reg2.gpr_index().is_some()
    )
}

/// An `X86Lea` whose destination or whose effective-address operands name a
/// state-backed GPR (guest RSP/RBP, or an APX EGPR). Under the native identity
/// register map those values live in the `GuestRegs` file rather than in the
/// host register of the same name, so the ordinary LEA lowering would compute
/// against the host frame pointer / host stack pointer.
pub(crate) fn x86_state_backed_gpr_lea_candidate(op: &SmirOp) -> bool {
    matches!(
        &op.kind,
        OpKind::X86Lea { dst, addr, .. }
            if x86_state_backed_arch_gpr(dst)
                || addr.regs().iter().any(x86_state_backed_arch_gpr)
    )
}

/// The exact `X86Lea` shapes the state-backed lowering reconstructs from the
/// `GuestRegs` snapshot. LEA never accesses memory and never updates flags, so
/// only forms whose effective address is a pure GPR expression are admitted:
/// segment-relative, RIP-relative, absolute, `GpRel`, and explicit addr32
/// addresses are excluded and fail closed.
pub(crate) fn x86_state_backed_gpr_lea_valid(op: &SmirOp) -> bool {
    let OpKind::X86Lea { dst, addr, width } = &op.kind else {
        return false;
    };
    if !x86_state_backed_gpr_lea_candidate(op)
        || op.x86_hint.is_some()
        || !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
    {
        return false;
    }
    let gpr =
        |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some());
    if !gpr(dst) {
        return false;
    }
    match addr {
        Address::Direct(base) => gpr(base),
        Address::BaseOffset { base, offset, .. } => gpr(base) && i32::try_from(*offset).is_ok(),
        Address::BaseIndexScale {
            base, index, scale, ..
        } => {
            base.as_ref().is_none_or(|base| gpr(base))
                && gpr(index)
                && matches!(scale, 1 | 2 | 4 | 8)
        }
        _ => false,
    }
}

// ============================================================================
// x86_64 Condition Codes
// ============================================================================

/// x86_64 condition codes for Jcc/SETcc/CMOVcc
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Cond {
    O = 0x0,  // Overflow
    No = 0x1, // Not overflow
    B = 0x2,  // Below (unsigned <), aka C/NAE
    Ae = 0x3, // Above or equal (unsigned >=), aka NC/NB
    E = 0x4,  // Equal, aka Z
    Ne = 0x5, // Not equal, aka NZ
    Be = 0x6, // Below or equal (unsigned <=), aka NA
    A = 0x7,  // Above (unsigned >), aka NBE
    S = 0x8,  // Sign (negative)
    Ns = 0x9, // Not sign (positive or zero)
    P = 0xA,  // Parity even
    Np = 0xB, // Parity odd
    L = 0xC,  // Less (signed <), aka NGE
    Ge = 0xD, // Greater or equal (signed >=), aka NL
    Le = 0xE, // Less or equal (signed <=), aka NG
    G = 0xF,  // Greater (signed >), aka NLE
}

impl X86Cond {
    /// Convert from SMIR Condition
    pub fn from_condition(cond: Condition) -> Self {
        match cond {
            Condition::Eq => X86Cond::E,
            Condition::Ne => X86Cond::Ne,
            Condition::Ult => X86Cond::B,
            Condition::Ule => X86Cond::Be,
            Condition::Ugt => X86Cond::A,
            Condition::Uge => X86Cond::Ae,
            Condition::Slt => X86Cond::L,
            Condition::Sle => X86Cond::Le,
            Condition::Sgt => X86Cond::G,
            Condition::Sge => X86Cond::Ge,
            Condition::Negative => X86Cond::S,
            Condition::Positive => X86Cond::Ns,
            Condition::Overflow => X86Cond::O,
            Condition::NoOverflow => X86Cond::No,
            Condition::Parity => X86Cond::P,
            Condition::NoParity => X86Cond::Np,
            Condition::Always => X86Cond::E, // Shouldn't be used for conditional ops
        }
    }

    /// Invert the condition
    pub fn invert(self) -> Self {
        match self {
            X86Cond::O => X86Cond::No,
            X86Cond::No => X86Cond::O,
            X86Cond::B => X86Cond::Ae,
            X86Cond::Ae => X86Cond::B,
            X86Cond::E => X86Cond::Ne,
            X86Cond::Ne => X86Cond::E,
            X86Cond::Be => X86Cond::A,
            X86Cond::A => X86Cond::Be,
            X86Cond::S => X86Cond::Ns,
            X86Cond::Ns => X86Cond::S,
            X86Cond::P => X86Cond::Np,
            X86Cond::Np => X86Cond::P,
            X86Cond::L => X86Cond::Ge,
            X86Cond::Ge => X86Cond::L,
            X86Cond::Le => X86Cond::G,
            X86Cond::G => X86Cond::Le,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ShiftCount {
    One,
    Imm(u8),
    Cl,
}

#[derive(Clone, Copy, Debug)]
enum ShiftRegOp {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sar,
}

#[derive(Clone, Copy, Debug)]
enum BitTestRegOp {
    Test,
    Set,
    Reset,
    Complement,
}

impl BitTestRegOp {
    fn name(self) -> &'static str {
        match self {
            Self::Test => "Bt",
            Self::Set => "Bts",
            Self::Reset => "Btr",
            Self::Complement => "Btc",
        }
    }

    fn register_opcode(self) -> u8 {
        match self {
            Self::Test => 0xA3,
            Self::Set => 0xAB,
            Self::Reset => 0xB3,
            Self::Complement => 0xBB,
        }
    }

    fn immediate_digit(self) -> u8 {
        match self {
            Self::Test => 4,
            Self::Set => 5,
            Self::Reset => 6,
            Self::Complement => 7,
        }
    }
}

impl ShiftRegOp {
    fn digit(self) -> u8 {
        match self {
            ShiftRegOp::Rol => 0,
            ShiftRegOp::Ror => 1,
            ShiftRegOp::Rcl => 2,
            ShiftRegOp::Rcr => 3,
            ShiftRegOp::Shl => 4,
            ShiftRegOp::Shr => 5,
            ShiftRegOp::Sar => 7,
        }
    }

    fn name(self) -> &'static str {
        match self {
            ShiftRegOp::Rol => "Rol",
            ShiftRegOp::Ror => "Ror",
            ShiftRegOp::Rcl => "Rcl",
            ShiftRegOp::Rcr => "Rcr",
            ShiftRegOp::Shl => "Shl",
            ShiftRegOp::Shr => "Shr",
            ShiftRegOp::Sar => "Sar",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum VecEncodingKind {
    Vex,
    Evex,
}

#[derive(Clone, Copy, Debug)]
struct VecEncoding {
    kind: VecEncodingKind,
    map: X86VecMap,
    pp: X86SsePrefix,
    opcode: u8,
    width: VecWidth,
    w: bool,
}

// ============================================================================
// x86_64 Instruction Emitter
// ============================================================================

/// x86_64 instruction emitter - handles raw instruction encoding
pub struct X86Emitter<'a> {
    code: &'a mut CodeBuffer,
}

// ============================================================================
// x86_64 Lowerer
// ============================================================================

/// x86_64 code generator
pub struct X86_64Lowerer {
    /// Code buffer
    code: CodeBuffer,

    /// Register allocator
    regalloc: RegAlloc,

    /// Block offsets in generated code
    block_offsets: HashMap<BlockId, usize>,

    /// Relocations to apply
    relocations: Vec<Relocation>,

    /// Pending jumps to fix up (source offset, target block, reloc kind)
    pending_jumps: Vec<(usize, BlockId, RelocKind)>,

    /// Guest base address used for PC-relative fixups
    guest_base: GuestAddr,

    /// Guest PC for blocks
    block_guest_pcs: HashMap<BlockId, GuestAddr>,

    /// Exact x86 source-instruction provenance copied from the function being
    /// lowered. Only byte-level validated replay families may consume it.
    x86_instruction_bytes: HashMap<(BlockId, GuestAddr), X86InstructionBytes>,

    /// Native-exit blocks (JIT general-exit ABI): block-id ⇒ resume guest PC.
    /// A block in this map is lowered as an EXIT STUB that records `exit_pc`
    /// (via the state pointer saved in the block frame) and returns to the trampoline, instead
    /// of lowering its ops/terminator. Lets the JIT run a hot loop natively and
    /// hand control back to the interpreter at the loop-exit address. Set via
    /// [`X86_64Lowerer::set_native_exits`] before `lower_function`.
    native_exits: std::collections::HashMap<BlockId, u64>,

    /// Native-exit branch edges (source block, target block) => resume guest PC.
    /// Unlike `native_exits`, these do not replace the target block. They only
    /// turn the selected terminator edge into an exit stub, so another path can
    /// still enter and execute the same target block normally.
    native_exit_edges: std::collections::HashMap<(BlockId, BlockId), u64>,

    /// Folded condition for the current block's `CondBranch` terminator.
    /// Set by `lower_block` when the block's last op is a `TestCondition`
    /// feeding the terminator's `cond` vreg: the SETcc-into-a-vreg + `test`
    /// round-trip is elided and the terminator emits `Jcc<cond>` directly off
    /// the live guest flags (the body's last flag-setting op). This avoids
    /// materializing the condition into a host register — which, under the 1:1
    /// identity reg map where every GPR is guest-live, would clobber guest
    /// state (no free scratch). Also faster: one `jcc` instead of setcc+test+jnz.
    pending_cond: Option<Condition>,

    /// Whether to adjust PC-relative displacements for code layout
    pcrel_adjust: bool,

    /// Emit guarded instruction-fault exits that restart the current guest PC
    /// in the interpreter. These exits require the native JIT trampoline's
    /// GuestRegs frame and must remain disabled for standalone lowerer users.
    jit_fault_deopt_guards: bool,

    /// Materialize `LEA` with an explicit guest PC base as its absolute guest
    /// address instead of a native RIP-relative relocation. Native JIT code is
    /// allocated independently of guest virtual addresses, while x86 `LEA`
    /// observes only the numeric effective address and performs no memory access.
    guest_pcrel_lea_immediates: bool,

    /// When set, `Load`/`Store` ops are lowered as calls back into the guest
    /// MMU (via the function pointers in `GuestRegs.load_fn`/`store_fn`) with a
    /// full guest-register spill/reload and a per-op fault-bail stub, instead of
    /// the direct-host-pointer accesses (which assume a flat host-mapped guest
    /// address space). Enables JIT of memory-touching hot regions under paging.
    mem_helpers: bool,

    /// Preserve the complete architectural ZMM/K file around MMU helper calls.
    /// Required when a region mixes admitted vector operations with scalar
    /// guest-memory loads/stores because the platform ABI makes vector/opmask
    /// registers caller-saved.
    preserve_vector_mem_helpers: bool,

    /// Synchronize the complete architectural ZMM/K file through `GuestRegs`
    /// around interpreter callouts. Unlike MMU helpers, the callee may
    /// semantically modify vector state, so the post-call reload consumes the
    /// helper-updated state rather than merely restoring the pre-call snapshot.
    preserve_vector_call_helpers: bool,

    /// Preserve the complete architectural ZMM/K file around system helpers
    /// such as the deterministic guest CPUID evaluator. These helpers do not
    /// modify vector state, but the platform ABI permits them to clobber the
    /// host registers carrying it.
    preserve_vector_system_helpers: bool,

    /// Preserve only YMM0-YMM15 around helper calls for an AVX-YMM16-safe
    /// replay region. Upper ZMM halves and K0-K7 remain authoritative in
    /// `GuestRegs`.
    avx_ymm16_vector_state: bool,

    /// Whether physical host vector registers also carry architectural state.
    /// State-backed vector operations synchronize their inputs and outputs at
    /// each boundary while this is set.
    native_vector_state_active: bool,

    /// Spill MM0-MM7 and execute host-only EMMS before every Rust helper call,
    /// then reload the complete MMX file from `GuestRegs` after the call. This
    /// is required because MMX aliases the host x87 register/tag file.
    preserve_mmx_helpers: bool,

    /// Use KMOVW instead of KMOVQ at vector helper boundaries. This is enabled
    /// only for admitted AVX512ER regions whose masks contain at most 16
    /// observable bits; partial stores preserve upper architectural K bits.
    narrow_vector_opmask_helpers: bool,

    /// When set, a `Terminator::Call` lowers to a runtime call-out (the
    /// `GuestRegs.call_fn` helper) that runs the callee in the interpreter and
    /// resumes native execution at the call's continuation block, instead of
    /// being treated as a region-ending native exit. State-backed memory target
    /// forms first read the 8-byte target through the MMU helper. The
    /// lift-through-calls path.
    call_helpers: bool,

    /// Code offsets of the disp32 field in each epilogue's `lea rsp, [rsp+frame]`
    /// frame-teardown placeholder. The frame size is not final until every block
    /// is lowered, so each epilogue emits a forced-disp32 LEA and is backpatched
    /// with the final frame size after lowering. Using the frame size (not the
    /// guest-clobberable RBP) keeps the host return path off guest control.
    epilogue_stack_patches: Vec<usize>,
}

impl Default for X86_64Lowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLowerer for X86_64Lowerer {
    fn target_arch(&self) -> &'static str {
        "x86_64"
    }

    fn lower_function(&mut self, func: &SmirFunction) -> Result<LowerResult, LowerError> {
        // Reset state
        self.code.clear();
        #[cfg(feature = "smir-jit")]
        if self.mem_helpers
            && !crate::smir::lower::runtime::x86_jit_vsib_function_virtuals_closed(func)
        {
            return Err(LowerError::InvalidOperand {
                op: "EVEX VSIB memory".to_string(),
                operand: "an elided VSIB virtual escapes through a phi, terminator, or another instruction/block".to_string(),
            });
        }
        #[cfg(feature = "smir-jit")]
        if self.mem_helpers
            && !crate::smir::lower::runtime::x86_jit_scalar_alu_function_virtuals_closed(func)
        {
            return Err(LowerError::InvalidOperand {
                op: "scalar ALU memory".to_string(),
                operand: "an elided scalar virtual escapes through a phi, terminator, or another instruction/block".to_string(),
            });
        }
        self.regalloc.reset();
        self.block_offsets.clear();
        self.relocations.clear();
        self.pending_jumps.clear();
        self.guest_base = func.guest_range.0;
        self.pending_cond = None;
        self.epilogue_stack_patches.clear();
        self.block_guest_pcs = func
            .blocks
            .iter()
            .map(|block| (block.id, block.guest_pc))
            .collect();
        self.x86_instruction_bytes = func.x86_instruction_bytes.clone();

        let entry_offset = self.code.position();

        // First pass: allocate registers and compute frame size
        // For now, use simple approach - just lower blocks in order

        // Emit prologue: `push rbp; mov rbp, rsp`, then a FIXED-SIZE region
        // (NOP-filled) reserved for the callee-saved saves + frame allocation.
        // Those depend on register allocation, which isn't known until the body
        // is lowered, so the region is backpatched after `fixup_jumps`. A fixed
        // size keeps every body offset / jump target stable. The original code
        // left this prologue as a never-finished stub, making it asymmetric with
        // `emit_epilogue` (which tears down callee-saved + frame) — that
        // corrupted the stack and made `ret` jump to garbage.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(PhysReg::Rbp);
            emitter.emit_mov_rr(PhysReg::Rbp, PhysReg::Rsp, OpWidth::W64);
        }
        const PROLOGUE_RESERVE: usize = 16;
        let prologue_patch_at = self.code.position();
        for _ in 0..PROLOGUE_RESERVE {
            self.code.emit_u8(0x90); // NOP placeholder, backpatched below
        }

        // Lower entry block first
        if let Some(entry_block) = func.get_block(func.entry) {
            self.lower_block(entry_block)?;
        }

        // Lower remaining blocks
        for block in &func.blocks {
            if block.id != func.entry {
                self.lower_block(block)?;
            }
        }

        // Fix up all jumps
        self.fixup_jumps()?;

        // Backpatch the reserved prologue region now that the frame size is
        // final: emit just the frame allocation, mirroring `emit_epilogue`'s
        // teardown. Callee-saved guest regs are intentionally NOT pushed (the
        // block owns all GPRs; the enter_native shim preserves host state), so
        // guest writes to RBX/R12-R15 survive the call.
        {
            let mut tmp = CodeBuffer::new();
            {
                let mut e = X86Emitter::new(&mut tmp);
                let frame = self.regalloc.frame_size();
                if frame > 0 {
                    // Flag-preserving frame allocation: LEA, not SUB. The entry
                    // shim sets the guest's RFLAGS (incl. CF) before the block;
                    // a `sub rsp,frame` here would clobber CF before the body's
                    // ADC/SBB read it as a carry-in.
                    e.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -(frame as i32));
                }
            }
            let bytes = tmp.data().to_vec();
            assert!(
                bytes.len() <= PROLOGUE_RESERVE,
                "prologue setup ({} bytes) exceeds reserved region ({})",
                bytes.len(),
                PROLOGUE_RESERVE
            );
            for (i, &b) in bytes.iter().enumerate() {
                self.code.data[prologue_patch_at + i] = b;
            }
            // Any remaining reserved bytes stay 0x90 (NOP) and execute harmlessly.
        }

        // Backpatch each epilogue's `lea rsp, [rsp + frame]` disp32 with the now-
        // final frame size, mirroring the prologue's `lea rsp, [rsp - frame]`.
        {
            let frame = self.regalloc.frame_size() as i32;
            let disp = frame.to_le_bytes();
            for &patch_at in &self.epilogue_stack_patches {
                self.code.data[patch_at..patch_at + 4].copy_from_slice(&disp);
            }
        }

        let code_size = self.code.len();

        Ok(LowerResult {
            code_size,
            entry_offset,
            block_offsets: self.block_offsets.clone(),
            relocations: self.relocations.clone(),
            stack_size: self.regalloc.frame_size(),
        })
    }

    fn code_buffer(&self) -> &CodeBuffer {
        &self.code
    }

    fn finalize(&mut self) -> Result<Vec<u8>, LowerError> {
        Ok(self.code.data().to_vec())
    }
}

// ============================================================================
// Tests
// ============================================================================
