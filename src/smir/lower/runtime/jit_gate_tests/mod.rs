//! jit_gate_tests.rs

use super::*;

// ---- split submodules ----
#[cfg(test)]
mod aarch64;
#[cfg(test)]
mod ac;
#[cfg(test)]
mod addr32_memory;
#[cfg(test)]
mod aes_memory_source;
#[cfg(test)]
mod ah_flags;
#[cfg(test)]
mod apx_bmi2_shift;
#[cfg(test)]
mod atomic_rmw;
#[cfg(test)]
mod bit_offset;
#[cfg(test)]
mod bswap_undefined;
#[cfg(test)]
mod byte_xchg;
#[cfg(test)]
mod cli;
#[cfg(test)]
mod clts;
#[cfg(test)]
mod cmpccxadd;
#[cfg(test)]
mod cmpxchg;
#[cfg(test)]
mod cpuid;
#[cfg(test)]
mod descriptor_table;
#[cfg(test)]
mod enter;
#[cfg(test)]
mod evex;
mod evex_alignr_memory_source;
#[cfg(test)]
mod evex_bf16_memory_source;
#[cfg(test)]
mod evex_broadcast_interleave_memory_source;
#[cfg(test)]
mod evex_broadcast_logic_memory_source;
#[cfg(test)]
mod evex_broadcast_memory_source;
#[cfg(test)]
mod evex_bw_immediate_replay;
#[cfg(test)]
mod evex_bw_shuffle_madd_memory_source;
#[cfg(test)]
mod evex_bw_shuffle_madd_replay;
#[cfg(test)]
mod evex_chunk_extract_replay;
#[cfg(test)]
mod evex_chunk_insert_memory_source;
#[cfg(test)]
mod evex_chunk_insert_replay;
#[cfg(test)]
mod evex_chunk_shuffle_memory_source;
#[cfg(test)]
mod evex_chunk_shuffle_replay;
#[cfg(test)]
mod evex_compress_memory_destination;
#[cfg(test)]
mod evex_dbpsadbw_memory_source;
#[cfg(test)]
mod evex_duplicate_move_memory_source;
#[cfg(test)]
mod evex_expand_memory_source;
mod evex_extract_memory_destination;
#[cfg(test)]
mod evex_fixup_imm_memory_source;
#[cfg(test)]
mod evex_fma3_packed_fp16_memory_source;
#[cfg(test)]
mod evex_fma3_packed_memory_source;
#[cfg(test)]
mod evex_fma3_register_replay;
#[cfg(test)]
mod evex_fma3_scalar_memory_source;
mod evex_four_dot_product_memory_source;
mod evex_four_fma_memory_source;
#[cfg(test)]
mod evex_fp16_complex_memory_source;
#[cfg(test)]
mod evex_fp16_flag_compare_replay;
#[cfg(test)]
mod evex_fp16_narrow_memory_destination;
#[cfg(test)]
mod evex_fp16_narrow_replay;
#[cfg(test)]
mod evex_fp16_packed_arithmetic_memory_source;
#[cfg(test)]
mod evex_fp16_packed_arithmetic_replay;
#[cfg(test)]
mod evex_fp16_scalar_replay;
#[cfg(test)]
mod evex_fp16_widen_replay;
#[cfg(test)]
mod evex_fp32_fp64_convert_replay;
#[cfg(test)]
mod evex_fp32_fp64_flag_compare_replay;
#[cfg(test)]
mod evex_fp_arithmetic_memory_source;
#[cfg(test)]
mod evex_fp_class_memory_source;
#[cfg(test)]
mod evex_fp_class_replay;
#[cfg(test)]
mod evex_fp_compare_memory_source;
#[cfg(test)]
mod evex_fp_compare_replay;
#[cfg(test)]
mod evex_fp_flag_compare_memory_source;
#[cfg(test)]
mod evex_fp_interleave_memory_source;
#[cfg(test)]
mod evex_fp_shuffle_memory_source;
#[cfg(test)]
mod evex_fp_sqrt_replay;
mod evex_full_permute_memory_source;
mod evex_gfni_affine_memory_source;
mod evex_gfni_multiply_memory_source;
#[cfg(test)]
mod evex_gfni_replay;
#[cfg(test)]
mod evex_gpr_broadcast_replay;
#[cfg(test)]
mod evex_half_move_memory_source;
#[cfg(test)]
mod evex_high_low_move_replay;
#[cfg(test)]
mod evex_ifma52_memory_source;
#[cfg(test)]
mod evex_int32_to_fp64_ignored_er;
#[cfg(test)]
mod evex_integer_arithmetic_memory_source;
#[cfg(test)]
mod evex_integer_interleave_memory_source;
#[cfg(test)]
mod evex_integer_mask_memory_source;
#[cfg(test)]
mod evex_integer_minmax_memory_source;
#[cfg(test)]
mod evex_integer_multiply_memory_source;
#[cfg(test)]
mod evex_integer_narrow_memory_destination;
#[cfg(test)]
mod evex_integer_pack_memory_source;
#[cfg(test)]
mod evex_integer_unary_memory_source;
#[cfg(test)]
mod evex_lane_shuffle_memory_source;
#[cfg(test)]
mod evex_lane_shuffle_replay;
#[cfg(test)]
mod evex_logic_memory_source;
#[cfg(test)]
mod evex_mask_blend_memory_source;
#[cfg(test)]
mod evex_mask_blend_replay;
#[cfg(test)]
mod evex_mask_broadcast_replay;
#[cfg(test)]
mod evex_mask_to_vector_replay;
#[cfg(test)]
mod evex_masked_logic_memory_source;
#[cfg(test)]
mod evex_move_replay;
#[cfg(test)]
mod evex_movntdqa_memory_source;
#[cfg(test)]
mod evex_multishift_memory_source;
#[cfg(test)]
mod evex_packed_abs_memory_source;
#[cfg(test)]
mod evex_packed_compare_replay;
#[cfg(test)]
mod evex_packed_convert_memory_source;
#[cfg(test)]
mod evex_packed_extend_memory_source;
#[cfg(test)]
mod evex_packed_extend_replay;
#[cfg(test)]
mod evex_packed_fp16_convert_memory_source;
#[cfg(test)]
mod evex_packed_fp_unary_memory_source;
#[cfg(test)]
mod evex_packed_funnel_shift_memory_source;
#[cfg(test)]
mod evex_packed_move_memory_source;
#[cfg(test)]
mod evex_packed_rotate_memory_source;
#[cfg(test)]
mod evex_packed_rotate_replay;
#[cfg(test)]
mod evex_packed_shift_imm_memory_source;
#[cfg(test)]
mod evex_packed_variable_shift_memory_source;
#[cfg(test)]
mod evex_permute_replay;
#[cfg(test)]
mod evex_psadbw_memory_source;
#[cfg(test)]
mod evex_range_memory_source;
#[cfg(test)]
mod evex_scalar_fp_arithmetic_memory_source;
#[cfg(test)]
mod evex_scalar_fp_compare_memory_source;
#[cfg(test)]
mod evex_scalar_fp_convert_memory_source;
#[cfg(test)]
mod evex_scalar_fp_convert_replay;
#[cfg(test)]
mod evex_scalar_fp_to_int_memory_source;
#[cfg(test)]
mod evex_scalar_fp_to_int_replay;
#[cfg(test)]
mod evex_scalar_fp_unary_memory_source;
#[cfg(test)]
mod evex_scalar_insert_memory_source;
#[cfg(test)]
mod evex_scalar_int_to_fp_memory_source;
#[cfg(test)]
mod evex_scalar_int_to_fp_replay;
#[cfg(test)]
mod evex_scalar_integer_move_replay;
#[cfg(test)]
mod evex_scalar_lane_transfer_replay;
#[cfg(test)]
mod evex_scalar_move_memory_source;
#[cfg(test)]
mod evex_scalar_move_replay;
#[cfg(test)]
mod evex_scale_f_memory_source;
#[cfg(test)]
mod evex_shared_count_shift_memory_source;
#[cfg(test)]
mod evex_ternary_logic_memory_source;
mod evex_two_table_permute_memory_source;
mod evex_variable_permute_memory_source;
#[cfg(test)]
mod evex_vector_align_memory_source;
#[cfg(test)]
mod evex_vector_align_replay;
#[cfg(test)]
mod evex_vector_to_mask_replay;
#[cfg(test)]
mod evex_vp2intersect_memory_source;
#[cfg(test)]
mod evex_vp2intersect_replay;
#[cfg(test)]
mod evex_vpclmulqdq_replay;
#[cfg(test)]
mod evex_vpshufbitqmb_memory_source;
#[cfg(test)]
mod far_call;
#[cfg(test)]
mod far_jump;
#[cfg(test)]
mod far_return;
#[cfg(test)]
mod fast_system_transfer;
#[cfg(test)]
mod fp_arithmetic_replay;
#[cfg(test)]
mod fp_binary;
#[cfg(test)]
mod fsgsbase;
#[cfg(test)]
mod gate;
#[cfg(test)]
mod invlpg;
#[cfg(test)]
mod invpcid;
#[cfg(test)]
mod io;
#[cfg(test)]
mod leave;
#[cfg(test)]
mod legacy_aes_replay;
#[cfg(test)]
mod legacy_alignr_replay;
#[cfg(test)]
mod legacy_blend_replay;
#[cfg(test)]
mod legacy_dot_product_replay;
#[cfg(test)]
mod legacy_fp_flag_compare_replay;
#[cfg(test)]
mod legacy_fp_round_replay;
#[cfg(test)]
mod legacy_gfni_replay;
#[cfg(test)]
mod legacy_high_byte_replay;
#[cfg(test)]
mod legacy_insertps_replay;
#[cfg(test)]
mod legacy_lane_shuffle_replay;
mod legacy_mov_mask_stack_destination_replay;
mod legacy_movd_q_stack_replay;
#[cfg(test)]
mod legacy_packed_extend_replay;
#[cfg(test)]
mod legacy_packed_fp_convert_replay;
#[cfg(test)]
mod legacy_packed_shift_replay;
#[cfg(test)]
mod legacy_packed_string_replay;
#[cfg(test)]
mod legacy_pclmulqdq_replay;
#[cfg(test)]
mod legacy_ptest_replay;
#[cfg(test)]
mod legacy_same_width_movx;
#[cfg(test)]
mod legacy_scalar_extract_replay;
#[cfg(test)]
mod legacy_scalar_fp_convert_replay;
#[cfg(test)]
mod legacy_scalar_insert_replay;
mod legacy_scalar_xmm_movq_replay;
#[cfg(test)]
mod legacy_sha_replay;
#[cfg(test)]
mod legacy_vex_fp_compare_replay;
#[cfg(test)]
mod legacy_vex_fp_estimate_replay;
#[cfg(test)]
mod legacy_vex_fp_horizontal_addsub_replay;
#[cfg(test)]
mod legacy_vex_fp_shuffle_replay;
#[cfg(test)]
mod legacy_vex_fp_sqrt_replay;
#[cfg(test)]
mod legacy_vex_high_low_move_replay;
#[cfg(test)]
mod legacy_vex_scalar_move_replay;
#[cfg(test)]
mod legacy_widening_dword_multiply_replay;
#[cfg(test)]
mod lmsw;
#[cfg(test)]
mod maskmovdqu;
#[cfg(test)]
mod mem_rmw_flagless;
#[cfg(test)]
mod mem_state_compare;
#[cfg(test)]
mod mmx;
#[cfg(test)]
mod mmx_maskmov;
#[cfg(test)]
mod mmx_memory;
#[cfg(test)]
mod mmx_memory_source;
#[cfg(test)]
mod mmx_xmm_transfer;
#[cfg(test)]
mod monitor_mwait;
#[cfg(test)]
mod movbe;
#[cfg(test)]
mod msr;
#[cfg(test)]
mod mxcsr_store;
#[cfg(test)]
mod non_memory_prefix_replay;
#[cfg(test)]
mod opmask;
#[cfg(test)]
mod ordinary_stack;
#[cfg(test)]
mod pkru;
#[cfg(test)]
mod pmc;
#[cfg(test)]
mod push_flags;
#[cfg(test)]
mod push_value;
#[cfg(test)]
mod random_state;
#[cfg(test)]
mod read_control;
#[cfg(test)]
mod read_debug;
#[cfg(test)]
mod require_apx;
#[cfg(test)]
mod reserved_nop;
#[cfg(test)]
mod scalar_alu_immediate;
#[cfg(test)]
mod selector;
#[cfg(test)]
mod selector_query;
#[cfg(test)]
mod selector_verify;
#[cfg(test)]
mod serialize;
#[cfg(test)]
mod shift_group6;
#[cfg(test)]
mod smsw;
#[cfg(test)]
mod sqrt;
#[cfg(test)]
mod sse4a;
#[cfg(test)]
mod stack_flags;
#[cfg(test)]
mod state_alu;
#[cfg(test)]
mod state_lea;
#[cfg(test)]
mod state_mem_load;
#[cfg(test)]
mod state_multiply;
#[cfg(test)]
mod sti;
#[cfg(test)]
mod swapgs;
#[cfg(test)]
mod tbm;
#[cfg(test)]
mod timing;
#[cfg(test)]
mod trap;
#[cfg(test)]
mod vbit_select;
#[cfg(test)]
mod vector;
#[cfg(test)]
mod vector_compare;
#[cfg(test)]
mod vex_alignr_memory_source;
#[cfg(test)]
mod vex_alignr_replay;
#[cfg(test)]
mod vex_apx_bmi_memory;
#[cfg(test)]
mod vex_apx_mulx;
#[cfg(test)]
mod vex_apx_mulx_memory;
#[cfg(test)]
mod vex_bmi2_shift;
#[cfg(test)]
mod vex_bmi2_shift_memory;
#[cfg(test)]
mod vex_broadcast_memory_source;
#[cfg(test)]
mod vex_byte_shuffle_memory_source;
#[cfg(test)]
mod vex_chunk_extract_replay;
#[cfg(feature = "smir-jit")]
mod vex_cross_lane_128_memory_source;
#[cfg(test)]
mod vex_cross_lane_128_replay;
#[cfg(test)]
mod vex_duplicate_move_memory_source;
#[cfg(test)]
mod vex_estimate_memory_source;
#[cfg(test)]
mod vex_extract_memory_destination;
mod vex_fma3_memory_source;
#[cfg(test)]
mod vex_fma3_replay;
#[cfg(test)]
mod vex_fma3_scalar_memory_source;
#[cfg(test)]
mod vex_fma4_memory_source;
#[cfg(test)]
mod vex_fma4_replay;
#[cfg(test)]
mod vex_fp16_narrow_memory_destination;
#[cfg(test)]
mod vex_fp16_narrow_replay;
#[cfg(test)]
mod vex_fp16_widen_replay;
#[cfg(test)]
mod vex_fp32_fp64_convert_replay;
#[cfg(test)]
mod vex_fp_arithmetic_memory_source;
#[cfg(test)]
mod vex_fp_compare_memory_source;
#[cfg(test)]
mod vex_fp_dot_product_memory_source;
#[cfg(test)]
mod vex_fp_dot_product_replay;
#[cfg(test)]
mod vex_fp_flag_compare_memory_source;
#[cfg(test)]
mod vex_fp_flag_compare_replay;
#[cfg(test)]
mod vex_fp_logic_replay;
#[cfg(test)]
mod vex_fp_round_replay;
#[cfg(test)]
mod vex_fp_shuffle_memory_source;
#[cfg(test)]
mod vex_gfni_memory_source;
#[cfg(test)]
mod vex_gfni_replay;
#[cfg(test)]
mod vex_half_move_memory_source;
#[cfg(test)]
mod vex_horizontal_integer_memory_source;
#[cfg(test)]
mod vex_ifma52_replay;
#[cfg(test)]
mod vex_immediate_blend_memory_source;
#[cfg(test)]
mod vex_immediate_blend_replay;
#[cfg(test)]
mod vex_immediate_permute_memory_source;
#[cfg(test)]
mod vex_immediate_permute_replay;
#[cfg(test)]
mod vex_integer_arithmetic_memory_source;
#[cfg(test)]
mod vex_integer_compare_memory_source;
#[cfg(test)]
mod vex_integer_dot_ext_replay;
#[cfg(test)]
mod vex_integer_dot_replay;
#[cfg(test)]
mod vex_integer_minmax_memory_source;
#[cfg(test)]
mod vex_integer_multiply_add_memory_source;
#[cfg(test)]
mod vex_integer_pack_memory_source;
#[cfg(test)]
mod vex_interleave_memory_source;
#[cfg(test)]
mod vex_lane_shuffle_memory_source;
#[cfg(test)]
mod vex_lane_shuffle_replay;
#[cfg(test)]
mod vex_logic_memory_source;
#[cfg(test)]
mod vex_masked_memory;
#[cfg(test)]
mod vex_mov_mask_stack_destination_replay;
#[cfg(test)]
mod vex_movntdqa_memory_source;
#[cfg(test)]
mod vex_mpsadbw_memory_source;
#[cfg(test)]
mod vex_ne_convert_memory_source;
#[cfg(test)]
mod vex_ne_convert_replay;
#[cfg(test)]
mod vex_pabs_memory_source;
mod vex_packed_convert_memory_source;
#[cfg(test)]
mod vex_packed_extend_memory_source;
#[cfg(test)]
mod vex_packed_extend_replay;
#[cfg(test)]
mod vex_packed_move_replay;
#[cfg(test)]
mod vex_packed_string_memory_source;
#[cfg(test)]
mod vex_packed_string_replay;
#[cfg(test)]
mod vex_pavg_memory_source;
#[cfg(test)]
mod vex_phminposuw_memory_source;
#[cfg(test)]
mod vex_pmul_high_word_memory_source;
#[cfg(test)]
mod vex_pmul_low_memory_source;
#[cfg(test)]
mod vex_pmulhrsw_memory_source;
#[cfg(test)]
mod vex_psadbw_memory_source;
#[cfg(test)]
mod vex_psign_memory_source;
#[cfg(test)]
mod vex_ptest_memory_source;
#[cfg(test)]
mod vex_ptest_replay;
#[cfg(test)]
mod vex_register_broadcast_replay;
#[cfg(test)]
mod vex_round_memory_source;
#[cfg(test)]
mod vex_scalar_convert_memory_source;
#[cfg(test)]
mod vex_scalar_extract_replay;
#[cfg(test)]
mod vex_scalar_fp_arithmetic_memory_source;
#[cfg(test)]
mod vex_scalar_fp_compare_memory_source;
#[cfg(test)]
mod vex_scalar_fp_convert_replay;
#[cfg(test)]
mod vex_scalar_fp_memory_source;
#[cfg(test)]
mod vex_scalar_fp_to_int_replay;
#[cfg(test)]
mod vex_scalar_insert_memory_source;
#[cfg(test)]
mod vex_scalar_insert_replay;
#[cfg(test)]
mod vex_scalar_int_to_fp_replay;
#[cfg(test)]
mod vex_scalar_integer_memory_source;
#[cfg(test)]
mod vex_scalar_l1_canonical;
#[cfg(test)]
mod vex_scalar_vmovq_replay;
#[cfg(test)]
mod vex_shared_count_shift_memory_source;
#[cfg(test)]
mod vex_sm3_sm4_memory_source;
#[cfg(test)]
mod vex_sqrt_memory_source;
#[cfg(test)]
mod vex_unaligned_packed_fp_move_replay;
#[cfg(feature = "smir-jit")]
mod vex_variable_blend_memory_source;
#[cfg(test)]
mod vex_variable_blend_replay;
#[cfg(feature = "smir-jit")]
mod vex_variable_permute_memory_source;
#[cfg(test)]
mod vex_variable_permute_replay;
#[cfg(test)]
mod vex_variable_shift_memory_source;
#[cfg(test)]
mod vex_vpclmulqdq_replay;
mod vex_vpermil2_memory_source;
#[cfg(test)]
mod vex_vpermil2_replay;
#[cfg(test)]
mod vex_widening_dword_multiply_memory_source;
#[cfg(test)]
mod vex_widening_dword_multiply_replay;
#[cfg(test)]
mod vex_zero_replay;
#[cfg(test)]
mod vpclmulqdq_memory_source;
#[cfg(test)]
mod waitpkg;
#[cfg(test)]
mod write_control;
#[cfg(test)]
mod write_debug;
#[cfg(test)]
mod x87_control;
#[cfg(test)]
mod x87_transcendental;
#[cfg(test)]
mod xadd;
#[cfg(test)]
mod xop;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    ArmDpRegShiftKind, OpKind, X86AdxKind, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86OpHint, X86SsePrefix, X86ThreeDNowKind, X86VecMap, X86X87ControlKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, BlockId, Condition, DispSize, FenceKind, FpPrecision, FpRoundMode,
    FunctionId, LocalId, MemWidth, OpWidth, ShiftOp, SignExtend, SrcOperand, VLaneOp, VReg,
    VecCmpCond, VecElementType, VecUnaryOp, VecWidth, VirtualId, X86AesOp, X86Reg,
};
use crate::smir::ir::{CallTarget, FunctionBuilder, LocalSlot, PhiNode, Terminator};

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn arm_x(n: u8) -> VReg {
    VReg::Arch(ArchReg::Arm(ArmReg::X(n)))
}

fn arm_v(n: u8) -> VReg {
    VReg::Arch(ArchReg::Arm(ArmReg::V(n)))
}

fn x86_gate(op: OpKind) -> bool {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    b.push_op(0x1000, op);
    b.set_terminator(Terminator::Return { values: vec![] });
    is_native_clobber_safe(&b.finish())
}

fn aarch64_gate(ops: Vec<OpKind>, allow_mem: bool) -> bool {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    for (i, op) in ops.into_iter().enumerate() {
        b.push_op(0x1000 + i as u64 * 4, op);
    }
    b.set_terminator(Terminator::Return { values: vec![] });
    is_aarch64_native_clobber_safe_excluding(
        &b.finish(),
        &std::collections::HashMap::new(),
        allow_mem,
    )
}

fn aarch32_gate_with_mem(ops: Vec<OpKind>, allow_mem: bool) -> bool {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    for (i, op) in ops.into_iter().enumerate() {
        b.push_op(0x1000 + i as u64 * 4, op);
    }
    b.set_terminator(Terminator::Return { values: vec![] });
    is_aarch32_aarch64_native_clobber_safe_excluding_with_mem(
        &b.finish(),
        &std::collections::HashMap::new(),
        allow_mem,
    )
}

fn aarch32_gate(ops: Vec<OpKind>) -> bool {
    aarch32_gate_with_mem(ops, false)
}

fn aarch32_cond_cfg(
    test_dst: VReg,
    branch_cond: VReg,
    condition: Condition,
    op_after_test: Option<OpKind>,
) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    let true_target = builder.create_block(0x2000);
    let false_target = builder.create_block(0x1004);
    builder.push_op(
        0x1000,
        OpKind::TestCondition {
            dst: test_dst,
            cond: condition,
        },
    );
    if let Some(op) = op_after_test {
        builder.push_op(0x1000, op);
    }
    builder.set_terminator(Terminator::CondBranch {
        cond: branch_cond,
        true_target,
        false_target,
    });
    builder.switch_to_block(true_target);
    builder.set_terminator(Terminator::Return { values: Vec::new() });
    builder.switch_to_block(false_target);
    builder.set_terminator(Terminator::Return { values: Vec::new() });
    builder.finish()
}

fn aarch32_call_cfg(
    target: CallTarget,
    link_dst: VReg,
    link_pc: i64,
    link_width: OpWidth,
    args: Vec<VReg>,
    continuation_pc: u64,
) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    let continuation = builder.create_block(continuation_pc);
    builder.push_op(
        0x1000,
        OpKind::Mov {
            dst: link_dst,
            src: SrcOperand::Imm(link_pc),
            width: link_width,
        },
    );
    builder.set_terminator(Terminator::Call {
        target,
        args,
        continuation,
    });
    builder.switch_to_block(continuation);
    builder.set_terminator(Terminator::Return { values: Vec::new() });
    builder.finish()
}

fn aarch32_indirect_cfg(
    target: VReg,
    possible_targets: Vec<BlockId>,
) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::IndirectBranch {
        target,
        possible_targets,
    });
    builder.finish()
}

fn aarch32_blx_lr_cfg(
    snapshot_dst: VReg,
    snapshot_src: VReg,
    call_target: VReg,
    link_pc: i64,
    args: Vec<VReg>,
) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    let continuation = builder.create_block(0x1004);
    builder.push_op(
        0x1000,
        OpKind::Mov {
            dst: snapshot_dst,
            src: SrcOperand::Reg(snapshot_src),
            width: OpWidth::W32,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::Mov {
            dst: arm_x(14),
            src: SrcOperand::Imm(link_pc),
            width: OpWidth::W32,
        },
    );
    builder.set_terminator(Terminator::Call {
        target: CallTarget::IndirectInterworking(call_target),
        args,
        continuation,
    });
    builder.switch_to_block(continuation);
    builder.set_terminator(Terminator::Return { values: Vec::new() });
    builder.finish()
}

fn x86_aarch64_gate(ops: Vec<OpKind>) -> bool {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    for (i, op) in ops.into_iter().enumerate() {
        b.push_op(0x1000 + i as u64, op);
    }
    b.set_terminator(Terminator::Return { values: vec![] });
    is_x86_aarch64_native_clobber_safe_excluding(&b.finish(), &std::collections::HashMap::new())
}
