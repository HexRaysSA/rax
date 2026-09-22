//! MXCSR exception-mask policy for validated register-only source replay.
//!
//! This is a positive allow-list, not an instruction decoder or an admission
//! gate. Its input must be the exact (possibly canonicalized) instruction from
//! an already validated `x86_native_replay_spans` entry. Provenance, semantic
//! grouping, host features, architectural controls, and state marshalling are
//! independent prerequisites. In particular, a `true` result does not permit
//! omitting guest MXCSR: binary32/binary64 VFPCLASS still observes MXCSR.DAZ.
//!
//! Primary authority: Intel SDM 086 (December 2024), Vol. 1 Sections 11.5 and
//! C.3-C.7, and the individual Vol. 2 instruction exception tables. Integer,
//! logical, transfer, shuffle, and cryptographic instructions listed below do
//! not generate SIMD floating-point exceptions. Three numeric families have
//! explicit additional evidence beside their classifiers below. Arithmetic,
//! conversion, and compare families otherwise remain mask-dependent, including
//! embedded-control/SAE subforms until separately proved and classified.

use crate::smir::ir::SmirFunction;
use crate::smir::ir::X86InstructionBytes;
use crate::smir::ir::types::{ArchReg, VReg, X86Reg};
use crate::smir::ir::types::{BlockId, GuestAddr};
use std::collections::HashMap;

/// Whether this exact replay cannot raise a SIMD floating-point exception for
/// any operand bits and any valid MXCSR exception-mask combination.
///
/// Unknown, malformed, memory, and non-allow-listed instructions return false.
/// No MXCSR value is read or changed. Complexity is O(C * L) time and O(1)
/// auxiliary space, where C is the fixed classifier count and L <= 15 bytes.
pub(crate) fn x86_native_replay_is_mxcsr_mask_independent(
    instruction: &X86InstructionBytes,
) -> bool {
    legacy_mask_independent(instruction)
        || vex_mask_independent(instruction)
        || evex_mask_independent(instruction)
        || nonexceptional_numeric(instruction)
}

/// Permit an unmasked MXCSR only when every executable native vector
/// operation is an exact replay span whose instruction cannot raise a SIMD
/// floating-point exception. Other native vector shapes remain conservative.
/// A missing or invalid replay span cannot satisfy this proof. For N semantic
/// operations and P source instructions, this costs O(N + P) expected time
/// and O(N + P) auxiliary space through the existing span validator.
pub(crate) fn x86_native_vector_mask_independent_excluding(
    function: &SmirFunction,
    excluded: &HashMap<BlockId, GuestAddr>,
) -> bool {
    for block in function
        .blocks
        .iter()
        .filter(|block| !excluded.contains_key(&block.id))
    {
        let spans =
            crate::smir::ir::x86_native_replay_spans(block, &function.x86_instruction_bytes);
        let mut index = 0;
        while index < block.ops.len() {
            if let Some(span) = spans.get(&index) {
                if !x86_native_replay_is_mxcsr_mask_independent(&span.instruction) {
                    return false;
                }
                index = span.end;
            } else {
                let op = &block.ops[index];
                let touches_vector_register = op
                    .kind
                    .source_vregs()
                    .into_iter()
                    .chain(op.kind.dests())
                    .any(|reg| {
                        matches!(
                            reg,
                            VReg::Arch(ArchReg::X86(
                                X86Reg::Xmm(_) | X86Reg::Ymm(_) | X86Reg::Zmm(_) | X86Reg::K(_)
                            ))
                        )
                    });
                if super::is_x86_native_vector_op(&op.kind)
                    || super::x86_jit_vector_mem_shape_valid(&op.kind)
                    || touches_vector_register
                {
                    return false;
                }
                index += 1;
            }
        }
    }
    true
}

fn legacy_mask_independent(instruction: &X86InstructionBytes) -> bool {
    // These classifiers name only exact register forms. "Stack" denotes an
    // architectural RSP/RBP operand handled by a state-backed replay wrapper;
    // it does not admit a guest-memory operand.
    instruction.legacy_register_aes_replay().is_some()
        || instruction.legacy_register_blend_replay().is_some()
        || instruction.legacy_scalar_xmm_movq_replay().is_some()
        || instruction
            .legacy_register_scalar_extract_replay()
            .is_some()
        || instruction.legacy_register_scalar_insert_replay().is_some()
        || instruction.legacy_register_lane_shuffle_replay().is_some()
        || instruction.legacy_register_alignr_replay().is_some()
        || instruction.legacy_register_gfni_replay().is_some()
        || instruction.legacy_register_insertps_replay().is_some()
        || instruction.legacy_register_pclmulqdq_replay().is_some()
        || instruction.legacy_register_ptest_replay().is_some()
        || instruction.legacy_register_packed_extend_replay().is_some()
        || instruction.legacy_register_packed_shift_replay().is_some()
        || instruction
            .legacy_register_widening_dword_multiply_replay()
            .is_some()
        || instruction.legacy_register_sha_replay().is_some()
        || instruction.is_legacy_register_packed_string_compare()
        || instruction
            .legacy_mov_mask_stack_destination_replay()
            .is_some()
        || instruction.legacy_movd_q_stack_replay().is_some()
        || instruction.is_legacy_high_byte_register_replay()
        || instruction
            .legacy_vex_register_fp_shuffle_needs_avx()
            .is_some()
        || instruction
            .legacy_vex_register_high_low_move_needs_avx()
            .is_some()
        || instruction
            .legacy_vex_register_scalar_move_needs_avx()
            .is_some()
}

fn vex_mask_independent(instruction: &X86InstructionBytes) -> bool {
    // The FP-named moves, logic, blends, and permutes transfer bits rather
    // than performing floating-point arithmetic, even for signaling NaNs.
    instruction
        .vex_register_widening_dword_multiply_needs_avx2()
        .is_some()
        || instruction.is_vex_register_aligned_packed_fp_move()
        || instruction.is_vex_register_unaligned_packed_fp_move()
        || instruction.is_vex_register_packed_integer_move()
        || instruction.is_vex_register_scalar_vmovq()
        || instruction.vex_register_broadcast_element_bits().is_some()
        || instruction.vex_register_lane_shuffle_needs_avx2().is_some()
        || instruction.vex_register_gfni_uses_ymm().is_some()
        || instruction.vex_register_vpclmulqdq_uses_ymm().is_some()
        || instruction
            .vex_register_packed_extend_needs_avx2()
            .is_some()
        || instruction.vex_zeroes_all_register_bits().is_some()
        || instruction.is_vex_register_packed_string_compare()
        || instruction.vex_register_integer_dot_fields().is_some()
        || instruction.vex_register_ifma52_fields().is_some()
        || instruction
            .vex_register_integer_dot_ext_is_int16()
            .is_some()
        || instruction
            .vex_register_immediate_blend_needs_avx2()
            .is_some()
        || instruction
            .vex_register_immediate_permute_needs_avx2()
            .is_some()
        || instruction
            .vex_register_chunk_extract_needs_avx2()
            .is_some()
        || instruction.is_vex_register_scalar_extract()
        || instruction
            .vex_mov_mask_stack_destination_needs_avx2()
            .is_some()
        || instruction.is_vex_register_ptest()
        || instruction
            .vex_register_variable_blend_needs_avx2()
            .is_some()
        || instruction
            .vex_register_variable_permute_needs_avx2()
            .is_some()
        || instruction.vex_register_alignr_needs_avx2().is_some()
        || instruction
            .vex_register_cross_lane_128_needs_avx2()
            .is_some()
        || instruction.is_vex_register_scalar_insert()
        || instruction.is_vex_register_fp_logic()
}

fn evex_mask_independent(instruction: &X86InstructionBytes) -> bool {
    instruction.evex_register_logic_requirements().is_some()
        || instruction
            .evex_register_integer_arithmetic_needs_vl()
            .is_some()
        || instruction
            .evex_register_shared_count_shift_needs_vl()
            .is_some()
        || instruction
            .evex_register_immediate_count_shift_needs_vl()
            .is_some()
        || instruction
            .evex_register_packed_funnel_shift_needs_vl()
            .is_some()
        || instruction.evex_register_packed_rotate_needs_vl().is_some()
        || instruction
            .evex_register_integer_minmax_needs_vl()
            .is_some()
        || instruction
            .evex_register_integer_multiply_requirements()
            .is_some()
        || instruction
            .evex_register_integer_interleave_needs_vl()
            .is_some()
        || instruction.evex_register_integer_pack_needs_vl().is_some()
        || instruction.evex_register_packed_abs_needs_vl().is_some()
        || instruction
            .evex_register_packed_average_needs_vl()
            .is_some()
        || instruction.evex_register_packed_test_needs_vl().is_some()
        || instruction
            .evex_register_packed_compare_needs_vl()
            .is_some()
        || instruction.evex_register_mask_blend_needs_vl().is_some()
        || instruction
            .evex_register_vector_to_mask_requirements()
            .is_some()
        || instruction
            .evex_register_mask_to_vector_requirements()
            .is_some()
        || instruction
            .evex_register_mask_broadcast_needs_vl()
            .is_some()
        || instruction.evex_register_lane_shuffle_needs_vl().is_some()
        || instruction.evex_register_vector_align_needs_vl().is_some()
        || instruction
            .evex_register_bw_shuffle_madd_needs_vl()
            .is_some()
        || instruction.evex_register_bw_immediate_needs_vl().is_some()
        || instruction.evex_register_chunk_shuffle_needs_vl().is_some()
        || instruction
            .evex_register_chunk_insert_requirements()
            .is_some()
        || instruction
            .evex_register_chunk_extract_requirements()
            .is_some()
        || instruction
            .evex_register_scalar_move_requires_fp16()
            .is_some()
        || instruction
            .evex_register_scalar_integer_move_requires_fp16()
            .is_some()
        || instruction
            .evex_register_scalar_lane_transfer_requires_dq()
            .is_some()
        || instruction.evex_register_high_low_move_needs_vl().is_some()
        || instruction.evex_register_gfni_needs_vl().is_some()
        || instruction.evex_register_vpclmulqdq_needs_vl().is_some()
        || instruction.evex_register_vp2intersect_needs_vl().is_some()
        || instruction.evex_register_fp_shuffle_needs_vl().is_some()
        || instruction
            .evex_register_avx512f_permute_needs_vl()
            .is_some()
        || instruction.evex_register_packed_move_needs_vl().is_some()
        || instruction.evex_register_packed_extend_needs_vl().is_some()
        || instruction.evex_register_broadcast_requirements().is_some()
        || instruction
            .evex_register_narrow_broadcast_needs_vl()
            .is_some()
        || instruction.evex_register_gpr_broadcast_needs_vl().is_some()
}

fn nonexceptional_numeric(instruction: &X86InstructionBytes) -> bool {
    // SDM 086 Vol. 2B 4-537, 4-539, 4-592, 4-594: RCPPS/RCPSS and
    // RSQRTPS/RSQRTSS (legacy and VEX) list SIMD FP exceptions as None.
    // This does not include differently specified EVEX RCP*/RSQRT* forms.
    instruction.legacy_vex_register_fp_estimate_needs_avx().is_some()
        // Vol. 2C 5-355, 5-357, 5-360, 5-362, 5-363, 5-365: all six
        // VFPCLASS forms list SIMD FP exceptions as None. FP32/64 still
        // observe DAZ; mask independence is not total MXCSR independence.
        || instruction.evex_register_fp_class_requirements().is_some()
        // Vol. 2C 5-43 through 5-45: VCVTNEPS2BF16 does not consult or
        // update MXCSR. This exact classifier admits only its VEX form;
        // ordinary FP16 narrowing/widening remains outside the allow-list.
        || instruction.vex_register_ne_convert_fields().is_some()
}
