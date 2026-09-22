//! Portable positive-policy and fail-closed tests; no native execution.

use std::collections::BTreeSet;

use crate::smir::ir::X86InstructionBytes;
use crate::smir::lower::runtime::trampolines::{
    x86_native_replay_is_mxcsr_mask_independent, x86_native_vector_mask_independent_excluding,
};

struct Case {
    classifier: &'static str,
    bytes: &'static [u8],
    matches: fn(&X86InstructionBytes) -> bool,
    // Number of trailing bytes after ModR/M; None denotes VZERO*, which has
    // no ModR/M. These fixtures otherwise contain register-only operands.
    trailing: Option<usize>,
}

macro_rules! option_case {
    ($classifier:ident, [$($byte:expr),+], $trailing:expr) => {
        Case {
            classifier: stringify!($classifier),
            bytes: &[$($byte),+],
            matches: |instruction| instruction.$classifier().is_some(),
            trailing: $trailing,
        }
    };
}

macro_rules! bool_case {
    ($classifier:ident, [$($byte:expr),+], $trailing:expr) => {
        Case {
            classifier: stringify!($classifier),
            bytes: &[$($byte),+],
            matches: |instruction| instruction.$classifier(),
            trailing: $trailing,
        }
    };
}

// One independently named encoding per allow-listed classifier. Each row
// verifies that the intended classifier actually recognizes its fixture;
// policy success through a different classifier cannot conceal a dead row.
const INDEPENDENT: &[Case] = &[
    option_case!(
        legacy_register_aes_replay,
        [0x66, 0x0F, 0x38, 0xDC, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_blend_replay,
        [0x66, 0x0F, 0x3A, 0x0C, 0xC1, 0xA5],
        Some(1)
    ),
    option_case!(
        legacy_scalar_xmm_movq_replay,
        [0xF3, 0x0F, 0x7E, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_scalar_extract_replay,
        [0x66, 0x0F, 0x3A, 0x14, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        legacy_register_scalar_insert_replay,
        [0x66, 0x0F, 0x3A, 0x20, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        legacy_register_lane_shuffle_replay,
        [0xF3, 0x0F, 0x12, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_alignr_replay,
        [0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x08],
        Some(1)
    ),
    option_case!(
        legacy_register_gfni_replay,
        [0x66, 0x0F, 0x38, 0xCF, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_insertps_replay,
        [0x66, 0x0F, 0x3A, 0x21, 0xC1, 0x31],
        Some(1)
    ),
    option_case!(
        legacy_register_pclmulqdq_replay,
        [0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x11],
        Some(1)
    ),
    option_case!(
        legacy_register_ptest_replay,
        [0x66, 0x0F, 0x38, 0x17, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_packed_extend_replay,
        [0x66, 0x0F, 0x38, 0x20, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_packed_shift_replay,
        [0x66, 0x0F, 0x71, 0xD0, 0x01],
        Some(1)
    ),
    option_case!(
        legacy_register_widening_dword_multiply_replay,
        [0x66, 0x0F, 0xF4, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_sha_replay,
        [0x0F, 0x38, 0xC8, 0xC1],
        Some(0)
    ),
    bool_case!(
        is_legacy_register_packed_string_compare,
        [0x66, 0x0F, 0x3A, 0x61, 0xC1, 0x08],
        Some(1)
    ),
    option_case!(
        legacy_mov_mask_stack_destination_replay,
        [0x0F, 0x50, 0xE0],
        Some(0)
    ),
    option_case!(
        legacy_movd_q_stack_replay,
        [0x66, 0x0F, 0x6E, 0xC4],
        Some(0)
    ),
    bool_case!(is_legacy_high_byte_register_replay, [0x00, 0xE4], Some(0)),
    option_case!(
        legacy_vex_register_fp_shuffle_needs_avx,
        [0x0F, 0x14, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_high_low_move_needs_avx,
        [0x0F, 0x12, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_scalar_move_needs_avx,
        [0xF3, 0x0F, 0x10, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_register_widening_dword_multiply_needs_avx2,
        [0xC4, 0xE1, 0x71, 0xF4, 0xC2],
        Some(0)
    ),
    bool_case!(
        is_vex_register_aligned_packed_fp_move,
        [0xC5, 0xF8, 0x28, 0xC1],
        Some(0)
    ),
    bool_case!(
        is_vex_register_unaligned_packed_fp_move,
        [0xC5, 0xF8, 0x10, 0xC1],
        Some(0)
    ),
    bool_case!(
        is_vex_register_packed_integer_move,
        [0xC5, 0xF9, 0x6F, 0xC1],
        Some(0)
    ),
    bool_case!(
        is_vex_register_scalar_vmovq,
        [0xC5, 0xFA, 0x7E, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_register_broadcast_element_bits,
        [0xC4, 0xE2, 0x79, 0x18, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_register_lane_shuffle_needs_avx2,
        [0xC5, 0xFA, 0x12, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_register_gfni_uses_ymm,
        [0xC4, 0xE2, 0x71, 0xCF, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_register_vpclmulqdq_uses_ymm,
        [0xC4, 0xE3, 0x71, 0x44, 0xC2, 0x11],
        Some(1)
    ),
    option_case!(
        vex_register_packed_extend_needs_avx2,
        [0xC4, 0xE2, 0x79, 0x20, 0xC1],
        Some(0)
    ),
    option_case!(vex_zeroes_all_register_bits, [0xC5, 0xF8, 0x77], None),
    bool_case!(
        is_vex_register_packed_string_compare,
        [0xC4, 0xE3, 0x79, 0x61, 0xC1, 0x08],
        Some(1)
    ),
    option_case!(
        vex_register_integer_dot_fields,
        [0xC4, 0xE2, 0x71, 0x50, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_register_ifma52_fields,
        [0xC4, 0xE2, 0xF1, 0xB4, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_register_integer_dot_ext_is_int16,
        [0xC4, 0xE2, 0x70, 0x50, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_register_immediate_blend_needs_avx2,
        [0xC4, 0xE3, 0x71, 0x0C, 0xC2, 0xA5],
        Some(1)
    ),
    option_case!(
        vex_register_immediate_permute_needs_avx2,
        [0xC4, 0xE3, 0x79, 0x04, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        vex_register_chunk_extract_needs_avx2,
        [0xC4, 0xE3, 0x7D, 0x19, 0xC1, 0x01],
        Some(1)
    ),
    bool_case!(
        is_vex_register_scalar_extract,
        [0xC4, 0xE3, 0x79, 0x14, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        vex_mov_mask_stack_destination_needs_avx2,
        [0xC5, 0xF8, 0x50, 0xE0],
        Some(0)
    ),
    bool_case!(
        is_vex_register_ptest,
        [0xC4, 0xE2, 0x79, 0x17, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_register_variable_blend_needs_avx2,
        [0xC4, 0xE3, 0x71, 0x4A, 0xC2, 0x40],
        Some(1)
    ),
    option_case!(
        vex_register_variable_permute_needs_avx2,
        [0xC4, 0xE2, 0x71, 0x0C, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_register_alignr_needs_avx2,
        [0xC4, 0xE3, 0x71, 0x0F, 0xC2, 0x08],
        Some(1)
    ),
    option_case!(
        vex_register_cross_lane_128_needs_avx2,
        [0xC4, 0xE3, 0x75, 0x06, 0xC2, 0x31],
        Some(1)
    ),
    bool_case!(
        is_vex_register_scalar_insert,
        [0xC4, 0xE3, 0x71, 0x20, 0xC2, 0x03],
        Some(1)
    ),
    bool_case!(is_vex_register_fp_logic, [0xC5, 0xF0, 0x54, 0xC2], Some(0)),
    option_case!(
        evex_register_logic_requirements,
        [0x62, 0xF1, 0x74, 0x49, 0x54, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_integer_arithmetic_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0xFE, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_shared_count_shift_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0xD2, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_immediate_count_shift_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0x72, 0xF2, 0x08],
        Some(1)
    ),
    option_case!(
        evex_register_packed_funnel_shift_needs_vl,
        [0x62, 0xF3, 0x75, 0x49, 0x71, 0xC2, 0x08],
        Some(1)
    ),
    option_case!(
        evex_register_packed_rotate_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x15, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_integer_minmax_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x39, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_integer_multiply_requirements,
        [0x62, 0xF2, 0x75, 0x49, 0x40, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_integer_interleave_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0x60, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_integer_pack_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0x63, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_abs_needs_vl,
        [0x62, 0xF2, 0x7D, 0x49, 0x1C, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_packed_average_needs_vl,
        [0x62, 0xF1, 0x75, 0x49, 0xE0, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_test_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x27, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_compare_needs_vl,
        [0x62, 0xF3, 0x75, 0x49, 0x1F, 0xC2, 0x00],
        Some(1)
    ),
    option_case!(
        evex_register_mask_blend_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x65, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_vector_to_mask_requirements,
        [0x62, 0xF2, 0x7E, 0x48, 0x29, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_mask_to_vector_requirements,
        [0x62, 0xF2, 0x7E, 0x48, 0x28, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_mask_broadcast_needs_vl,
        [0x62, 0xF2, 0x7E, 0x48, 0x3A, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_lane_shuffle_needs_vl,
        [0x62, 0xF1, 0x7E, 0x49, 0x12, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_vector_align_needs_vl,
        [0x62, 0xF3, 0x75, 0x49, 0x03, 0xC2, 0x08],
        Some(1)
    ),
    option_case!(
        evex_register_bw_shuffle_madd_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x00, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_bw_immediate_needs_vl,
        [0x62, 0xF3, 0x75, 0x49, 0x0F, 0xC2, 0x08],
        Some(1)
    ),
    option_case!(
        evex_register_chunk_shuffle_needs_vl,
        [0x62, 0xF3, 0x75, 0x49, 0x23, 0xC2, 0x01],
        Some(1)
    ),
    option_case!(
        evex_register_chunk_insert_requirements,
        [0x62, 0xF3, 0x75, 0x29, 0x18, 0xC2, 0x01],
        Some(1)
    ),
    option_case!(
        evex_register_chunk_extract_requirements,
        [0x62, 0xF3, 0x7D, 0x29, 0x19, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        evex_register_scalar_move_requires_fp16,
        [0x62, 0xF1, 0x76, 0x09, 0x10, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_integer_move_requires_fp16,
        [0x62, 0xF1, 0xFE, 0x08, 0x7E, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_lane_transfer_requires_dq,
        [0x62, 0xF3, 0x7D, 0x08, 0x14, 0xC1, 0x01],
        Some(1)
    ),
    option_case!(
        evex_register_high_low_move_needs_vl,
        [0x62, 0xF1, 0x74, 0x08, 0x12, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_gfni_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0xCF, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_vpclmulqdq_needs_vl,
        [0x62, 0xF3, 0x75, 0x48, 0x44, 0xC2, 0x11],
        Some(1)
    ),
    option_case!(
        evex_register_vp2intersect_needs_vl,
        [0x62, 0xF2, 0x77, 0x48, 0x68, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_fp_shuffle_needs_vl,
        [0x62, 0xF1, 0x74, 0x49, 0x14, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_avx512f_permute_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x16, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_move_needs_vl,
        [0x62, 0xF1, 0x7D, 0x49, 0x6F, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_packed_extend_needs_vl,
        [0x62, 0xF2, 0x7D, 0x49, 0x20, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_broadcast_requirements,
        [0x62, 0xF2, 0x7D, 0x49, 0x18, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_narrow_broadcast_needs_vl,
        [0x62, 0xF2, 0x7D, 0x49, 0x78, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_gpr_broadcast_needs_vl,
        [0x62, 0xF2, 0x7D, 0x49, 0x7C, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_fp_estimate_needs_avx,
        [0x0F, 0x53, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp_class_requirements,
        [0x62, 0xF3, 0x7D, 0x49, 0x66, 0xC1, 0xFF],
        Some(1)
    ),
    option_case!(
        vex_register_ne_convert_fields,
        [0xC4, 0xE2, 0x7A, 0x72, 0xC1],
        Some(0)
    ),
];

// Conservative exclusions are explicit for inventory coverage, but the
// production decision never uses this as a negative list. VPERMIL2 is a
// potential addition pending AMD primary-source exception-table verification.
const REQUIRES_MASKS: &[Case] = &[
    option_case!(
        legacy_register_packed_fp_convert_replay,
        [0x66, 0x0F, 0x5A, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_scalar_fp_convert_replay,
        [0xF3, 0x0F, 0x5A, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_register_round_replay,
        [0x66, 0x0F, 0x3A, 0x08, 0xC1, 0x00],
        Some(1)
    ),
    option_case!(
        legacy_register_dot_product_replay,
        [0x66, 0x0F, 0x3A, 0x40, 0xC1, 0xFF],
        Some(1)
    ),
    option_case!(
        legacy_register_fp_flag_compare_replay,
        [0x0F, 0x2E, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp_arithmetic_needs_vl,
        [0x62, 0xF1, 0x74, 0x49, 0x58, 0xC2],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_fp_arithmetic_needs_avx,
        [0x0F, 0x58, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_fp_compare_needs_avx,
        [0x0F, 0xC2, 0xC1, 0x00],
        Some(1)
    ),
    bool_case!(
        is_vex_register_fp_flag_compare,
        [0xC5, 0xF8, 0x2F, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_round_destination_index,
        [0xC4, 0xE3, 0x79, 0x08, 0xC1, 0x00],
        Some(1)
    ),
    option_case!(
        vex_scalar_fp_convert_destination_index,
        [0xC5, 0xF2, 0x5A, 0xC2],
        Some(0)
    ),
    option_case!(
        vex_scalar_fp_to_int_destination_index,
        [0xC5, 0xFA, 0x2D, 0xC1],
        Some(0)
    ),
    option_case!(
        vex_scalar_int_to_fp_destination_index,
        [0xC5, 0xF2, 0x2A, 0xC2],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_fp_horizontal_addsub_needs_avx,
        [0xC5, 0xF1, 0x7C, 0xC2],
        Some(0)
    ),
    bool_case!(
        is_vex_register_fp16_widen,
        [0xC4, 0xE2, 0x79, 0x13, 0xC1],
        Some(0)
    ),
    bool_case!(
        is_vex_register_fp16_narrow,
        [0xC4, 0xE3, 0x79, 0x1D, 0xC1, 0x00],
        Some(1)
    ),
    option_case!(
        evex_register_packed_fma_needs_vl,
        [0x62, 0xF2, 0x75, 0x49, 0x98, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_fma_needs_vl,
        [0x62, 0xF2, 0x75, 0x09, 0x99, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_fp16_embedded_control_needs_vl,
        [0x62, 0xF5, 0x74, 0x18, 0x58, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_packed_fp16_fma_needs_vl,
        [0x62, 0xF6, 0x75, 0x49, 0x98, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_fp16_fma_needs_vl,
        [0x62, 0xF6, 0x75, 0x09, 0x99, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_fp16_arithmetic_needs_vl,
        [0x62, 0xF5, 0x76, 0x09, 0x58, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_fp_compare_requirements,
        [0x62, 0xF1, 0x74, 0x49, 0xC2, 0xC2, 0x00],
        Some(1)
    ),
    option_case!(
        evex_register_fp16_flag_compare_requirements,
        [0x62, 0xF5, 0x7C, 0x08, 0x2E, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp32_fp64_flag_compare_requirements,
        [0x62, 0xF1, 0x7C, 0x08, 0x2E, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp16_widen_requirements,
        [0x62, 0xF2, 0x7D, 0x49, 0x13, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp16_narrow_requirements,
        [0x62, 0xF3, 0x7D, 0x49, 0x1D, 0xC1, 0x00],
        Some(1)
    ),
    bool_case!(
        is_vex_register_fp32_fp64_convert,
        [0xC5, 0xF8, 0x5A, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp32_fp64_convert_needs_vl,
        [0x62, 0xF1, 0x7C, 0x49, 0x5A, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_fp_sqrt_requirements,
        [0x62, 0xF1, 0x7C, 0x49, 0x51, 0xC1],
        Some(0)
    ),
    option_case!(
        legacy_vex_register_fp_sqrt_needs_avx,
        [0x0F, 0x51, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_fp_to_int_requires_fp16,
        [0x62, 0xF1, 0x7E, 0x08, 0x2D, 0xC1],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_fp_convert_requires_fp16,
        [0x62, 0xF1, 0x76, 0x09, 0x5A, 0xC2],
        Some(0)
    ),
    option_case!(
        evex_register_scalar_int_to_fp_requires_fp16,
        [0x62, 0xF1, 0x76, 0x08, 0x2A, 0xC2],
        Some(0)
    ),
    bool_case!(
        is_vex_register_fma3,
        [0xC4, 0xE2, 0x71, 0x98, 0xC2],
        Some(0)
    ),
    bool_case!(
        is_vex_register_fma4,
        [0xC4, 0xE3, 0x71, 0x68, 0xC2, 0x30],
        Some(1)
    ),
    bool_case!(
        is_vex_register_vpermil2,
        [0xC4, 0xE3, 0x71, 0x48, 0xC2, 0x30],
        Some(1)
    ),
    option_case!(
        vex_register_fp_dot_product_uses_ymm,
        [0xC4, 0xE3, 0x75, 0x40, 0xC2, 0xFF],
        Some(1)
    ),
];

fn policy(bytes: &[u8]) -> bool {
    X86InstructionBytes::new(bytes)
        .as_ref()
        .is_some_and(x86_native_replay_is_mxcsr_mask_independent)
}

fn lifted_function(
    bytes: &[u8],
    level: crate::smir::optimize::OptLevel,
) -> crate::smir::ir::SmirFunction {
    use crate::smir::ir::types::{BlockId, FunctionId, SourceArch};
    use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let pc = 0x7100;
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(SourceArch::X86_64);
    let result = lifter.lift_insn(pc, bytes, &mut context).unwrap();
    assert_eq!(result.bytes_consumed, bytes.len());
    let mut block = SmirBlock::new(BlockId(0), pc);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, pc);
    function.add_block(block);
    function
        .x86_instruction_bytes
        .insert((BlockId(0), pc), X86InstructionBytes::new(bytes).unwrap());
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

#[test]
fn unmasked_vector_admission_requires_every_executed_vector_op_to_have_safe_exact_replay() {
    use crate::smir::ir::types::BlockId;
    use crate::smir::optimize::OptLevel;
    use std::collections::HashMap;

    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let safe = lifted_function(&[0x66, 0x0F, 0x38, 0x17, 0xC1], level); // PTEST
        let unsafe_fp = lifted_function(&[0x0F, 0x58, 0xC1], level); // ADDPS
        let executed = HashMap::new();
        assert!(
            x86_native_vector_mask_independent_excluding(&safe, &executed),
            "{level:?}"
        );
        assert!(
            !x86_native_vector_mask_independent_excluding(&unsafe_fp, &executed),
            "{level:?}"
        );

        let mut no_provenance = safe.clone();
        no_provenance.x86_instruction_bytes.clear();
        assert!(
            !x86_native_vector_mask_independent_excluding(&no_provenance, &executed),
            "{level:?}"
        );
        let excluded = HashMap::from([(BlockId(0), 0x7100)]);
        assert!(
            x86_native_vector_mask_independent_excluding(&unsafe_fp, &excluded),
            "{level:?}"
        );
    }
}

#[test]
fn mxcsr_replay_policy_covers_every_audited_positive_and_conservative_family() {
    assert_eq!(INDEPENDENT.len(), 91);
    assert_eq!(REQUIRES_MASKS.len(), 38);
    for (cases, expected) in [(INDEPENDENT, true), (REQUIRES_MASKS, false)] {
        for case in cases {
            let instruction = X86InstructionBytes::new(case.bytes).unwrap();
            assert!(
                (case.matches)(&instruction),
                "invalid fixture for {}: {:02X?}",
                case.classifier,
                case.bytes
            );
            assert_eq!(policy(case.bytes), expected, "{}", case.classifier);
        }
    }
}

#[test]
fn mxcsr_replay_policy_rejects_memory_truncation_and_trailing_bytes() {
    for case in INDEPENDENT {
        for length in 0..case.bytes.len() {
            assert!(
                !policy(&case.bytes[..length]),
                "{} truncated to {length}",
                case.classifier
            );
        }
        let mut trailing = case.bytes.to_vec();
        trailing.push(0x90);
        assert!(!policy(&trailing), "{} trailing byte", case.classifier);
        let Some(immediate_bytes) = case.trailing else {
            continue;
        };
        // Replace the register ModR/M by a complete [RAX] memory operand,
        // retaining ModR/M.reg because some families use it as an opcode.
        let mut memory = case.bytes.to_vec();
        let modrm = memory.len() - immediate_bytes - 1;
        assert_eq!(memory[modrm] >> 6, 3, "{}", case.classifier);
        memory[modrm] &= 0x38;
        assert!(!policy(&memory), "{} memory operand", case.classifier);
    }
    for bytes in [
        &[][..],
        &[0x90][..],                   // valid but not a replay classifier
        &[0x0F, 0x0B][..],             // UD2
        &[0x0F, 0xAE, 0x10][..],       // LDMXCSR [RAX]
        &[0xF0, 0x0F, 0x14, 0xC1][..], // illegal LOCK UNPCKLPS
        &[0x66, 0x66, 0x0F, 0x14, 0xC1][..],
        &[0x62, 0xF1, 0x70, 0x48, 0x54, 0xC2][..], // EVEX.U=0
        &[0x62, 0xF1, 0x74, 0x68, 0x54, 0xC2][..], // reserved L'L
        &[0x62, 0xF1, 0x74, 0xC8, 0x54, 0xC2][..], // zeroing k0
        &[0x62, 0xF1, 0x74, 0x58, 0x54, 0xC2][..], // reserved EVEX.b
    ] {
        assert!(!policy(bytes), "{bytes:02X?}");
    }
}

#[test]
fn mxcsr_replay_policy_does_not_confuse_bit_operations_with_fp_arithmetic() {
    for ll in 0u8..3 {
        for mask in 0u8..8 {
            for zeroing in [false, true] {
                if zeroing && mask == 0 {
                    continue;
                }
                let p2 = (ll << 5) | 0x08 | mask | if zeroing { 0x80 } else { 0 };
                for (p1, logical_opcode, arithmetic_opcode) in
                    [(0x74, 0x54, 0x58), (0xF5, 0x57, 0x59)]
                {
                    assert!(policy(&[0x62, 0xF1, p1, p2, logical_opcode, 0xC2]));
                    assert!(!policy(&[0x62, 0xF1, p1, p2, arithmetic_opcode, 0xC2]));
                }
            }
        }
    }
    for packed in [false, true] {
        for opcode in [0x52, 0x53] {
            for w in [0u8, 0x80] {
                for l in [0u8, 4] {
                    let p1 = w | if packed { 0x78 } else { 0x72 } | l;
                    assert!(policy(&[0xC4, 0xE1, p1, opcode, 0xC2]));
                    assert!(!policy(&[0xC4, 0xE1, p1, 0x51, 0xC2]));
                }
            }
        }
    }
    for pp in [0u8, 1] {
        for opcode in [0x66, 0x67] {
            for w in [0u8, 0x80] {
                if pp == 0 && w != 0 {
                    continue;
                }
                for ll in 0u8..3 {
                    for immediate in [0u8, 0x80, 0xFF] {
                        assert!(policy(&[
                            0x62,
                            0xF3,
                            0x7C | pp | w,
                            (ll << 5) | 0x09,
                            opcode,
                            0xC1,
                            immediate,
                        ]));
                    }
                }
            }
        }
    }
    // Suppressing only precision through ROUND's immediate does not suppress
    // invalid exceptions. Do not generalize BF16 to ordinary FP16 conversion.
    assert!(!policy(&[0x66, 0x0F, 0x3A, 0x08, 0xC1, 0x08]));
    assert!(policy(&[0xC4, 0xE2, 0x7A, 0x72, 0xC1]));
    assert!(!policy(&[0xC4, 0xE3, 0x79, 0x1D, 0xC1, 0x00]));
    // No blanket SAE inference: the original family remains conservative.
    assert!(!policy(&[0x62, 0xF2, 0x75, 0x18, 0x98, 0xC2]));
}

fn classifier_calls(source: &str) -> BTreeSet<&str> {
    source
        .split('.')
        .skip(1)
        .filter_map(|suffix| {
            let length = suffix
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            let name = &suffix[..length];
            (length != 0
                && suffix[length..].trim_start().starts_with('(')
                && !matches!(name, "is_some" | "map" | "or_else" | "then_some"))
            .then_some(name)
        })
        .collect()
}

#[test]
fn mxcsr_replay_policy_inventory_accounts_for_all_aggregate_classifier_families() {
    // Intentional source-path coupling: adding, moving, or renaming an
    // aggregate family must trigger an explicit policy audit. Unknown bytes
    // still fail closed in production even before this test is updated.
    let aggregate = classifier_calls(include_str!("../../../ir/x86_native_replay/aggregate.rs"));
    let policy_source = include_str!("../trampolines/mxcsr_replay_policy.rs");
    let (_, allow_list_source) = policy_source
        .split_once("fn legacy_mask_independent")
        .expect("policy classifier section");
    let allow_list = classifier_calls(allow_list_source);
    let tested_positive: BTreeSet<_> = INDEPENDENT.iter().map(|case| case.classifier).collect();
    let conservative: BTreeSet<_> = REQUIRES_MASKS.iter().map(|case| case.classifier).collect();
    assert_eq!(
        tested_positive.len(),
        INDEPENDENT.len(),
        "duplicate positive fixture"
    );
    assert_eq!(
        conservative.len(),
        REQUIRES_MASKS.len(),
        "duplicate conservative fixture"
    );
    assert_eq!(
        allow_list, tested_positive,
        "every positive classifier needs a live fixture"
    );
    assert!(tested_positive.is_disjoint(&conservative));
    let audited: BTreeSet<_> = tested_positive.union(&conservative).copied().collect();
    assert_eq!(
        aggregate, audited,
        "new replay families require a mask-policy audit"
    );
}
