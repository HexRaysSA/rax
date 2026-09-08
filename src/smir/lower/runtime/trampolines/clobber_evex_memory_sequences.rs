//! Exact EVEX vector memory-replay sequence dispatch for the clobber gate.

use super::*;
use crate::smir::ir::types::{BlockId, GuestAddr, VReg};
use crate::smir::ir::{SmirBlock, X86InstructionBytes};
use std::collections::HashMap;

/// Return the semantic-op count consumed by one exact EVEX vector
/// memory-source replay sequence.
///
/// Each family performs its own byte, graph, provenance, address, and virtual
/// value validation. Keeping their ordered dispatch together prevents an
/// implemented family from being admitted by feature discovery and lowering
/// while remaining invisible to the clobber gate. The fixed family list makes
/// this O(1) time and O(1) space per candidate.
pub(crate) fn x86_jit_evex_memory_replay_sequence_len(
    block: &SmirBlock,
    index: usize,
    allow_mem: bool,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
    virtual_definitions: &HashMap<VReg, usize>,
    virtual_uses: &HashMap<VReg, usize>,
) -> Option<usize> {
    if let Some(sequence) = x86_jit_evex_packed_shift_imm_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_broadcast_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_duplicate_move_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_movntdqa_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_move_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_extract_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed());
    }
    if let Some(sequence) = x86_jit_evex_scalar_insert_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_narrow_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) =
        x86_jit_evex_fp16_narrow_memory_sequence(block, index, allow_mem, instruction_bytes)
    {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_extend_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_fp16_convert_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_convert_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_compress_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_expand_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_fp_to_int_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_int_to_fp_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_four_fma_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_half_move_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_half_move_store_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_four_dot_product_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_bw_shuffle_madd_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_fp_interleave_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_fp_shuffle_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_lane_shuffle_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_chunk_insert_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_chunk_shuffle_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_dbpsadbw_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_psadbw_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_vpshufbitqmb_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_vp2intersect_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_gfni_multiply_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_arithmetic_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_pack_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_interleave_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_unary_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_integer_mask_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_integer_minmax_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_abs_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_fp_unary_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_logic_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_masked_logic_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_multishift_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_full_permute_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_two_table_permute_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_variable_permute_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_fp16_complex_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_move_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_fp_arithmetic_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_fp_convert_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_fp_flag_compare_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_fp_compare_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scalar_fp_unary_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_packed_fp_compare_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_fp_class_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_ternary_logic_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_range_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    if let Some(sequence) = x86_jit_evex_scale_f_memory_sequence(
        block,
        index,
        allow_mem,
        instruction_bytes,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(sequence.consumed);
    }
    None
}
