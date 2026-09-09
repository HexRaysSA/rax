//! Feature requirements contributed by exact x86 native-replay spans.

#[path = "vector_replay_features_evex_extract_memory.rs"]
mod evex_extract_memory;
#[path = "vector_replay_features_evex_fp16_narrow_memory.rs"]
mod evex_fp16_narrow_memory;
#[path = "vector_replay_features_evex_half_move_memory.rs"]
mod evex_half_move_memory;
#[path = "vector_replay_features_evex_integer_memory.rs"]
mod evex_integer_memory;
#[path = "vector_replay_features_evex_scalar_insert_memory.rs"]
mod evex_scalar_insert_memory;
#[path = "vector_replay_feature_probes.rs"]
mod feature_probes;
#[path = "vector_replay_feature_requirements.rs"]
mod feature_requirements;
#[path = "vector_replay_span_features.rs"]
mod span_features;

pub(crate) use feature_probes::*;
pub(crate) use feature_requirements::X86NativeReplayFeatureRequirements;

/// Accumulate the host features required by exact x86 native-replay spans and
/// helper-backed x86 memory-source sequences in O(N) time and O(P + V)
/// temporary space per block for N operations, P guest instruction addresses,
/// and V virtual registers.
pub(crate) fn x86_native_replay_feature_requirements(
    func: &crate::smir::ir::SmirFunction,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
) -> X86NativeReplayFeatureRequirements {
    let mut requirements = X86NativeReplayFeatureRequirements::default();
    let mut all_spans_support_avx_ymm16 = true;
    for block in func
        .blocks
        .iter()
        .filter(|block| !excluded.contains_key(&block.id))
    {
        span_features::accumulate_x86_native_replay_span_requirements(
            block,
            &func.x86_instruction_bytes,
            &mut requirements,
            &mut all_spans_support_avx_ymm16,
        );

        let mut virtual_definitions = std::collections::HashMap::new();
        let mut virtual_uses = std::collections::HashMap::new();
        for op in &block.ops {
            for register in op.kind.dests() {
                if matches!(register, crate::smir::ir::types::VReg::Virtual(_)) {
                    *virtual_definitions.entry(register).or_insert(0usize) += 1;
                }
            }
            for register in op.kind.source_vregs() {
                if matches!(register, crate::smir::ir::types::VReg::Virtual(_)) {
                    *virtual_uses.entry(register).or_insert(0usize) += 1;
                }
            }
        }
        let mut index = 0usize;
        while index < block.ops.len() {
            if let Some(sequence) = super::x86_jit_evex_vsib_memory_sequence(
                block, index, true, &func.x86_instruction_bytes,
                &virtual_definitions, &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // Native VSIB uses scalar MMU helpers and full ZMM moves,
                // never a host gather/scatter. Only AVX512F is required,
                // including narrow-width and qword guest encodings.
                requirements.has_k16_opmask_span = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(consumed) =
                super::evex_broadcast_memory_features::accumulate_evex_broadcast_memory_requirements(
                    block,
                    index,
                    func,
                    &virtual_definitions,
                    &virtual_uses,
                    &mut requirements,
                    &mut all_spans_support_avx_ymm16,
                )
            {
                index += consumed;
            } else if let Some(consumed) = super::evex_duplicate_move_memory_features::accumulate_evex_duplicate_move_memory_requirements(
                block,
                index,
                func,
                &virtual_definitions,
                &virtual_uses,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(consumed) = super::evex_movntdqa_memory_features::accumulate_evex_movntdqa_memory_requirements(
                block,
                index,
                func,
                &virtual_definitions,
                &virtual_uses,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(consumed) = super::evex_packed_move_memory_features::accumulate_evex_packed_move_memory_requirements(
                block,
                index,
                func,
                &virtual_definitions,
                &virtual_uses,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_extend_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Architecturally, opcode 20H/30H also requires BW while the
                // remaining widening moves require only AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.has_k16_opmask_span |= sequence.encoding.writemask.is_some();
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fp16_convert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // every operation in this family requires AVX-512-FP16.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512fp16 = true;
                requirements.has_k16_opmask_span |= sequence.encoding.writemask.is_some();
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_convert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // AVX-512F is implied by the full ZMM/K state bridge;
                // qword conversions additionally require AVX-512DQ.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                requirements.has_k16_opmask_span |= sequence.encoding.writemask.is_some();
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_scalar_fp_to_int_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge requires
                // AVX-512BW. Binary16 conversion additionally requires
                // AVX-512FP16; binary32/binary64 use AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512fp16 |= sequence.encoding.needs_avx512fp16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_scalar_int_to_fp_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge requires
                // AVX-512BW. Binary16 conversion additionally requires
                // AVX-512FP16; binary32/binary64 use AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512fp16 |= sequence.encoding.needs_avx512fp16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(consumed) = evex_half_move_memory::accumulate_evex_half_move_memory_replay_requirements(
                block,
                index,
                func,
                &virtual_definitions,
                &virtual_uses,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(sequence) = super::x86_jit_evex_four_fma_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx5124fmaps = true;
                // Packed 4FMAPS observes K[15:0]; scalar 4FMAPS observes only
                // K[0]. Both can use AVX512F KMOVW without AVX512BW.
                requirements.has_k16_opmask_span = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_bf16_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // the fused span consumes the directly lowered BF16 operation,
                // so its architectural feature must be retained here too.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512bf16 = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_fp_interleave_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // VUNPCKL/HPS/PD require AVX-512F. The full-width native
                // vector/opmask bridge additionally requires AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_fp_shuffle_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // VSHUFPS/PD require AVX-512F. The full-width native
                // vector/opmask bridge additionally requires AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_chunk_shuffle_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // All four chunk shuffles require AVX-512F. The full-width
                // native vector/opmask bridge additionally requires BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_chunk_insert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The instruction requires AVX-512F or DQ. The full-width
                // native vector/opmask bridge additionally requires BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_dbpsadbw_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge and VDBPSADBW itself
                // require AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_gfni_multiply_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // VGF2P8MULB requires GFNI and AVX-512F/VL. The full-width
                // vector/opmask state bridge additionally requires BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_gfni = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_bw_shuffle_madd_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // VPSHUFB, VPMADDUBSW, and VPMADDWD require AVX-512BW.
                // The full-width vector/opmask bridge has the same minimum.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_integer_arithmetic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Byte/word operations also require BW architecturally;
                // dword/quadword operations require only AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_integer_pack_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // Every EVEX saturating-pack form requires AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_integer_interleave_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW.
                // Byte/word interleaves also require BW architecturally;
                // doubleword/quadword forms themselves require AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_integer_mask_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Byte/word compare/test forms also require BW
                // architecturally; dword/quadword forms require only F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(span) = super::x86_jit_evex_fp_class_memory_feature_span(
                block,
                index,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= span.needs_avx512vl;
                requirements.needs_avx512dq |= span.needs_avx512dq;
                requirements.needs_avx512fp16 |= span.needs_avx512fp16;
                all_spans_support_avx_ymm16 = false;
                index += span.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_integer_minmax_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Byte/word operations also require BW architecturally;
                // dword/quadword operations require only AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_abs_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Byte/word VPABS forms also require BW architecturally;
                // dword/quadword forms require only AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(consumed) =
                evex_extract_memory::accumulate_evex_extract_memory_replay_requirements(
                    block,
                    index,
                    func,
                    &virtual_definitions,
                    &virtual_uses,
                    &mut requirements,
                    &mut all_spans_support_avx_ymm16,
                )
            {
                index += consumed;
            } else if let Some(consumed) = evex_scalar_insert_memory::accumulate_evex_scalar_insert_memory_replay_requirements(
                block,
                index,
                func,
                &virtual_definitions,
                &virtual_uses,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(consumed) = evex_fp16_narrow_memory::accumulate_evex_fp16_narrow_memory_replay_requirements(
                block,
                index,
                func,
                &mut requirements,
                &mut all_spans_support_avx_ymm16,
            ) {
                index += consumed;
            } else if let Some(consumed) =
                evex_integer_memory::accumulate_evex_integer_memory_replay_requirements(
                    block,
                    index,
                    func,
                    &virtual_definitions,
                    &virtual_uses,
                    &mut requirements,
                    &mut all_spans_support_avx_ymm16,
                )
            {
                index += consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fp_unary_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                let uses_k16_opmasks =
                    sequence.encoding.elem != crate::smir::ir::types::VecElementType::F16;
                // Binary16 operations can observe K[31:0] and use the full
                // opmask bridge. Every packed F32/F64 unary operation observes
                // at most K[15:0] and can use the existing KMOVW bridge.
                requirements.needs_avx512bw |= !uses_k16_opmasks;
                requirements.has_k16_opmask_span |= uses_k16_opmasks;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                requirements.needs_avx512er |= sequence.encoding.needs_avx512er;
                requirements.needs_avx512fp16 |= sequence.encoding.needs_avx512fp16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_logic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW
                // even when the logical instruction itself requires only F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_masked_logic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW
                // even when the logical instruction itself requires only F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_multishift_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // VPMULTISHIFTQB additionally requires AVX-512VBMI.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512vbmi = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_full_permute_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // VPERMB additionally requires AVX-512VBMI; every other
                // covered operation requires AVX-512F or AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512vbmi |= sequence.encoding.needs_avx512vbmi;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_two_table_permute_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Byte permutations additionally require AVX-512VBMI;
                // word forms require BW, and D/Q/PS/PD forms require F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512vbmi |= sequence.encoding.needs_avx512vbmi;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_variable_permute_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW;
                // VPERMILPS/PD themselves require AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_broadcast_logic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW
                // even when the logical instruction itself requires only F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512dq |= sequence.encoding.needs_avx512dq;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_broadcast_interleave_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width native vector-state bridge uses AVX-512BW
                // even though VPUNPCK*DQ/QDQ itself requires AVX-512F only.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) =
                super::x86_jit_evex_packed_fp16_arithmetic_memory_sequence(
                    block,
                    index,
                    true,
                    &func.x86_instruction_bytes,
                    &virtual_definitions,
                    &virtual_uses,
                )
            {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // the arithmetic operation itself requires AVX-512-FP16.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512fp16 = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fp16_complex_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // packed complex arithmetic itself requires AVX-512-FP16.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512fp16 = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(span) =
                super::evex_scalar_fp_memory_features::x86_jit_evex_scalar_fp_memory_feature_span(
                    block,
                    index,
                    &func.x86_instruction_bytes,
                    &virtual_definitions,
                    &virtual_uses,
                )
            {
                requirements.any = true;
                requirements.needs_avx = true;
                // Most scalar spans need the full KMOVQ bridge. The classic
                // reciprocal approximations use the existing low-16 KMOVW
                // bridge, allowing AVX512ER-only hosts without AVX512BW.
                requirements.needs_avx512bw |= span.needs_avx512bw;
                requirements.needs_avx512dq |= span.needs_avx512dq;
                requirements.needs_avx512er |= span.needs_avx512er;
                requirements.needs_avx512fp16 |= span.needs_avx512fp16;
                requirements.has_k16_opmask_span |= span.uses_k16_opmasks;
                all_spans_support_avx_ymm16 = false;
                index += span.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fp_arithmetic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // packed binary32/binary64 arithmetic itself requires F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fp_compare_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // packed comparison itself requires F or FP16.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512fp16 |= sequence.encoding.needs_avx512fp16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_gfni_affine_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // affine GFNI additionally requires GFNI and F/VL.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_gfni = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_fixup_imm_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // VFIXUPIMM itself requires AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_range_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // every VRANGE operation additionally requires AVX-512DQ.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512dq = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_scale_f_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW.
                // Binary16 VSCALEF additionally requires AVX-512FP16;
                // binary32/binary64 use the baseline AVX-512F gate.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512fp16 |=
                    sequence.encoding.elem == crate::smir::ir::types::VecElementType::F16;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_funnel_shift_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // every packed funnel-shift operation requires VBMI2.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512vbmi2 = true;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_shift_imm_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // Word/byte-lane shifts and the full-width K bridge require BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_rotate_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // packed doubleword/quadword rotates themselves require F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_variable_shift_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // doubleword/quadword shifts themselves require AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_ternary_logic_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // VPTERNLOGD/Q themselves require AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_shared_count_shift_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // doubleword/quadword shifts themselves require AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_alignr_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge and VPALIGNR itself
                // require AVX-512BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_vector_align_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // VALIGND/Q itself requires AVX-512F.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_mask_blend_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                // The full-width vector/opmask bridge requires AVX-512BW;
                // dword/qword/float blends require F, while byte/word blends
                // already require BW.
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_scalar_fma3_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx512bw = true;
                requirements.needs_avx512fp16 |=
                    sequence.encoding.elem == crate::smir::ir::types::VecElementType::F16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_evex_packed_fma3_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx512bw = true;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_avx512fp16 |=
                    sequence.encoding.elem == crate::smir::ir::types::VecElementType::F16;
                all_spans_support_avx_ymm16 = false;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fma4_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_fma4 = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_vpermil2_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_xop = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_sm3_sm4_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_sm3 |= sequence.encoding.kind.needs_sm3();
                requirements.needs_sm4 |= sequence.encoding.kind.needs_sm4();
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_packed_string_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_masked_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                // The fused implementation emits AVX VMOVDQU only; integer
                // guest forms therefore do not require host AVX2.
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vpclmulqdq_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx512bw |= !sequence.encoding.supports_avx_ymm16;
                requirements.needs_avx512vl |= sequence.encoding.needs_avx512vl;
                requirements.needs_pclmulqdq |= sequence.encoding.needs_pclmulqdq;
                requirements.needs_vpclmulqdq |= sequence.encoding.needs_vpclmulqdq;
                all_spans_support_avx_ymm16 &= sequence.encoding.supports_avx_ymm16;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_gfni_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_gfni = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_duplicate_move_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_estimate_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fp_flag_compare_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_sqrt_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_packed_convert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_f16c |= sequence.encoding.needs_f16c();
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_ne_convert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx_ne_convert = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fp16_narrow_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_f16c = true;
                requirements.needs_vex_fp16_narrow = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_round_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_scalar_convert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_extract_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.needs_avx2();
                index += sequence.consumed();
            } else if let Some(consumed) = super::x86_jit_vex_scalar_move_memory_sequence_len(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fp_compare_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fp_dot_product_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_mpsadbw_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.width == crate::smir::ir::types::VecWidth::V256;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_scalar_insert_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_alignr_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.width == crate::smir::ir::types::VecWidth::V256;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_fp_shuffle_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_immediate_blend_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.encoding.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_immediate_permute_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.encoding.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_cross_lane_128_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.encoding.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_variable_blend_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.encoding.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_variable_permute_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.encoding.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_lane_shuffle_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.width == crate::smir::ir::types::VecWidth::V256;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_aes_memory_sequence(
                block,
                index,
                true,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx512bw |= !sequence.supports_avx_ymm16;
                requirements.needs_avx512vl |= sequence.needs_avx512vl;
                requirements.needs_aes |= sequence.needs_aes;
                requirements.needs_vaes |= sequence.needs_vaes;
                all_spans_support_avx_ymm16 &= sequence.supports_avx_ymm16;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_movntdqa_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                // The helper performs the memory transfer and ignores the
                // cache-placement hint; only the AVX YMM16 state bridge is
                // executed on the host, including for the guest AVX2 form.
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_phminposuw_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_packed_abs_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.width == crate::smir::ir::types::VecWidth::V256;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_broadcast_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.needs_avx2;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_packed_extend_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.width == crate::smir::ir::types::VecWidth::V256;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_ptest_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                index += sequence.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_integer_dot_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx_vnni = true;
                index += sequence.binary.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_ifma52_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx_ifma = true;
                index += sequence.binary.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_integer_dot_ext_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx_vnni_int8 |= !sequence.int16;
                requirements.needs_avx_vnni_int16 |= sequence.int16;
                index += sequence.binary.consumed;
            } else if let Some(sequence) = super::x86_jit_vex_binary_memory_sequence(
                block,
                index,
                true,
                &func.x86_instruction_bytes,
                &virtual_definitions,
                &virtual_uses,
            ) {
                requirements.any = true;
                requirements.needs_avx = true;
                requirements.needs_avx2 |= sequence.needs_avx2;
                requirements.needs_fma |= sequence.needs_fma;
                index += sequence.consumed;
            } else {
                index += 1;
            }
        }
    }
    requirements.all_spans_support_avx_ymm16 = requirements.any && all_spans_support_avx_ymm16;
    if requirements.all_spans_support_avx_ymm16 {
        // These replay families address only YMM0-YMM15 and no opmask state.
        // Their dedicated state bridge itself requires AVX even when every
        // replayed source instruction is legacy SSE, but no AVX-512 feature.
        requirements.needs_avx = true;
        requirements.needs_avx512bw = false;
    }
    requirements
}

#[cfg(test)]
#[path = "vector_replay_features_tests.rs"]
mod tests;
