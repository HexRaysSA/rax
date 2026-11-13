//! Exact source-instruction native-replay lowering.

use super::*;
use crate::smir::ir::X86NativeReplaySpan;

impl X86_64Lowerer {
    /// Scope approximate estimates under masked, round-to-nearest host
    /// control. LEA, stores and MXCSR transfers preserve every guest flag;
    /// no GPR/vector scratch register is needed. The 16-byte stack slot is
    /// released after restoring the complete incoming MXCSR. O(1) time/space.
    pub(super) fn emit_estimate_control_enter(&mut self) {
        self.code.emit_bytes(&[0x48, 0x8D, 0x64, 0x24, 0xF0]); // lea rsp,[rsp-16]
        self.code.emit_bytes(&[0x0F, 0xAE, 0x1C, 0x24]); // stmxcsr [rsp]
        self.code.emit_bytes(&[0xC7, 0x44, 0x24, 0x04]); // mov [rsp+4],control
        self.code
            .emit_bytes(&crate::host::x86_estimate::control().to_le_bytes());
        self.code.emit_bytes(&[0x0F, 0xAE, 0x54, 0x24, 0x04]); // ldmxcsr [rsp+4]
    }

    pub(super) fn emit_estimate_control_exit(&mut self) {
        self.code.emit_bytes(&[0x0F, 0xAE, 0x14, 0x24]); // ldmxcsr [rsp]
        self.code.emit_bytes(&[0x48, 0x8D, 0x64, 0x24, 0x10]); // lea rsp,[rsp+16]
    }

    /// Clear the four status flags that Intel defines as zero after
    /// `PTEST`, `VPTEST`, `VTESTPS`, and `VTESTPD`, preserving CF, ZF, and every
    /// unaffected flag.
    ///
    /// Some translated x86-64 hosts compute CF/ZF but preserve OF/SF/AF/PF.
    /// Masking a pushed flag image avoids exposing the temporary flags
    /// produced by the `AND` instruction and does not modify a guest GPR.
    pub(crate) fn emit_ptest_defined_flag_canonicalization(&mut self) {
        self.code.emit_u8(0x9C); // pushfq
        self.code
            .emit_bytes(&[0x48, 0x81, 0x24, 0x24, 0x6B, 0xF7, 0xFF, 0xFF]);
        self.code.emit_u8(0x9D); // popfq
    }

    /// Emit one source instruction with the equivalent host encoding and
    /// status fixups selected by its byte-validated replay classifier.
    pub(crate) fn emit_native_replay_span(
        &mut self,
        span: &X86NativeReplaySpan,
    ) -> Result<(), LowerError> {
        if self.try_emit_legacy_high_byte_replay(span)? {
            return Ok(());
        }
        if span.instruction.is_legacy_register_packed_string_compare() {
            // Legacy PCMPxSTRx writes at most XMM0 bits 127:0 and preserves
            // shared vector state above bit 127. Index forms write ECX only.
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }
        if let Some(returns_mask) = span.instruction.vex_register_packed_string_returns_mask() {
            self.code.emit_bytes(span.instruction.as_slice());
            if returns_mask && self.avx_ymm16_vector_state {
                self.emit_avx_ymm16_state_backed_upper_clear(0);
            }
            return Ok(());
        }
        if span.instruction.vex_zeroes_all_register_bits().is_some() {
            self.code.emit_bytes(span.instruction.as_slice());
            if self.avx_ymm16_vector_state {
                self.emit_avx_ymm16_state_backed_all_upper_clear();
            }
            return Ok(());
        }
        if let Some(replay) = span.instruction.legacy_register_scalar_fp_convert_replay() {
            if let Some(destination @ (4 | 5)) = replay.gpr_destination() {
                let rewritten = span
                    .instruction
                    .legacy_scalar_fp_to_int_with_destination_rax()
                    .expect("validated legacy scalar FP-to-integer must rewrite to RAX");
                self.emit_state_backed_gpr_replay(&rewritten, destination);
            } else if let Some(source @ (4 | 5)) = replay.gpr_source() {
                let rewritten = span
                    .instruction
                    .legacy_scalar_int_to_fp_with_source_rax()
                    .expect("validated legacy scalar integer-to-FP must rewrite to RAX");
                self.emit_state_backed_gpr_source_replay(&rewritten, source);
            } else {
                self.code.emit_bytes(span.instruction.as_slice());
            }
            return Ok(());
        }
        if let Some(replay) = span.instruction.legacy_register_scalar_extract_replay() {
            if matches!(replay.destination, 4 | 5) {
                let rewritten = span
                    .instruction
                    .legacy_scalar_extract_with_destination_rax()
                    .expect("validated legacy scalar extract must rewrite to RAX");
                self.emit_state_backed_gpr_replay(&rewritten, replay.destination);
            } else {
                self.code.emit_bytes(span.instruction.as_slice());
            }
            return Ok(());
        }
        if let Some(replay) = span.instruction.legacy_register_scalar_insert_replay() {
            if matches!(replay.source, 4 | 5) {
                let rewritten = span
                    .instruction
                    .legacy_scalar_insert_with_source_rax()
                    .expect("validated legacy scalar insert must rewrite to RAX");
                self.emit_state_backed_gpr_source_replay(&rewritten, replay.source);
            } else {
                self.code.emit_bytes(span.instruction.as_slice());
            }
            return Ok(());
        }
        if span
            .instruction
            .legacy_register_lane_shuffle_replay()
            .is_some()
        {
            // Legacy lane shuffles preserve every destination bit above bit
            // 127, so exact replay must not receive a VEX upper-clear postlude.
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }
        if span.instruction.legacy_register_alignr_replay().is_some() {
            // Legacy PALIGNR preserves every destination bit above bit 127,
            // so exact replay must not receive a VEX upper-clear postlude.
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }
        if span.instruction.legacy_register_gfni_replay().is_some() {
            // Legacy GFNI updates only the low 128 destination bits and
            // preserves the shared YMM/ZMM state above bit 127.
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }
        if span.instruction.legacy_register_round_replay().is_some() {
            // Legacy ROUND preserves every destination bit above bit 127;
            // unlike VROUND, it must not receive a VEX upper-clear postlude.
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }
        if let Some(destination) = span.instruction.legacy_mov_mask_stack_destination_index() {
            let rewritten = span
                .instruction
                .legacy_mov_mask_stack_destination_with_destination_rax()
                .expect("validated legacy MOVMSK stack destination must rewrite to RAX");
            self.emit_state_backed_gpr_replay(&rewritten, destination);
            return Ok(());
        }
        if let Some(replay) = span.instruction.legacy_movd_q_stack_replay() {
            let rewritten = span
                .instruction
                .legacy_movd_q_stack_with_gpr_rax()
                .expect("validated legacy MOVD/MOVQ stack operand must rewrite to RAX");
            if replay.gpr_is_destination() {
                self.emit_state_backed_gpr_replay(&rewritten, replay.gpr);
            } else {
                self.emit_state_backed_gpr_source_replay(&rewritten, replay.gpr);
            }
            return Ok(());
        }
        if let Some(destination) = span.instruction.vex_scalar_extract_destination_index()
            && matches!(destination, 4 | 5)
        {
            let rewritten = span
                .instruction
                .vex_scalar_extract_with_destination(0)
                .expect("validated VEX scalar extract must rewrite to RAX");
            self.emit_state_backed_gpr_replay(&rewritten, destination);
            return Ok(());
        }
        if let Some(destination) = span.instruction.vex_mov_mask_stack_destination_index() {
            let rewritten = span
                .instruction
                .vex_mov_mask_stack_destination_with_destination(0)
                .expect("validated VEX MOVMSK stack destination must rewrite to EAX");
            self.emit_state_backed_gpr_replay(&rewritten, destination);
            return Ok(());
        }
        if let Some(destination) = span.instruction.vex_scalar_fp_to_int_destination_index() {
            if matches!(destination, 4 | 5) {
                let rewritten = span
                    .instruction
                    .vex_scalar_fp_to_int_with_destination(0)
                    .expect("validated VEX scalar FP-to-integer must rewrite to RAX");
                self.emit_state_backed_gpr_replay(&rewritten, destination);
            } else {
                self.code.emit_bytes(span.instruction.as_slice());
            }
            return Ok(());
        }
        if let Some(source) = span.instruction.vex_scalar_int_to_fp_source_index()
            && matches!(source, 4 | 5)
        {
            let destination = span
                .instruction
                .vex_scalar_int_to_fp_destination_index()
                .expect("validated VEX scalar integer-to-FP must have a destination");
            let rewritten = span
                .instruction
                .vex_scalar_int_to_fp_with_source(0)
                .expect("validated VEX scalar integer-to-FP must rewrite to RAX");
            self.emit_state_backed_gpr_source_replay(&rewritten, source);
            if self.avx_ymm16_vector_state {
                self.emit_avx_ymm16_state_backed_upper_clear(destination);
            }
            return Ok(());
        }
        if let Some(avx) = span.instruction.legacy_vex_register_fp_estimate_needs_avx() {
            let encoding = if avx {
                span.instruction
                    .vex_fp_estimate_native_encoding()
                    .expect("validated VEX estimate has an equivalent host encoding")
            } else {
                span.instruction
            };
            self.emit_estimate_control_enter();
            self.code.emit_bytes(encoding.as_slice());
            self.emit_estimate_control_exit();
            if avx && self.avx_ymm16_vector_state {
                let destination = span
                    .instruction
                    .vex_fp_estimate_destination_index()
                    .expect("validated VEX estimate has a destination");
                self.emit_avx_ymm16_state_backed_upper_clear(destination);
            }
            return Ok(());
        }
        if let Some(destination) = span
            .instruction
            .vex_fma4_destination_index()
            .or_else(|| span.instruction.vex_vpermil2_destination_index())
            .or_else(|| span.instruction.vex_fp_dot_product_destination_index())
            .or_else(|| span.instruction.vex_integer_dot_destination_index())
            .or_else(|| span.instruction.vex_ifma52_destination_index())
            .or_else(|| span.instruction.vex_ne_convert_destination_index())
            .or_else(|| span.instruction.vex_integer_dot_ext_destination_index())
            .or_else(|| span.instruction.vex_immediate_blend_destination_index())
            .or_else(|| span.instruction.vex_immediate_permute_destination_index())
            .or_else(|| span.instruction.vex_chunk_extract_destination_index())
            .or_else(|| span.instruction.vex_variable_blend_destination_index())
            .or_else(|| span.instruction.vex_variable_permute_destination_index())
            .or_else(|| span.instruction.vex_alignr_destination_index())
            .or_else(|| span.instruction.vex_cross_lane_128_destination_index())
            .or_else(|| span.instruction.vex_scalar_insert_destination_index())
            .or_else(|| span.instruction.vex_gfni_destination_index())
            .or_else(|| span.instruction.vex_vpclmulqdq_destination_index())
            .or_else(|| span.instruction.vex_packed_extend_destination_index())
            .or_else(|| {
                span.instruction
                    .vex_aligned_packed_fp_move_destination_index()
            })
            .or_else(|| {
                span.instruction
                    .vex_unaligned_packed_fp_move_destination_index()
            })
            .or_else(|| span.instruction.vex_packed_integer_move_destination_index())
            .or_else(|| {
                span.instruction
                    .vex_register_scalar_vmovq_destination_index()
            })
            .or_else(|| span.instruction.vex_register_broadcast_destination_index())
            .or_else(|| span.instruction.vex_lane_shuffle_destination_index())
            .or_else(|| span.instruction.vex_fp32_fp64_convert_destination_index())
            .or_else(|| span.instruction.vex_fp16_widen_destination_index())
            .or_else(|| span.instruction.vex_fp16_narrow_destination_index())
            .or_else(|| span.instruction.vex_round_destination_index())
            .or_else(|| span.instruction.vex_scalar_fp_convert_destination_index())
            .or_else(|| span.instruction.vex_scalar_int_to_fp_destination_index())
            .or_else(|| {
                span.instruction
                    .vex_avx_ymm16_upper_clear_destination_index()
            })
        {
            self.code.emit_bytes(span.instruction.as_slice());
            if self.avx_ymm16_vector_state {
                self.emit_avx_ymm16_state_backed_upper_clear(destination);
            }
            return Ok(());
        }
        if span.instruction.legacy_register_ptest_replay().is_some()
            || span.instruction.is_vex_register_ptest()
        {
            self.code.emit_bytes(span.instruction.as_slice());
            self.emit_ptest_defined_flag_canonicalization();
            return Ok(());
        }
        if !span.preserve_mxcsr_de {
            self.code.emit_bytes(span.instruction.as_slice());
            return Ok(());
        }

        // Register-source VCVTPH2PSX must preserve the pre-instruction value
        // of MXCSR.DE under the current Intel SDM. Snapshot MXCSR immediately
        // before replay, capture the host result afterwards, and clear only DE
        // when it was previously clear. PUSHFQ/POPFQ make the wrapper invisible
        // to guest flag liveness; no guest GPR or vector register is clobbered.
        self.code.emit_bytes(&[0x9C]); // pushfq
        self.code.emit_bytes(&[0x48, 0x83, 0xEC, 0x10]); // sub rsp, 16
        self.code.emit_bytes(&[0x0F, 0xAE, 0x1C, 0x24]); // stmxcsr [rsp]
        self.code.emit_bytes(span.instruction.as_slice());
        self.code.emit_bytes(&[0x0F, 0xAE, 0x5C, 0x24, 0x04]); // stmxcsr [rsp+4]
        self.code
            .emit_bytes(&[0xF7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00]); // test dword [rsp], 2
        self.code.emit_bytes(&[0x75, 0x08]); // jnz preserve-post-DE
        self.code
            .emit_bytes(&[0x81, 0x64, 0x24, 0x04, 0xFD, 0xFF, 0xFF, 0xFF]); // and [rsp+4], !2
        self.code.emit_bytes(&[0x0F, 0xAE, 0x54, 0x24, 0x04]); // ldmxcsr [rsp+4]
        self.code.emit_bytes(&[0x48, 0x83, 0xC4, 0x10]); // add rsp, 16
        self.code.emit_bytes(&[0x9D]); // popfq
        Ok(())
    }
}
