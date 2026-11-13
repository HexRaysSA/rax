//! Helper-backed VEX scalar-conversion memory-source lowering.

use std::collections::HashMap;

use super::X86_64Lowerer;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{VReg, VecWidth};
use crate::smir::ir::{SmirBlock, X86NativeReplaySpan, X86VexScalarConvertMemoryKind};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_VECTOR_SCRATCH_OFFSET, X86_JIT_VECTOR_SCRATCH_INDEX,
};

impl X86_64Lowerer {
    /// Fuse one exact deterministic VEX.L=0 scalar-conversion memory source.
    ///
    /// The precise MMU helper commits only its nonarchitectural transfer slot.
    /// FP sources are replayed from a borrowed XMM register; integer sources
    /// are replayed from push/pop-preserved RAX. The existing register replay
    /// bridge supplies destination zero-upper behavior and the state-backed
    /// RSP/RBP destination contract. Every borrowed architectural register is
    /// restored before continuation.
    pub(crate) fn try_lower_jit_vex_scalar_convert_memory_source(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) =
            crate::smir::lower::runtime::x86_jit_vex_scalar_convert_memory_sequence(
                block,
                index,
                true,
                &self.x86_instruction_bytes,
                virtual_definitions,
                virtual_uses,
            )
        else {
            return Ok(None);
        };
        let address = match &block.ops[index].kind {
            OpKind::Load { addr, .. } => addr,
            _ => unreachable!("validated VEX scalar conversion starts with a scalar load"),
        };
        self.emit_jit_vector_mem_helper(
            block.ops[index].guest_pc,
            true,
            X86_JIT_VECTOR_SCRATCH_INDEX as u8,
            address,
            sequence.encoding.memory_size,
            true,
            true,
        )?;

        let encoding = sequence.encoding;
        let span = X86NativeReplaySpan {
            end: index + sequence.consumed,
            instruction: encoding.register_instruction,
            needs_avx512vl: false,
            needs_avx512dq: false,
            needs_avx512fp16: false,
            preserve_mxcsr_de: false,
        };
        match encoding.kind {
            X86VexScalarConvertMemoryKind::FpConvert { .. } => {
                let scratch = encoding
                    .vector_scratch
                    .expect("validated FP conversion has a vector scratch register");
                self.code.emit_u8(0x50); // push guest RAX
                self.emit_load_state_ptr_rax();
                self.emit_jit_vector_scratch_load(PhysReg::Xmm(scratch), VecWidth::V128);
                self.emit_narrow_vector_leaf(VecWidth::V128, |lowerer| {
                    lowerer.emit_native_replay_span(&span)
                })?;
                self.emit_jit_vector_scratch_restore(scratch);
                self.code.emit_u8(0x58); // pop guest RAX
            }
            X86VexScalarConvertMemoryKind::IntToFp { int_width, .. } => {
                self.code.emit_u8(0x50); // push guest RAX
                self.emit_load_state_ptr_rax();
                if int_width == crate::smir::ir::types::OpWidth::W64 {
                    self.code.emit_u8(0x48);
                }
                self.code.emit_bytes(&[0x8B, 0x80]); // mov eax/rax,[rax+scratch]
                self.code.emit_u32(X86_GUEST_VECTOR_SCRATCH_OFFSET as u32);
                self.emit_narrow_vector_leaf(VecWidth::V128, |lowerer| {
                    lowerer.emit_native_replay_span(&span)
                })?;
                self.code.emit_u8(0x58); // pop guest RAX
            }
            X86VexScalarConvertMemoryKind::FpToInt { .. } => {
                let scratch = encoding
                    .vector_scratch
                    .expect("validated FP-to-integer conversion borrows XMM0");
                self.code.emit_u8(0x50); // push guest RAX
                self.emit_load_state_ptr_rax();
                self.emit_jit_vector_scratch_load(PhysReg::Xmm(scratch), VecWidth::V128);
                self.code.emit_u8(0x58); // pop guest RAX

                self.emit_narrow_vector_leaf(VecWidth::V128, |lowerer| {
                    lowerer.emit_native_replay_span(&span)
                })?;

                // RAX can itself be the conversion destination. Preserve its
                // post-conversion value while borrowing it as the state base.
                self.code.emit_u8(0x50); // push post-conversion guest RAX
                self.emit_load_state_ptr_rax();
                self.emit_jit_vector_scratch_restore(scratch);
                self.code.emit_u8(0x58); // pop post-conversion guest RAX
            }
        }

        Ok(Some(sequence.consumed))
    }
}
