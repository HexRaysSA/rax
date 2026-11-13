//! Helper-backed VEX reciprocal-estimate memory-source lowering.

use std::collections::HashMap;

use super::{VecEncoding, VecEncodingKind, X86_64Lowerer};
use crate::smir::ir::SmirBlock;
use crate::smir::ir::ops::{OpKind, X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{VReg, VecWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_JIT_VECTOR_SCRATCH_INDEX};

impl X86_64Lowerer {
    fn vex_estimate_phys_reg(index: u8, width: VecWidth) -> PhysReg {
        match width {
            VecWidth::V128 => PhysReg::Xmm(index),
            VecWidth::V256 => PhysReg::Ymm(index),
            _ => unreachable!("validated VEX reciprocal-estimate width"),
        }
    }

    /// Fuse one exact VEX packed or scalar reciprocal-estimate memory source.
    ///
    /// The MMU helper commits only the nonarchitectural vector transfer slot.
    /// A borrowed low vector register carries the helper result into the
    /// register-source estimate and is restored completely before
    /// continuation. The native instruction reports no SIMD exceptions,
    /// ignores MXCSR.RC, and preserves all MXCSR and RFLAGS state.
    pub(crate) fn try_lower_jit_vex_estimate_memory_source(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_vex_estimate_memory_sequence(
            block,
            index,
            true,
            &self.x86_instruction_bytes,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };
        let address = match &block.ops[index].kind {
            OpKind::Load { addr, .. } | OpKind::VLoad { addr, .. } => addr,
            _ => unreachable!("validated VEX reciprocal estimate starts with a memory load"),
        };
        self.emit_jit_vector_mem_helper(
            block.ops[index].guest_pc,
            true,
            X86_JIT_VECTOR_SCRATCH_INDEX as u8,
            address,
            sequence.memory_size,
            true,
            true,
        )?;

        let scratch_index = (0..16u8)
            .find(|candidate| {
                *candidate != sequence.destination && sequence.source1 != Some(*candidate)
            })
            .expect("two VEX operands leave at least fourteen scratch registers");
        let scratch = Self::vex_estimate_phys_reg(scratch_index, sequence.width);
        let destination = Self::vex_estimate_phys_reg(sequence.destination, sequence.width);
        let encoding = VecEncoding {
            kind: VecEncodingKind::Vex,
            map: X86VecMap::Map0F,
            pp: if sequence.source1.is_some() {
                X86SsePrefix::Rep
            } else {
                X86SsePrefix::None
            },
            opcode: sequence.opcode,
            // Scalar estimates are VEX.LIG; canonical L=0 also executes on
            // translated hosts that reject L=1. Packed L keeps its meaning.
            width: sequence.width,
            w: sequence.w,
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch, sequence.width);
        self.emit_estimate_control_enter();
        if let Some(source1) = sequence.source1 {
            self.emit_vec_rrr(
                encoding,
                destination,
                Self::vex_estimate_phys_reg(source1, VecWidth::V128),
                scratch,
            );
        } else {
            self.emit_vec_rr(encoding, destination, scratch, 0);
        }
        self.emit_estimate_control_exit();
        self.emit_jit_vector_scratch_restore(scratch_index);
        self.code.emit_u8(0x58); // pop guest RAX

        if self.avx_ymm16_vector_state {
            self.emit_avx_ymm16_state_backed_upper_clear(sequence.destination);
        }
        Ok(Some(sequence.consumed))
    }
}
