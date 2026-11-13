//! Helper-backed VEX floating-point square-root memory-source lowering.

use std::collections::HashMap;

use super::{VecEncoding, VecEncodingKind, X86_64Lowerer};
use crate::smir::ir::SmirBlock;
use crate::smir::ir::ops::{OpKind, X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{VReg, VecElementType, VecWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_JIT_VECTOR_SCRATCH_INDEX};

impl X86_64Lowerer {
    fn vex_sqrt_phys_reg(index: u8, width: VecWidth) -> PhysReg {
        match width {
            VecWidth::V128 => PhysReg::Xmm(index),
            VecWidth::V256 => PhysReg::Ymm(index),
            _ => unreachable!("validated VEX square-root width"),
        }
    }

    /// Fuse one exact VEX packed or scalar floating-point square-root
    /// memory-source decomposition.
    ///
    /// The MMU helper commits only the nonarchitectural vector transfer slot.
    /// A borrowed low vector register carries the helper result into a native
    /// register-source square root and is restored completely before
    /// continuation. Guest MXCSR remains active for the operation, and the
    /// enclosing vector trampoline captures accrued IE/DE/PE status.
    pub(crate) fn try_lower_jit_vex_sqrt_memory_source(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_vex_sqrt_memory_sequence(
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
            _ => unreachable!("validated VEX square-root sequence starts with a memory load"),
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
        let scratch = Self::vex_sqrt_phys_reg(scratch_index, sequence.width);
        let destination = Self::vex_sqrt_phys_reg(sequence.destination, sequence.width);
        let prefix = match (sequence.source1.is_some(), sequence.elem) {
            (false, VecElementType::F32) => X86SsePrefix::None,
            (false, VecElementType::F64) => X86SsePrefix::OpSize,
            (true, VecElementType::F32) => X86SsePrefix::Rep,
            (true, VecElementType::F64) => X86SsePrefix::Repne,
            _ => unreachable!("validated VEX square-root element"),
        };
        let encoding = VecEncoding {
            kind: VecEncodingKind::Vex,
            map: X86VecMap::Map0F,
            pp: prefix,
            opcode: 0x51,
            width: sequence.width,
            w: sequence.w,
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch, sequence.width);
        self.emit_narrow_vector_leaf(sequence.width, |lowerer| {
            if let Some(source1) = sequence.source1 {
                lowerer.emit_vec_rrr(
                    encoding,
                    destination,
                    Self::vex_sqrt_phys_reg(source1, VecWidth::V128),
                    scratch,
                );
            } else {
                lowerer.emit_vec_rr(encoding, destination, scratch, 0);
            }
            Ok(())
        })?;
        self.emit_jit_vector_scratch_restore(scratch_index);
        self.code.emit_u8(0x58); // pop guest RAX

        if self.avx_ymm16_vector_state {
            self.emit_avx_ymm16_state_backed_upper_clear(sequence.destination);
        }
        Ok(Some(sequence.consumed))
    }
}
