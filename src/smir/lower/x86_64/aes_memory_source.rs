//! Helper-backed VEX/EVEX AES memory-source lowering.

use std::collections::HashMap;

use super::X86_64Lowerer;
use crate::smir::ir::SmirBlock;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{ArchReg, VReg, VecWidth, X86Reg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_JIT_VECTOR_SCRATCH_INDEX};

impl X86_64Lowerer {
    fn aes_memory_phys_reg(index: u8, width: VecWidth) -> PhysReg {
        match width {
            VecWidth::V128 => PhysReg::Xmm(index),
            VecWidth::V256 => PhysReg::Ymm(index),
            VecWidth::V512 => PhysReg::Zmm(index),
            _ => unreachable!("validated AES vector width"),
        }
    }

    fn aes_memory_vreg(index: u8, width: VecWidth) -> VReg {
        VReg::Arch(ArchReg::X86(match width {
            VecWidth::V128 => X86Reg::Xmm(index),
            VecWidth::V256 => X86Reg::Ymm(index),
            VecWidth::V512 => X86Reg::Zmm(index),
            _ => unreachable!("validated AES vector width"),
        }))
    }

    /// Fuse an exact VEX/EVEX `VLoad`/`X86Aes` memory-source pair. The MMU
    /// helper commits only the nonarchitectural transfer slot. A vector
    /// register not named by the guest instruction carries that value into the
    /// already-validated register AES lowerer and is restored completely before
    /// native execution continues.
    pub(crate) fn try_lower_jit_aes_memory_source(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_aes_memory_sequence(
            block,
            index,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };
        if self.avx_ymm16_vector_state && !sequence.supports_avx_ymm16 {
            return Err(LowerError::InvalidOperand {
                op: "X86Aes memory source".to_string(),
                operand: "AVX-only vector bridge cannot carry high-register or 512-bit AES"
                    .to_string(),
            });
        }
        let address = match &block.ops[index].kind {
            OpKind::VLoad { addr, .. } => addr,
            _ => unreachable!("validated AES memory sequence starts with VLoad"),
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
            .expect("at most two AES operands leave at least fourteen scratch registers");
        let scratch_phys = Self::aes_memory_phys_reg(scratch_index, sequence.width);
        let scratch_vreg = Self::aes_memory_vreg(scratch_index, sequence.width);
        let temporary = match block.ops[index].kind {
            OpKind::VLoad { dst, .. } => dst,
            _ => unreachable!("validated AES memory sequence starts with VLoad"),
        };
        let mut consumer = block.ops[index + 1].clone();
        let OpKind::X86Aes { src1, src2, .. } = &mut consumer.kind else {
            unreachable!("validated AES memory sequence consumer")
        };
        if *src1 == temporary {
            *src1 = scratch_vreg;
        }
        if *src2 == Some(temporary) {
            *src2 = Some(scratch_vreg);
        }

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch_phys, sequence.width);
        self.emit_narrow_vector_leaf(sequence.width, |lowerer| lowerer.lower_op(&consumer))?;
        self.emit_jit_vector_scratch_restore(scratch_index);
        self.code.emit_u8(0x58); // pop guest RAX

        if self.avx_ymm16_vector_state {
            self.emit_avx_ymm16_state_backed_upper_clear(sequence.destination);
        }
        Ok(Some(sequence.consumed))
    }
}
