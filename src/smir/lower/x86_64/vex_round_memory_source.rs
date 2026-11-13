//! Helper-backed VEX floating-point round memory-source lowering.

use std::collections::HashMap;

use super::X86_64Lowerer;
use crate::smir::ir::SmirBlock;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{VReg, VecWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_JIT_VECTOR_SCRATCH_INDEX};

impl X86_64Lowerer {
    fn vex_round_memory_phys_reg(index: u8, width: VecWidth) -> PhysReg {
        match width {
            VecWidth::V128 => PhysReg::Xmm(index),
            VecWidth::V256 => PhysReg::Ymm(index),
            _ => unreachable!("validated VEX floating-point round width"),
        }
    }

    /// Fuse one exact VEX packed or scalar floating-point round memory-source
    /// decomposition.
    ///
    /// The precise MMU helper commits only the nonarchitectural vector
    /// transfer slot. A byte-validated register-source rewrite consumes that
    /// value from a borrowed low vector register, which is restored in full
    /// before continuation. Guest MXCSR remains active for the native round,
    /// so the enclosing vector trampoline captures accrued IE/PE status.
    pub(crate) fn try_lower_jit_vex_round_memory_source(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_vex_round_memory_sequence(
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
            _ => unreachable!("validated VEX round sequence starts with a memory load"),
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
        let scratch = Self::vex_round_memory_phys_reg(encoding.scratch, encoding.width);
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch, encoding.width);
        self.emit_narrow_vector_leaf(encoding.width, |lowerer| {
            lowerer
                .code
                .emit_bytes(encoding.register_instruction.as_slice());
            Ok(())
        })?;
        self.emit_jit_vector_scratch_restore(encoding.scratch);
        self.code.emit_u8(0x58); // pop guest RAX

        if self.avx_ymm16_vector_state {
            self.emit_avx_ymm16_state_backed_upper_clear(encoding.destination);
        }
        Ok(Some(sequence.consumed))
    }
}
