//! Block lowering and instruction fusion dispatch.

use crate::smir::ir::SmirBlock;
use crate::smir::ir::ops::SmirOp;
use crate::smir::lower::LowerError;

use super::Aarch64Lowerer;

impl Aarch64Lowerer {
    pub(crate) fn lower_ops(&mut self, block_ops: &[SmirOp]) -> Result<(), LowerError> {
        let op_end = block_ops.len();
        let mut idx = 0;
        while idx < op_end {
            let ops = &block_ops[idx..op_end];
            if let Some(consumed) = self.try_lower_neon_fusion(ops)? {
                idx += consumed;
                continue;
            }
            // Memory-fusion peepholes emit INLINE native loads/stores at the raw
            // guest address — correct only when NOT routing memory through the
            // MMU helpers. Skip them in mem_helpers mode so Load/Store reach the
            // call-out path in lower_op.
            if !self.mem_helpers {
                if let Some(consumed) = self.try_lower_fused_signed_load_w(ops)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_fused_ldpsw_pair(ops)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_fused_mem_indexed(ops)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_fused_pair_indexed(ops)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_fused_mem_reg_offset(ops)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_fused_ldclr(ops)? {
                    idx += consumed;
                    continue;
                }
            }
            if let Some(consumed) = self.try_lower_fused_extract(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_rev16(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_rev32(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_bitfield_insert_zero(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_bitfield_insert_low(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_cls(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_flagm(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_sysreg_access(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_cond_compare(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_select(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_vector_inverted_logic(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_inverted_reg_logic(ops)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_fused_inverted_shifted_logic(ops)? {
                idx += consumed;
                continue;
            }
            self.lower_op(&block_ops[idx])?;
            idx += 1;
        }
        Ok(())
    }

    pub(crate) fn lower_block(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        self.block_offsets.insert(block.id, self.code.position());
        // Frontier block: emit an exit stub instead of its body. Branches from
        // interior blocks land on the stub; the interpreter resumes at the
        // block's guest PC. (The block's ops are never executed natively — which
        // is why the clobber gate excludes native-exit blocks.)
        if let Some(&resume_pc) = self.native_exits.get(&block.id) {
            return self.emit_native_exit(resume_pc);
        }
        if self.try_lower_guest_blx_lr_exit(block)? {
            return Ok(());
        }
        let (folded_index, folded_cond) = Self::folded_branch_condition(block);
        if let Some(index) = folded_index {
            self.lower_ops(&block.ops[..index])?;
            self.lower_ops(&block.ops[index + 1..])?;
        } else {
            self.lower_ops(&block.ops)?;
        }
        self.lower_terminator(block, folded_cond)
    }
}
