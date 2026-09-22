//! One callback transaction per admitted scalar AtomicRmw.

use super::*;
use crate::smir::lower::runtime::X86AtomicRmwOp;
use crate::smir::lower::{X86_GUEST_ATOMIC_RMW_FN_OFFSET, X86_GUEST_CTX_OFFSET};
use std::collections::HashMap;

impl X86_64Lowerer {
    /// Keep the existing exact sequence grammar, but never split its memory
    /// transaction into ordinary load and store callbacks. Flag replay and
    /// XADD/XCHG writeback occur only after the atomic callback succeeds.
    pub(crate) fn try_lower_jit_mem_atomic_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_mem_atomic_rmw_sequence(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };
        let operation = if sequence.swap {
            X86AtomicRmwOp::Swap
        } else {
            match sequence.digit {
                0 => X86AtomicRmwOp::Add,
                1 => X86AtomicRmwOp::Or,
                4 => X86AtomicRmwOp::And,
                5 => X86AtomicRmwOp::Sub,
                6 => X86AtomicRmwOp::Xor,
                _ => {
                    return Err(LowerError::UnsupportedOp {
                        op: "scalar AtomicRmw callback operation".to_string(),
                    });
                }
            }
        };
        let source_index = sequence
            .source_reg
            .map(|source| self.jit_arch_enc(source))
            .transpose()?;
        let writeback = sequence
            .writeback
            .map(|dst| self.get_dst_reg(dst))
            .transpose()?;

        // Caller frame (32 bytes): old element +0, reserved +8, source +16,
        // original architectural RAX +24. The helper's two pushes add 16
        // bytes, retaining RSP == 0 (mod 16) immediately before CALL.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq, before any flag-changing bookkeeping
        for enc in [1u8, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            self.emit_struct_mov(PhysReg::Rax, enc, i32::from(enc) * 8, true);
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 8, OpWidth::W64);
        }
        self.emit_struct_mov(PhysReg::Rax, 1, 0, true);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        self.emit_jit_mem_effective_address(sequence.addr, false)?;

        // Snapshot the architectural source before any callback can change
        // caller-saved registers. All 32 GPRs, including RSP/RBP, are coherent
        // in GuestRegs, so source/address aliases need no special branch.
        if let Some(index) = source_index {
            self.emit_struct_mov(PhysReg::Rax, 2, i32::from(index) * 8, false);
        } else {
            // The folded MovVirtual writes only its declared width. Preserve
            // that observable callback operand, including narrow -1 values.
            self.emit_movabs(2, sequence.source_imm as u64 & sequence.width.mask());
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 32, PhysReg::Rdx, OpWidth::W64);
            emitter.emit_mov_ri_imm64(PhysReg::R8, operation as i64);
        }
        self.emit_struct_mov(PhysReg::Rax, 7, X86_GUEST_CTX_OFFSET, false);
        self.emit_struct_mov(PhysReg::Rax, 11, X86_GUEST_ATOMIC_RMW_FN_OFFSET, false);
        // Keep the state pointer in RCX on the no-callback path. ECX is the
        // size argument on the call path, so reload it only after the guard.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W64);
            emitter.emit_test_rr(PhysReg::R11, PhysReg::R11, OpWidth::W64);
        }
        let no_callback = self.emit_jcc_placeholder(X86Cond::E);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_ri_imm64(PhysReg::Rcx, sequence.mem_width.bytes() as i64);
            emitter.emit_call_reg(PhysReg::R11);
            emitter.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rbp,
                X86_STATE_PTR_AT_RBP,
                OpWidth::W64,
            );
            emitter.emit_test_rr(PhysReg::Rdx, PhysReg::Rdx, OpWidth::W64);
        }
        let failure = self.emit_jcc_placeholder(X86Cond::E);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq: original flags, including INC/DEC CF
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 8);
            if sequence.replay {
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, sequence.width);
                match sequence.replay_unary {
                    Some(1) => emitter.emit_inc(PhysReg::Rax, sequence.width),
                    Some(2) => emitter.emit_dec(PhysReg::Rax, sequence.width),
                    None => emitter.emit_alu_mem_disp(
                        sequence.opcode,
                        PhysReg::Rax,
                        PhysReg::Rsp,
                        16,
                        DispSize::Auto,
                        sequence.width,
                        X86AluEncoding::RegRm,
                    ),
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "scalar AtomicRmw unary replay".to_string(),
                        });
                    }
                }
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            if let Some(destination) = writeback {
                emitter.emit_mov_rm(destination, PhysReg::Rsp, 0, sequence.width);
            }
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        }
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        self.patch_rel32_to_current(no_callback)?;
        self.patch_rel32_to_current(failure)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 40);
        }
        self.emit_native_exit(sequence.guest_pc);
        self.patch_rel32_to_current(done)?;
        Ok(Some(sequence.consumed))
    }
}
