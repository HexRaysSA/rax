//! Fault-precise helper-backed lowering for indirect far CALL (`FF /3`).

use crate::smir::ir::ops::{OpKind, SmirOp, X86FarCallOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::ir::{SmirBlock, Terminator};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_FAR_CALL_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact memory-only far-CALL shape emitted by the strict lifter.
pub(crate) fn x86_far_call_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86FarCall(X86FarCallOp {
        addr,
        target,
        offset_width,
        requires_apx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    let uses_egpr = addr
        .regs()
        .iter()
        .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
    op.x86_hint.is_none()
        && matches!(next_pc.checked_sub(op.guest_pc), Some(2..=15))
        && matches!(offset_width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        && *target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
        && addr.is_x86_state_backed_shape()
        && (!uses_egpr || *requires_apx)
}

/// A validated far-CALL op owns its terminal dynamic branch. Its helper has
/// already pushed the return frame and therefore must bypass generic near-call
/// and indirect-branch lowering.
pub(crate) fn x86_far_call_terminal_shape_valid(block: &SmirBlock) -> bool {
    let Some(op) = block.ops.last() else {
        return false;
    };
    let OpKind::X86FarCall(call) = &op.kind else {
        return false;
    };
    x86_far_call_shape_valid(op)
        && matches!(
            &block.terminator,
            Terminator::IndirectBranch {
                target,
                possible_targets,
            } if *target == call.target && possible_targets.is_empty()
        )
}

impl X86_64Lowerer {
    /// Spill scalar state, compute the far-pointer address, and call the owning
    /// vCPU validator. Success returns at its dynamic target; failure restores
    /// the pre-op native image and exits at the faulting guest instruction.
    pub(crate) fn emit_x86_far_call(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarCall requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarCall requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_far_call_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86FarCall".to_string(),
                operand: "requires an unhinted state-backed FF /3 address, architectural RIP target, valid offset width, APX for every EGPR, and exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86FarCall(call) = &op.kind else {
            unreachable!("validated X86FarCall shape changed")
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        self.emit_jit_mem_effective_address(&call.addr, false)?; // RSI = pointer address
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let width = match call.offset_width {
                OpWidth::W16 => 0,
                OpWidth::W32 => 1,
                OpWidth::W64 => 2,
                _ => unreachable!("validated far-CALL offset width changed"),
            };
            emitter.emit_mov_ri(
                PhysReg::Rdx,
                width | (i64::from(call.requires_apx) << 2) | (i64::from(call.stack_segment) << 3),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(PhysReg::Rcx, call.next_pc as i64, OpWidth::W64);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_FAR_CALL_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_x86_serialize();
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.emit_x86_retirement();
        self.emit_epilogue_with_ret(None); // helper supplied dynamic exit_pc

        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
