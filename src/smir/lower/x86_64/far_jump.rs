//! Fault-precise helper-backed lowering for indirect far JMP (`FF /5`).

use crate::smir::ir::ops::{OpKind, SmirOp, X86FarJumpOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::ir::{SmirBlock, Terminator};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_FAR_JUMP_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact memory-only far-JMP shape emitted by the strict lifter.
pub(crate) fn x86_far_jump_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86FarJump(X86FarJumpOp {
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

/// A validated far-JMP op owns its terminal indirect branch. Native lowering
/// commits a dynamic helper-provided `exit_pc` and returns before the generic
/// terminator lowering observes architectural RIP as an ordinary host GPR.
pub(crate) fn x86_far_jump_terminal_shape_valid(block: &SmirBlock) -> bool {
    let Some(op) = block.ops.last() else {
        return false;
    };
    let OpKind::X86FarJump(jump) = &op.kind else {
        return false;
    };
    x86_far_jump_shape_valid(op)
        && matches!(
            &block.terminator,
            Terminator::IndirectBranch {
                target,
                possible_targets,
            } if *target == jump.target && possible_targets.is_empty()
        )
}

impl X86_64Lowerer {
    /// Spill the complete scalar state, compute the far-pointer address from
    /// `GuestRegs`, and call the owning-vCPU validator. Success returns with the
    /// helper's dynamic target in `exit_pc`; failure restores the pre-op image
    /// and replays direct at the faulting instruction.
    pub(crate) fn emit_x86_far_jump(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarJump requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarJump requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_far_jump_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86FarJump".to_string(),
                operand: "requires an unhinted state-backed FF /5 address, architectural RIP target, valid offset width, APX for every EGPR, and exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86FarJump(jump) = &op.kind else {
            unreachable!("validated X86FarJump shape changed")
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        self.emit_jit_mem_effective_address(&jump.addr, false)?; // RSI = pointer address
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let width = match jump.offset_width {
                OpWidth::W16 => 0,
                OpWidth::W32 => 1,
                OpWidth::W64 => 2,
                _ => unreachable!("validated far-JMP offset width changed"),
            };
            emitter.emit_mov_ri(
                PhysReg::Rdx,
                width | (i64::from(jump.requires_apx) << 2) | (i64::from(jump.stack_segment) << 3),
                OpWidth::W32,
            );
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+far_jump_fn]
        self.code.emit_u32(X86_GUEST_FAR_JUMP_FN_OFFSET as u32);

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
        self.emit_epilogue_with_ret(None); // preserve helper-written dynamic exit_pc

        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
