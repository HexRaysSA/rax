//! Fault-precise helper-backed lowering for far RET (`CA`/`CB`).

use crate::smir::ir::ops::{OpKind, SmirOp, X86FarReturnOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::ir::{SmirBlock, Terminator};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_FAR_RETURN_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact terminal far-RET shape emitted by the strict lifter.
pub(crate) fn x86_far_return_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86FarReturn(X86FarReturnOp {
        target,
        offset_width,
        pop_bytes,
        requires_apx,
        next_pc,
    }) = &op.kind
    else {
        return false;
    };
    let minimum_len = 1 + usize::from(*requires_apx) * 2 + usize::from(*pop_bytes != 0) * 2;
    op.x86_hint.is_none()
        && next_pc
            .checked_sub(op.guest_pc)
            .is_some_and(|len| (minimum_len as u64..=15).contains(&len))
        && matches!(offset_width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        && *target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
}

/// A validated far-RET op owns its terminal dynamic branch. The helper has
/// already consumed the complete return frame and must bypass generic indirect
/// branch lowering.
pub(crate) fn x86_far_return_terminal_shape_valid(block: &SmirBlock) -> bool {
    let Some(op) = block.ops.last() else {
        return false;
    };
    let OpKind::X86FarReturn(ret) = &op.kind else {
        return false;
    };
    x86_far_return_shape_valid(op)
        && matches!(
            &block.terminator,
            Terminator::IndirectBranch {
                target,
                possible_targets,
            } if *target == ret.target && possible_targets.is_empty()
        )
}

impl X86_64Lowerer {
    /// Spill scalar state and invoke the owning vCPU validator. Success reloads
    /// the committed post-return state and exits at its dynamic target; failure
    /// reloads the pre-op image and exits at the faulting guest instruction.
    pub(crate) fn emit_x86_far_return(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarReturn requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86FarReturn requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_far_return_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86FarReturn".to_string(),
                operand: "requires an unhinted architectural RIP target, valid offset width, and exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86FarReturn(ret) = &op.kind else {
            unreachable!("validated X86FarReturn shape changed")
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            let width = match ret.offset_width {
                OpWidth::W16 => 0,
                OpWidth::W32 => 1,
                OpWidth::W64 => 2,
                _ => unreachable!("validated far-RET offset width changed"),
            };
            let encoding =
                width | (i64::from(ret.requires_apx) << 2) | (i64::from(ret.pop_bytes) << 16);
            emitter.emit_mov_ri(PhysReg::Rsi, encoding, OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+far_return_fn]
        self.code.emit_u32(X86_GUEST_FAR_RETURN_FN_OFFSET as u32);

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
