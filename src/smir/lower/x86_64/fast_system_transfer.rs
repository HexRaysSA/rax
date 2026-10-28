//! Fault-precise helper-backed lowering for Intel SYSENTER/SYSEXIT.

use crate::smir::ir::ops::{OpKind, SmirOp, X86FastSystemTransferKind, X86FastSystemTransferOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::ir::{SmirBlock, Terminator};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_FAST_SYSTEM_TRANSFER_FN_OFFSET, X86_STATE_PTR_AT_RBP,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact operand-free state shape emitted for `0F 34`/`0F 35`.
pub(crate) fn x86_fast_system_transfer_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86FastSystemTransfer(X86FastSystemTransferOp {
        kind,
        target,
        stack_pointer,
        return_target,
        return_stack_pointer,
        operand64,
        next_pc,
    }) = &op.kind
    else {
        return false;
    };
    op.x86_hint.is_none()
        && next_pc
            .checked_sub(op.guest_pc)
            .is_some_and(|len| (2..=15).contains(&len))
        && *target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
        && *stack_pointer == VReg::Arch(ArchReg::X86(X86Reg::Rsp))
        && *return_target == VReg::Arch(ArchReg::X86(X86Reg::Rdx))
        && *return_stack_pointer == VReg::Arch(ArchReg::X86(X86Reg::Rcx))
        && (*kind == X86FastSystemTransferKind::Sysexit || !*operand64)
}

/// A validated fast system transfer owns the matching terminal dynamic branch.
pub(crate) fn x86_fast_system_transfer_terminal_shape_valid(block: &SmirBlock) -> bool {
    let Some(op) = block.ops.last() else {
        return false;
    };
    let OpKind::X86FastSystemTransfer(transfer) = &op.kind else {
        return false;
    };
    x86_fast_system_transfer_shape_valid(op)
        && matches!(
            &block.terminator,
            Terminator::IndirectBranch {
                target,
                possible_targets,
            } if *target == transfer.target && possible_targets.is_empty()
        )
}

impl X86_64Lowerer {
    /// Spill complete scalar state, evaluate the dynamic transfer through the
    /// owning vCPU, and leave the region at either the committed target or the
    /// original faulting PC. A failure performs no architectural commit and is
    /// replayed directly for exact #GP(0) delivery.
    pub(crate) fn emit_x86_fast_system_transfer(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86FastSystemTransfer requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_fast_system_transfer_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86FastSystemTransfer".to_string(),
                operand: "requires an unhinted 2-15 byte SYSENTER/SYSEXIT encoding, exact architectural RIP/RSP/RCX/RDX operands, and exact end PC"
                    .to_string(),
            });
        }
        let OpKind::X86FastSystemTransfer(transfer) = &op.kind else {
            unreachable!("validated X86FastSystemTransfer shape changed")
        };

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        // SysV arguments: RDI=GuestRegs, RSI=kind, RDX=operand64.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(
                PhysReg::Rsi,
                match transfer.kind {
                    X86FastSystemTransferKind::Sysenter => 0,
                    X86FastSystemTransferKind::Sysexit => 1,
                },
                OpWidth::W32,
            );
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(transfer.operand64), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+fast_system_transfer_fn]
        self.code
            .emit_u32(X86_GUEST_FAST_SYSTEM_TRANSFER_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_x86_serialize();
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // restore exact pre-transfer native flags
        self.emit_flag_preserving_stack_pop8();
        self.emit_x86_retirement();
        self.emit_epilogue_with_ret(None); // helper supplied dynamic exit_pc

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
