//! Fault-precise, helper-backed lowering for x86 CLI.

use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::OpWidth;
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_CLI_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the complete CLI shape emitted by the strict x86-64 lifter.
pub(crate) fn x86_cli_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86Cli {
        requires_apx,
        next_pc,
    } = &op.kind
    else {
        return false;
    };
    let minimum_len = if *requires_apx { 3 } else { 1 };
    op.x86_hint.is_none()
        && next_pc
            .checked_sub(op.guest_pc)
            .is_some_and(|len| (minimum_len..=15).contains(&len))
}

impl X86_64Lowerer {
    /// Execute CLI against the marshalled guest interrupt-control shadow.
    ///
    /// Both outcomes leave the native region. Success commits IF or VIF and
    /// resumes at `next_pc`; failure restores the complete scalar/vector state
    /// and replays the direct instruction at `guest_pc` for exact #UD/#GP(0)
    /// delivery.
    pub(crate) fn emit_x86_cli(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86Cli requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_cli_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86Cli".to_string(),
                operand: "requires an unhinted one-to-fifteen-byte CLI encoding and exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86Cli {
            requires_apx,
            next_pc,
        } = &op.kind
        else {
            unreachable!("validated X86Cli shape changed")
        };

        // Publish every identity-mapped GPR before crossing the Rust ABI.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        // SysV arguments: RDI=GuestRegs, RSI=requires_apx.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rsi, i64::from(*requires_apx), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+cli_fn]
        self.code.emit_u32(X86_GUEST_CLI_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // restore exact pre-CLI native flags
        self.emit_flag_preserving_stack_pop8(); // discard saved guest RAX
        self.emit_x86_retirement();
        self.emit_native_exit(*next_pc);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
