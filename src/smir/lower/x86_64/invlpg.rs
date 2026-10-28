//! Fault-precise, helper-backed lowering for x86 INVLPG.

use crate::smir::ir::ops::{OpKind, SmirOp, X86InvlpgOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_INVLPG_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact address and handoff shape emitted by the strict x86-64
/// INVLPG lifter. EGPR components require a REX2/APX encoding; a REX2 encoding
/// remains explicit even when its address uses only legacy GPRs.
pub(crate) fn x86_invlpg_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86Invlpg(X86InvlpgOp {
        addr,
        requires_apx,
        next_pc,
    }) = &op.kind
    else {
        return false;
    };
    let instruction_len = next_pc.checked_sub(op.guest_pc);
    let uses_egpr = addr
        .regs()
        .iter()
        .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
    let minimum_len = if *requires_apx { 4 } else { 3 };
    instruction_len.is_some_and(|len| (minimum_len..=15).contains(&len))
        && op.x86_hint.is_none()
        && addr.is_x86_state_backed_shape()
        && (!uses_egpr || *requires_apx)
}

impl X86_64Lowerer {
    /// Call the owning vCPU's canonical INVLPG helper and leave native
    /// execution on both outcomes. Failure restores the complete pre-op state
    /// and replays at `guest_pc`; success serializes and resumes at `next_pc`.
    pub(crate) fn emit_x86_invlpg(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86Invlpg requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_invlpg_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86Invlpg".to_string(),
                operand: "requires an unhinted state-backed x86 address, APX for every EGPR, and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86Invlpg(invlpg) = &op.kind else {
            unreachable!("validated X86Invlpg shape changed")
        };

        // Publish every identity-mapped GPR before borrowing RAX/RSI/RDI/RDX.
        // The two pushes preserve flags and retain 16-byte SysV call alignment.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        // `emit_jit_mem_effective_address` computes the guest linear address in
        // RSI from the state image without dereferencing it.
        self.emit_jit_mem_effective_address(&invlpg.addr, false)?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(invlpg.requires_apx), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+invlpg_fn]
        self.code.emit_u32(X86_GUEST_INVLPG_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_x86_serialize();
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.emit_x86_retirement();
        self.emit_native_exit(invlpg.next_pc);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
