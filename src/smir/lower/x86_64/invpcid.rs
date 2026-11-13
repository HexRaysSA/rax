//! Fault-precise, helper-backed lowering for x86 INVPCID.

use crate::smir::ir::ops::{OpKind, SmirOp, X86InvpcidOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CPL_OFFSET, X86_GUEST_INVPCID_FN_OFFSET,
    X86_STATE_PTR_AT_RBP,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact register, address, and handoff shape emitted by the
/// strict long-mode INVPCID lifter. Every EGPR operand requires APX provenance.
pub(crate) fn x86_invpcid_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86Invpcid(X86InvpcidOp {
        invpcid_type,
        addr,
        requires_apx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    let type_index = match invpcid_type {
        VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
        _ => None,
    };
    let uses_egpr = type_index.is_some_and(|index| index >= 16)
        || addr
            .regs()
            .iter()
            .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
    let instruction_len = next_pc.checked_sub(op.guest_pc);
    let minimum_len = if *requires_apx { 6 } else { 5 };
    instruction_len.is_some_and(|len| (minimum_len..=15).contains(&len))
        && type_index.is_some()
        && op.x86_hint.is_none()
        && addr.is_x86_state_backed_shape()
        && (!uses_egpr || *requires_apx)
}

impl X86_64Lowerer {
    /// Call the owning vCPU's canonical INVPCID helper and leave native
    /// execution on both outcomes. Guard/helper failure restores the pre-op
    /// state and replays at `guest_pc`; success serializes and resumes at the
    /// exact `next_pc` after translation-dependent caches are synchronized.
    pub(crate) fn emit_x86_invpcid(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86Invpcid requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86Invpcid requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_invpcid_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86Invpcid".to_string(),
                operand: "requires an unhinted x86 GPR type, a state-backed address, APX for every EGPR, and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86Invpcid(invpcid) = &op.kind else {
            unreachable!("validated X86Invpcid shape changed")
        };
        let VReg::Arch(ArchReg::X86(type_reg)) = invpcid.invpcid_type else {
            unreachable!("validated INVPCID type register changed")
        };
        let type_index = type_reg
            .gpr_index()
            .expect("validated INVPCID GPR index changed");

        // Publish identity-mapped GPRs before borrowing RAX/RSI/RDI/RDX/RCX.
        // The two pushes preserve RFLAGS and maintain SysV call alignment.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let mut guard_faults = Vec::with_capacity(2);
        if invpcid.requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            guard_faults.push(self.emit_jcc_placeholder(X86Cond::E));
        }
        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        guard_faults.push(self.emit_jcc_placeholder(X86Cond::Ne));

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        self.emit_jit_mem_effective_address(&invpcid.addr, false)?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rax,
                i32::from(type_index) * 8,
                OpWidth::W64,
            );
            emitter.emit_mov_ri(PhysReg::Rcx, i64::from(invpcid.requires_apx), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_INVPCID_FN_OFFSET as u32);

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
        self.emit_native_exit(invpcid.next_pc);

        for branch in guard_faults {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
