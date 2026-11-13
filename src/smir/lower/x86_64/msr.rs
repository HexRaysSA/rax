//! Fault-precise, helper-backed RDMSR/WRMSR lowering.

use crate::smir::ir::ops::{OpKind, SmirOp, X86MsrOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET, X86_GUEST_MSR_FN_OFFSET,
    X86_STATE_PTR_AT_RBP,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the fixed implicit-register shape emitted by the strict x86-64
/// lifter and an exact two-to-fifteen-byte post-instruction frontier.
pub(crate) fn x86_msr_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86Msr(X86MsrOp {
        eax,
        ecx,
        edx,
        next_pc,
        ..
    }) = &op.kind
    else {
        return false;
    };
    matches!(next_pc.checked_sub(op.guest_pc), Some(2..=15))
        && op.x86_hint.is_none()
        && *eax == VReg::Arch(ArchReg::X86(X86Reg::Rax))
        && *ecx == VReg::Arch(ArchReg::X86(X86Reg::Rcx))
        && *edx == VReg::Arch(ArchReg::X86(X86Reg::Rdx))
}

impl X86_64Lowerer {
    /// Execute an MSR access through the canonical guest-state helper. Dynamic
    /// privilege/MSR faults restore every GPR and flag and deoptimize at the
    /// faulting PC. Successful WRMSR terminates at `next_pc`; RDMSR reloads its
    /// zero-extended EDX:EAX result and continues in the region.
    pub(crate) fn emit_x86_msr(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86Msr requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_msr_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86Msr".to_string(),
                operand: "requires implicit EAX/ECX/EDX and an exact next PC".to_string(),
            });
        }
        let OpKind::X86Msr(msr) = &op.kind else {
            unreachable!("validated X86Msr shape changed")
        };

        // Publish the identity-mapped register file before borrowing RAX as the
        // state base. The saved RFLAGS image makes guards and the Rust ABI
        // invisible to the guest.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        // Real-address mode permits RDMSR/WRMSR. Protected, compatibility, and
        // 64-bit execution require effective CPL0; VM86 is marshalled as CPL3.
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],1
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        let real_mode = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        let privilege_fault = self.emit_jcc_placeholder(X86Cond::Ne);
        self.patch_rel32_to_current(real_mode)?;

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rsi, i64::from(msr.write), OpWidth::W32);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_MSR_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        if msr.write {
            // A fixed CPUID barrier is stronger than the TSC-deadline exception
            // and is architecturally unobservable; all represented MSR state is
            // already committed before the exact next-PC handoff.
            self.emit_x86_serialize();
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-access RAX

        let done = if msr.write {
            self.emit_x86_retirement();
            self.emit_native_exit(msr.next_pc);
            None
        } else {
            self.code.emit_u8(0xE9);
            let patch = self.code.position();
            self.code.emit_u32(0);
            Some(patch)
        };

        // Privilege failure still has the state pointer in RAX; a helper-level
        // failure already reloaded it into RCX. Both paths share exact restore.
        self.patch_rel32_to_current(privilege_fault)?;
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        if let Some(done) = done {
            self.patch_rel32_to_current(done)?;
        }
        Ok(())
    }
}
