//! Fault-precise, helper-backed RDTSC/RDTSCP/RDPMC lowering.

use crate::smir::ir::ops::{OpKind, SmirOp, X86ReadPmcOp, X86ReadTscOp};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET, X86_GUEST_CR4_OFFSET,
    X86_GUEST_PMC_FN_OFFSET, X86_GUEST_TSC_AUX_OFFSET, X86_GUEST_TSC_FN_OFFSET,
    X86_STATE_PTR_AT_RBP,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the fixed architectural destination shape emitted by the two x86
/// encodings. `None` is RDTSC; `Some(RCX)` is RDTSCP.
pub(crate) fn x86_read_tsc_shape_valid(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            dst_hi: VReg::Arch(ArchReg::X86(X86Reg::Rdx)),
            dst_aux: None | Some(VReg::Arch(ArchReg::X86(X86Reg::Rcx))),
        })
    )
}

/// Validate RDPMC's fixed implicit-register shape and absence of unrelated
/// encoding metadata.
pub(crate) fn x86_read_pmc_shape_valid(op: &SmirOp) -> bool {
    op.x86_hint.is_none()
        && matches!(
            &op.kind,
            OpKind::X86ReadPmc(X86ReadPmcOp {
                dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                dst_hi: VReg::Arch(ArchReg::X86(X86Reg::Rdx)),
                selector: VReg::Arch(ArchReg::X86(X86Reg::Rcx)),
            })
        )
}

impl X86_64Lowerer {
    /// Lower both timestamp instructions through the emulator's guest-clock
    /// helper. The host TSC and host IA32_TSC_AUX are never guest-visible.
    /// CR4.TSD privilege failures deoptimize before any destination commits.
    pub(crate) fn emit_x86_read_tsc(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86ReadTsc requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_read_tsc_shape_valid(&op.kind) {
            return Err(LowerError::InvalidOperand {
                op: "X86ReadTsc".to_string(),
                operand: "requires EAX/EDX and optional ECX destinations".to_string(),
            });
        }
        let OpKind::X86ReadTsc(X86ReadTscOp { dst_aux, .. }) = &op.kind else {
            unreachable!("validated X86ReadTsc shape changed")
        };

        // Publish every identity-mapped GPR before borrowing RAX as the state
        // base. PUSHFQ protects architectural flags from the dynamic guard and
        // Rust helper call.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; stack remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        // #GP(0) iff CR0.PE=1, CR4.TSD=1, and effective CPL is nonzero.
        // Native admission records virtual-8086 mode as effective CPL3.
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],imm32
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        let real_mode = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr4],imm32
        self.code.emit_u32(X86_GUEST_CR4_OFFSET as u32);
        self.code.emit_u32(1 << 2);
        let tsd_clear = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        let fault_branch = self.emit_jcc_placeholder(X86Cond::Ne);

        self.patch_rel32_to_current(real_mode)?;
        self.patch_rel32_to_current(tsd_clear)?;

        if dst_aux.is_some() {
            // Intel RDTSCP waits for all earlier loads to become globally
            // visible, but does not wait for earlier stores. LFENCE is the
            // corresponding host ordering primitive and does not alter flags.
            self.code.emit_bytes(&[0x0F, 0xAE, 0xE8]);
        }

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);
        // The platform ABI requires DF=0 at every Rust call boundary. Guest DF
        // remains protected by the saved RFLAGS image and is restored below.
        self.code.emit_u8(0xFC); // cld
        self.code.emit_bytes(&[0x48, 0x89, 0xC7]); // mov rdi,rax (GuestRegs)
        self.emit_host_c_helper_call(X86_GUEST_TSC_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        if dst_aux.is_some() {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rcx,
                X86_GUEST_TSC_AUX_OFFSET,
                OpWidth::W32,
            );
            // Store a complete qword so the architectural ECX write clears the
            // upper 32 bits when the identity register file is reloaded.
            emitter.emit_mov_mr(PhysReg::Rcx, 8, PhysReg::Rdx, OpWidth::W64);
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-read RAX
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        // No destination has committed on this path. Restore the original
        // identity-mapped state, then hand the instruction to the interpreter
        // so it delivers the architectural #GP(0) at the exact guest PC.
        let fault = self.code.position();
        let rel = fault as i64 - fault_branch as i64 - 4;
        if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
            return Err(LowerError::RelocationOutOfRange {
                offset: fault_branch,
                target: fault,
            });
        }
        self.code.patch_i32(fault_branch, rel as i32);
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }

    /// Lower RDPMC through the canonical deterministic guest-PMU helper.
    /// Dynamic privilege and selector failures restore the complete entry state
    /// and deoptimize at the faulting PC before EDX:EAX commits.
    pub(crate) fn emit_x86_read_pmc(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86ReadPmc requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_read_pmc_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86ReadPmc".to_string(),
                operand: "requires ECX selector and EAX/EDX destinations".to_string(),
            });
        }

        // Publish the identity-mapped GPRs before borrowing RAX as the state
        // pointer. Saved RFLAGS hide the helper call and success test.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_bytes(&[0x48, 0x89, 0xC7]); // mov rdi,rax (GuestRegs)
        self.emit_host_c_helper_call(X86_GUEST_PMC_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let helper_fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-read RAX
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        self.patch_rel32_to_current(helper_fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }
}
