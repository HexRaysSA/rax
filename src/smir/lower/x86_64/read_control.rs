//! Fault-precise, state-backed lowering for x86 control-register reads.

use crate::smir::ir::ops::{OpKind, SmirOp, X86ControlReg};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET, X86_GUEST_CR2_OFFSET,
    X86_GUEST_CR3_OFFSET, X86_GUEST_CR4_OFFSET, X86_GUEST_CR8_OFFSET,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the exact 64-bit GPR/control-register shape emitted by the strict
/// x86-64 lifter. REX2 permits every GPR through R31; the preceding
/// `X86RequireApx` operation retains the source encoding's dynamic admission.
pub(crate) fn x86_read_control_shape_valid(kind: &OpKind) -> bool {
    let OpKind::X86ReadControl { dst, control } = kind else {
        return false;
    };
    matches!(
        dst,
        VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some_and(|index| index < 32)
    ) && matches!(
        control,
        X86ControlReg::Cr0
            | X86ControlReg::Cr2
            | X86ControlReg::Cr3
            | X86ControlReg::Cr4
            | X86ControlReg::Cr8
    )
}

impl X86_64Lowerer {
    /// Read the selected guest control register through `GuestRegs` without
    /// executing the host's privileged `MOV r64, CRn` instruction.
    ///
    /// The dynamic protected-mode privilege failure restores every GPR and
    /// RFLAGS bit before handing off at the original guest PC. Successful
    /// CR0/CR2/CR3/CR4 reads execute a register-preserving CPUID barrier to
    /// retain their serializing contract; Intel does not define MOV-from-CR8
    /// as serializing.
    pub(crate) fn emit_x86_read_control(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86ReadControl requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_read_control_shape_valid(&op.kind) {
            return Err(LowerError::InvalidOperand {
                op: "X86ReadControl".to_string(),
                operand: "requires one x86 GPR destination and CR0/CR2/CR3/CR4/CR8".to_string(),
            });
        }
        let OpKind::X86ReadControl { dst, control } = &op.kind else {
            unreachable!("validated X86ReadControl shape changed")
        };
        let destination = match dst {
            VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index().unwrap(),
            _ => unreachable!("validated X86ReadControl destination changed"),
        };
        let control_offset = match control {
            X86ControlReg::Cr0 => X86_GUEST_CR0_OFFSET,
            X86ControlReg::Cr2 => X86_GUEST_CR2_OFFSET,
            X86ControlReg::Cr3 => X86_GUEST_CR3_OFFSET,
            X86ControlReg::Cr4 => X86_GUEST_CR4_OFFSET,
            X86ControlReg::Cr8 => X86_GUEST_CR8_OFFSET,
        };

        // Publish identity-mapped GPRs before using RAX/RDX/RCX as scratch.
        // RSP/RBP remain canonical in their state-backed slots.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        // Real-address mode (CR0.PE=0) permits the read. Otherwise effective
        // CPL must be zero; GuestRegs.cpl maps VM86 execution to CPL3.
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],1
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        let real_mode = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        let fault = self.emit_jcc_placeholder(X86Cond::Ne);

        self.patch_rel32_to_current(real_mode)?;
        if matches!(control, X86ControlReg::Cr8) {
            self.emit_live_cr8_read(op.guest_pc)?;
        }
        if !matches!(control, X86ControlReg::Cr8) {
            self.emit_x86_serialize();
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rax, control_offset, OpWidth::W64);
        }
        self.emit_store_gpr_slot_from_reg(destination, PhysReg::Rdx, OpWidth::W64)?;

        // Preserve the state pointer in RCX before an RBP destination updates
        // the prologue's saved guest-RBP word, then resume with exact flags.
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        if destination == 5 {
            self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        }
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-read RAX
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        // Fault path: all published state still contains the pre-instruction
        // register image. Restore it and let the interpreter deliver #GP(0).
        self.patch_rel32_to_current(fault)?;
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }
}
mod live_priority;
