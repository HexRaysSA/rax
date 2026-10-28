//! Fault-precise, state-backed LMSW lowering.

use crate::smir::ir::ops::{OpKind, SmirOp, X86LmswOp, X86LmswSource};
use crate::smir::ir::types::{ArchReg, MemWidth, OpWidth, SignExtend, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET,
};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the complete LMSW shape emitted by the strict x86-64 lifter.
///
/// The encoded instruction is 3..=15 bytes, has no generic operation hint,
/// and reads either one x86 GPR or a GuestRegs-backed address. EGPR sources or
/// address components necessarily require REX2/APX; REX2 may also encode only
/// legacy registers and still requires the dynamic APX guard.
pub(crate) fn x86_lmsw_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86Lmsw(X86LmswOp {
        source,
        requires_apx,
        next_pc,
    }) = &op.kind
    else {
        return false;
    };
    let instruction_len = next_pc.checked_sub(op.guest_pc);
    if !matches!(instruction_len, Some(3..=15)) || op.x86_hint.is_some() {
        return false;
    }

    match source {
        X86LmswSource::Register { src } => matches!(
            src,
            VReg::Arch(ArchReg::X86(reg))
                if reg.gpr_index().is_some_and(|index| index < 16 || *requires_apx)
        ),
        X86LmswSource::Memory { addr } => {
            let uses_egpr = addr
                .regs()
                .iter()
                .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
            addr.is_x86_state_backed_shape() && (!uses_egpr || *requires_apx)
        }
    }
}

impl X86_64Lowerer {
    /// Emit LMSW's dynamic prefix and privilege checks while RAX addresses
    /// `GuestRegs`. Every returned branch selects the common non-committing
    /// replay path. The checks precede any helper-backed memory source read.
    fn emit_x86_lmsw_guards(&mut self, requires_apx: bool) -> Result<Vec<usize>, LowerError> {
        let mut fault_branches = Vec::with_capacity(2);

        // An unavailable REX2 prefix raises #UD before privilege validation.
        if requires_apx {
            self.code.emit_bytes(&[0x83, 0xB8]); // cmp dword [rax+apx],0
            self.code.emit_u32(X86_GUEST_APX_ENABLED_OFFSET as u32);
            self.code.emit_u8(0);
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));
        }

        // Real-address mode has effective CPL 0. In protected/long mode LMSW
        // requires CPL0; GuestRegs.cpl maps virtual-8086 mode to CPL3.
        self.code.emit_bytes(&[0xF7, 0x80]); // test dword [rax+cr0],1
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        let real_mode = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cpl],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ne));

        self.patch_rel32_to_current(real_mode)?;
        Ok(fault_branches)
    }

    /// Commit `CR0[3:0]` from RDX while RAX addresses `GuestRegs`.
    /// An already-set `CR0.PE` bit is ORed back into the result, so LMSW can
    /// enter protected mode but cannot leave it. Bits 63:4 remain unchanged.
    fn emit_x86_lmsw_commit_from_rdx(&mut self) {
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_and_ri(PhysReg::Rdx, 0xF, OpWidth::W64);
        emitter.emit_mov_rm(
            PhysReg::Rcx,
            PhysReg::Rax,
            X86_GUEST_CR0_OFFSET,
            OpWidth::W64,
        );
        emitter.emit_mov_rr(PhysReg::Rsi, PhysReg::Rcx, OpWidth::W64);
        emitter.emit_and_ri(PhysReg::Rcx, -16, OpWidth::W64);
        emitter.emit_and_ri(PhysReg::Rsi, 1, OpWidth::W64);
        emitter.emit_or_rr(PhysReg::Rcx, PhysReg::Rdx, OpWidth::W64);
        emitter.emit_or_rr(PhysReg::Rcx, PhysReg::Rsi, OpWidth::W64);
        emitter.emit_mov_mr(
            PhysReg::Rax,
            X86_GUEST_CR0_OFFSET,
            PhysReg::Rcx,
            OpWidth::W64,
        );
    }

    /// Update state-backed CR0 without executing host LMSW.
    ///
    /// Both successful source forms serialize and leave the native region at
    /// the exact next instruction because CR0.MP/EM/TS can immediately change
    /// instruction behavior. Dynamic guard or memory failures restore all GPRs
    /// and RFLAGS and restart at the original guest PC without committing CR0.
    pub(crate) fn emit_x86_lmsw(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86Lmsw requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_lmsw_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86Lmsw".to_string(),
                operand: "requires a fixed-width x86 GPR or state-backed memory source, APX for every EGPR, and an exact next PC"
                    .to_string(),
            });
        }
        let OpKind::X86Lmsw(X86LmswOp {
            source,
            requires_apx,
            next_pc,
        }) = &op.kind
        else {
            unreachable!("validated X86Lmsw shape changed")
        };
        if matches!(source, X86LmswSource::Memory { .. }) && !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "LMSW memory source requires JIT MMU helpers".to_string(),
            });
        }

        // A memory form owns one aligned 16-byte slot across its helper call.
        // The helper stages its zero-extended B2 result in this slot.
        if matches!(source, X86LmswSource::Memory { .. }) {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }

        // Publish every identity-mapped GPR before borrowing RAX/RDX/RCX/RSI.
        // RSP/RBP/EGPR values already reside in their canonical state slots.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq
        self.emit_spill_legacy_gprs_to_state_from_rax(8);

        let fault_branches = self.emit_x86_lmsw_guards(*requires_apx)?;

        match source {
            X86LmswSource::Register { src } => {
                let source_index = match src {
                    VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index().unwrap(),
                    _ => unreachable!("validated X86Lmsw source changed"),
                };
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rm(
                        PhysReg::Rdx,
                        PhysReg::Rax,
                        i32::from(source_index) * 8,
                        OpWidth::W64,
                    );
                }
                self.emit_x86_lmsw_commit_from_rdx();
            }
            X86LmswSource::Memory { addr } => {
                // Restore the exact pre-instruction register image before the
                // MMU helper. Guard failures have already been excluded.
                self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
                self.emit_reload_all(PhysReg::Rcx);
                self.code.emit_u8(0x9D); // popfq
                self.emit_flag_preserving_stack_pop8();

                self.emit_jit_mem_op(
                    op.guest_pc,
                    true,
                    None,
                    Some(16),
                    None,
                    None,
                    None,
                    addr,
                    MemWidth::B2,
                    SignExtend::Zero,
                    16,
                )?;

                // Snapshot again after the helper. Its result is the aligned
                // qword at [rsp], hence [rsp+16] after push RAX + pushfq.
                self.code.emit_u8(0x50);
                self.emit_load_state_ptr_rax();
                self.code.emit_u8(0x9C);
                self.emit_spill_legacy_gprs_to_state_from_rax(8);
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 16, OpWidth::W64);
                }
                self.emit_x86_lmsw_commit_from_rdx();
            }
        }

        self.emit_x86_serialize();
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        if matches!(source, X86LmswSource::Memory { .. }) {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_x86_retirement();
        self.emit_native_exit(*next_pc);

        // Guard failures precede the register read or MMU helper call. Restore
        // the exact pre-instruction image and replay LMSW to deliver #UD/#GP.
        for branch in fault_branches {
            self.patch_rel32_to_current(branch)?;
        }
        self.code.emit_bytes(&[0x48, 0x89, 0xC1]); // mov rcx,rax
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        if matches!(source, X86LmswSource::Memory { .. }) {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}
