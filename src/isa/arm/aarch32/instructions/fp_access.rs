//! Shared standalone/mixed-width FP access classification and policy.
use super::*;
use crate::isa::arm::aarch32::fp_admission;
use crate::isa::arm::aarch32::fp_controls::{FpAccessFault, fp_access_kind};

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn fp_data_enabled(&self) -> bool {
        self.cpu.fp_control_context().effective_fpexc_enabled()
    }

    pub(super) fn fp_access_fault(&self, insn: &DecodedInsn) -> Option<ExecResult> {
        let mut kind = fp_access_kind(insn)?;
        let in_it = insn.state.is_thumb() && self.cpu.cpsr.in_it_block();
        // Predicate failure has already skipped the instruction. Choose
        // Undefined for executed restricted encodings before FP access traps.
        if !fp_admission::predicate_supported(insn, kind.advsimd, in_it) {
            return Some(ExecResult::Undefined);
        }
        // Capability absence is a decode failure, before FP access traps and
        // before the handler can modify any architectural state.
        if !fp_admission::instruction_supported(
            insn,
            kind.advsimd,
            &self.cpu.vfp,
            self.cpu.cp15.id_isar[5],
            self.cpu.cp15.id_isar6,
        ) {
            return Some(ExecResult::Undefined);
        }
        if in_it {
            kind.condition = self.cpu.cpsr.it_condition();
        }
        // Arm DDI0406C.d B1.11.2 permits User-mode FPSID reads on VFPv2.
        // The mixed-width Armv8-A PE retains the privileged-only rule.
        if kind.system_read == Some(0)
            && self.cpu.fp_access_context.is_none()
            && matches!((self.cpu.vfp.mvfr0 >> 4) & 0xff, 0x01 | 0x11)
        {
            if insn.state.is_thumb() && (kind.raw >> 12) & 15 == 13 {
                return Some(ExecResult::Undefined);
            }
            kind.privileged_only = false;
        }
        let access = self
            .cpu
            .fp_control_context()
            .check(kind, self.cpu.cpsr.mode)
            .map(|fault| match fault {
                FpAccessFault::UndefinedEncoding => ExecResult::Undefined,
                FpAccessFault::Undefined => {
                    ExecResult::Exception(ExceptionType::UndefinedInstruction)
                }
                FpAccessFault::Trap {
                    target_el,
                    syndrome,
                    undefined,
                } => ExecResult::FpAccessTrap {
                    target_el,
                    syndrome,
                    undefined,
                },
            });
        if access.is_some() {
            return access;
        }
        if !fp_admission::execution_supported(insn, kind.advsimd, &self.cpu.vfp) {
            // This PE synchronously bounces an unsupported scalar operating
            // mode to guest support code, after access checks, before effects.
            return Some(ExecResult::Exception(ExceptionType::UndefinedInstruction));
        }
        None
    }
}
