//! Shared standalone/mixed-width FP access classification and policy.
use super::*;
use crate::isa::arm::aarch32::fp_controls::{FpAccessFault, fp_access_kind};

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn fp_data_enabled(&self) -> bool {
        self.cpu.fp_control_context().effective_fpexc_enabled()
    }

    pub(super) fn fp_access_fault(&self, insn: &DecodedInsn) -> Option<ExecResult> {
        let mut kind = fp_access_kind(insn)?;
        if insn.state.is_thumb() && self.cpu.cpsr.in_it_block() {
            kind.condition = self.cpu.cpsr.it_condition();
        }
        self.cpu
            .fp_control_context()
            .check(kind)
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
            })
    }
}
