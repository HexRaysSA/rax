//! One admitted VFP instruction, with at most eight register-bank iterations.
use super::*;

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn exec_short_vector(&mut self, insn: &DecodedInsn) -> Option<ExecResult> {
        let plan = match crate::isa::arm::aarch32::short_vectors::plan(insn, &self.cpu.vfp) {
            Ok(Some(plan)) => plan,
            Ok(None) => return None,
            Err(()) => return Some(ExecResult::Undefined),
        };
        // These admitted data-processing forms access only VFP state. Retain
        // it so a future scalar-handler rejection cannot expose a prefix.
        let before = self.cpu.vfp.clone();
        for iteration in 0..plan.iterations {
            let element = plan.instruction(insn, iteration);
            let result = match element.mnemonic {
                Mnemonic::VADD
                | Mnemonic::VSUB
                | Mnemonic::VMUL
                | Mnemonic::VDIV
                | Mnemonic::VNMUL => self.exec_vfp_binop(&element),
                Mnemonic::VMLA | Mnemonic::VMLS | Mnemonic::VNMLA | Mnemonic::VNMLS => {
                    self.exec_vfp_accop(&element)
                }
                Mnemonic::VABS | Mnemonic::VNEG | Mnemonic::VSQRT => self.exec_vfp_unop(&element),
                Mnemonic::VMOV => self.exec_vmov(&element),
                _ => ExecResult::Undefined,
            };
            if !matches!(result, ExecResult::Continue) {
                self.cpu.vfp = before;
                return Some(result);
            }
        }
        Some(ExecResult::Continue)
    }
}
