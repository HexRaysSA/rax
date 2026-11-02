//! Predicate/access admission precedes the optional FP destination transaction.
use super::*;
impl<'a, M: ArmMemory> Executor<'a, M> {
    pub fn execute(&mut self, insn: &DecodedInsn) -> ExecResult {
        self.cpu.instruction_size = insn.size;
        if !self.condition_matches(insn) {
            return ExecResult::Continue;
        }
        if let Some(fault) = self.fp_access_fault(insn) {
            return fault;
        }
        let pending = crate::isa::arm::aarch32::fp_traps::Transaction::begin(self.cpu, insn);
        let result = self.execute_admitted(insn);
        match pending {
            Some(pending) => pending.finish(self.cpu, result),
            None => result,
        }
    }
}
