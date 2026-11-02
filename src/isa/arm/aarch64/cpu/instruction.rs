//! Fetch, instruction-boundary state and retirement of AArch64 attempts.
use super::{AArch64Cpu, ArmError, CpuExit};

impl AArch64Cpu {
    /// Fetch instruction at PC.
    pub(crate) fn fetch_instruction(&self) -> Result<u32, ArmError> {
        self.read_instruction_word(self.pc)
    }

    /// Execute one instruction.
    pub(crate) fn execute_instruction(&mut self) -> Result<CpuExit, ArmError> {
        if self.aarch32.is_some() {
            return self.execute_aarch32_instruction();
        }
        self.last_instruction_size = 4;
        self.tbi_tag.store(0, std::sync::atomic::Ordering::Relaxed);
        self.last_fault_level
            .store(0, std::sync::atomic::Ordering::Relaxed);
        // Fetch instruction
        let insn = self.fetch_instruction()?;

        // Check breakpoint
        if self.breakpoints.contains(&self.pc) {
            return Ok(CpuExit::Breakpoint(self.pc as u32));
        }

        self.check_instruction_entry(insn)?;

        // Save PC and advance
        let old_pc = self.pc;
        self.pc = self.pc.wrapping_add(4);

        // Clear BTYPE (set by branches)
        let old_btype = self.btype;
        self.btype = 0;

        // Execute
        let result = self.decode_with_fp_traps(insn);

        match result {
            Ok(exit @ CpuExit::Undefined(_)) => {
                // An undefined instruction has not completed. Preserve the
                // direct-step exit shape at its original architectural frontier.
                self.pc = old_pc;
                self.btype = old_btype;
                Ok(exit)
            }
            Ok(exit) => {
                self.insn_count = self.insn_count.wrapping_add(1);
                self.cycle_count = self.cycle_count.wrapping_add(1);
                Ok(exit)
            }
            Err(mut e) => {
                // Restore PC on error
                self.pc = old_pc;
                self.btype = old_btype;
                if let ArmError::MemoryError(info) = &mut e {
                    self.retag_fault_address(info);
                }
                Err(e)
            }
        }
    }
}
