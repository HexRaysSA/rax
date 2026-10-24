//! Precise illegal-state and branch-target checks at instruction entry.

use super::*;

impl AArch64Cpu {
    /// Fetch through the CPU's exact instruction permission/translation path
    /// and expose the resulting source-page GP metadata to a SMIR backend.
    pub(crate) fn smir_fetch_guarded(&self, pc: u64) -> Result<bool, ArmError> {
        self.tbi_tag.store(0, std::sync::atomic::Ordering::Relaxed);
        self.last_fault_level
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.read_instruction_word(pc)?;
        Ok(self
            .instruction_guarded
            .load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Decode-time checks precede PC advance, BTYPE clearing, and all effects.
    pub(super) fn check_instruction_entry(&self, instruction: u32) -> Result<(), ArmError> {
        self.pauth_environment()
            .check_entry(
                instruction,
                self.pstate_bits(),
                Some(
                    self.instruction_guarded
                        .load(std::sync::atomic::Ordering::Relaxed),
                ),
            )
            .map_err(|error| Self::pauth_error(instruction, error))
    }
}
