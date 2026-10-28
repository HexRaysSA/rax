//! A32/T32 HVC admission on an enclosing AArch64 PE.
//! Arm A32/T32 ISA v2025-03, HVC A1/T1, defines the enable and
//! constrained-unpredictable cases. This PE selects UNDEFINED for those cases.
use super::super::AArch64Cpu;
use crate::isa::arm::common::cpu::{ArmError, CpuExit};

impl AArch64Cpu {
    pub(super) fn execute_aarch32_hvc(
        &mut self,
        raw: u32,
        thumb: bool,
        in_it: bool,
    ) -> Result<CpuExit, ArmError> {
        let controls = self.pauth_controls();
        if matches!(self.current_el, 0 | 3)
            || !controls.el2_enabled()
            || (thumb && in_it)
            || (!thumb && raw >> 28 != 14)
        {
            return Err(ArmError::UndefinedInstruction(raw));
        }
        let enabled = if controls.implemented_els & (1 << 3) != 0 {
            controls.scr_el3 & (1 << 8) != 0
        } else {
            controls.hcr_el2 & (1 << 29) == 0
        };
        if !enabled {
            return Err(ArmError::UndefinedInstruction(raw));
        }
        let immediate = if thumb {
            (((raw >> 16) & 15) << 12) | (raw & 0xfff)
        } else {
            (((raw >> 8) & 0xfff) << 4) | (raw & 15)
        };
        self.clear_exclusive_monitor();
        self.pc = u64::from((self.pc as u32).wrapping_add(4));
        self.insn_count = self.insn_count.wrapping_add(1);
        self.cycle_count = self.cycle_count.wrapping_add(1);
        Ok(CpuExit::Hvc(immediate as u16))
    }
}
