//! Scalar SME length arithmetic for the fixed 128-bit implemented SVL.
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};

// This implementation choice is independent of the normal SVE vector length.
// Arm XML 2025-12 CurrentSVL and the three instruction operations define the
// effective lengths; variable SME/ZA state remains a separate implementation.
const IMPLEMENTED_SVL_BITS: i64 = 128;

impl AArch64Cpu {
    /// Called only after instruction admission and CheckSMEEnabled succeed.
    pub(super) fn exec_sme_scalar_length(&mut self, instruction: u32) -> Result<CpuExit, ArmError> {
        let destination = (instruction & 31) as u8;
        let immediate = (((instruction >> 5) & 63) as i64) << 58 >> 58;
        let vector_bytes = IMPLEMENTED_SVL_BITS / 8;
        if instruction & 0xffff_f800 == 0x04bf_5800 {
            // RDSVL uses XZR for register 31; it cannot change SP.
            self.set_x(destination, (immediate * vector_bytes) as u64);
            return Ok(CpuExit::Continue);
        }
        let scale = match instruction & 0xffe0_f800 {
            0x0420_5800 => vector_bytes,              // ADDSVL
            0x0460_5800 => IMPLEMENTED_SVL_BITS / 64, // ADDSPL
            _ => return Ok(CpuExit::Undefined(instruction)),
        };
        let source = ((instruction >> 16) & 31) as u8;
        let base = if source == 31 {
            self.get_sp()
        } else {
            self.get_x(source)
        };
        let result = base.wrapping_add((immediate * scale) as u64);
        self.set_gpr_or_sp(destination, result);
        Ok(CpuExit::Continue)
    }
}
