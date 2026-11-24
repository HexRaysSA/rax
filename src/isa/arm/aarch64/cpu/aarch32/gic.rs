//! AArch32 aliases of the enclosing PE's physical GICv3 CPU interface.

use super::AArch64Cpu;
use crate::isa::arm::aarch32::cpu::Armv7Cpu;
use crate::isa::arm::aarch32::instructions::ExecResult;
use crate::isa::arm::common::cpu::ArmError;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::isa::arm::decoder::{DecodedInsn, Mnemonic};

#[cfg(test)]
mod tests;

const FMO: u64 = 1 << 3;
const IMO: u64 = 1 << 4;

#[derive(Clone, Copy)]
enum Access {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

struct Transfer {
    register: Aarch64SysRegEncoding,
    access: Access,
    hstr_selector: u8,
    interrupt_override: u64,
    high_word: Option<usize>,
}

impl Transfer {
    fn decode(instruction: &DecodedInsn) -> Option<Self> {
        use Access::{ReadOnly, ReadWrite, WriteOnly};
        let raw = instruction.raw;
        if (raw >> 8) & 15 != 15 || raw >> 28 == 15 {
            return None;
        }
        let crm = (raw & 15) as u8;
        // Arm IHI 0069H Table 12-7. CP15 pair encodings use CRm for
        // HSTR and do not share the scalar transfer's register fields.
        if matches!(instruction.mnemonic, Mnemonic::MCRR | Mnemonic::MRRC) {
            let opc1 = ((raw >> 4) & 15) as u8;
            if crm != 12 || opc1 > 2 {
                return None;
            }
            return Some(Self {
                register: Aarch64SysRegEncoding::new(3, 0, 12, 11, 5 + opc1),
                access: WriteOnly,
                hstr_selector: crm,
                interrupt_override: FMO | IMO,
                high_word: Some(((raw >> 16) & 15) as usize),
            });
        }
        if !matches!(instruction.mnemonic, Mnemonic::MCR | Mnemonic::MRC) || (raw >> 21) & 7 != 0 {
            return None;
        }
        let crn = ((raw >> 16) & 15) as u8;
        let opc2 = ((raw >> 5) & 7) as u8;
        let (access, interrupt_override) = match (crn, crm, opc2) {
            (4, 6, 0) => (ReadWrite, FMO | IMO),                  // PMR
            (12, 8, 0 | 2) => (ReadOnly, FMO),                    // IAR0, HPPIR0
            (12, 8, 1) => (WriteOnly, FMO),                       // EOIR0
            (12, 8, 3..=7) | (12, 12, 6) => (ReadWrite, FMO),     // BPR0, AP0R<n>, IGRPEN0
            (12, 9, 0..=3) | (12, 12, 3 | 7) => (ReadWrite, IMO), // AP1R<n>, BPR1, IGRPEN1
            (12, 12, 0 | 2) => (ReadOnly, IMO),                   // IAR1, HPPIR1
            (12, 12, 1) => (WriteOnly, IMO),                      // EOIR1
            (12, 11, 1) => (WriteOnly, FMO | IMO),                // DIR
            (12, 11, 3) => (ReadOnly, FMO | IMO),                 // RPR
            (12, 12, 4) => (ReadWrite, FMO | IMO),                // CTLR
            (12, 12, 5) => (ReadWrite, 0),                        // SRE stays physical
            _ => return None,
        };
        Some(Self {
            register: Aarch64SysRegEncoding::new(3, 0, crn, crm, opc2),
            access,
            hstr_selector: crn,
            interrupt_override,
            high_word: None,
        })
    }
}

impl AArch64Cpu {
    pub(super) fn execute_aarch32_gic_transfer(
        &mut self,
        instruction: &DecodedInsn,
        state: &mut Armv7Cpu,
    ) -> Result<Option<ExecResult>, ArmError> {
        let Some(transfer) = Transfer::decode(instruction) else {
            return Ok(None);
        };
        if self.current_el == 0 {
            return Ok(Some(ExecResult::Undefined));
        }
        let context = self.aarch32_fp_context();
        if context.traps_cp15(transfer.hstr_selector) {
            // The common CP15 executor emits the syndrome with the correct
            // target width, transfer registers and A32/T32 predicate.
            return Ok(None);
        }
        if self.gic.is_none() || (self.sysregs.id_aa64pfr0_el1 >> 4) & 15 != 2 {
            return Ok(Some(ExecResult::Undefined));
        }
        let register = ((instruction.raw >> 12) & 15) as usize;
        let read = instruction.mnemonic == Mnemonic::MRC;
        let admitted = match instruction.mnemonic {
            Mnemonic::MRC => !matches!(transfer.access, Access::WriteOnly),
            Mnemonic::MCR | Mnemonic::MCRR => {
                !matches!(transfer.access, Access::ReadOnly)
                    && register != 15
                    && transfer.high_word != Some(15)
            }
            _ => false,
        };
        if !admitted {
            return Ok(Some(ExecResult::Undefined));
        }
        let el2_override = self.current_el == 1
            && context.el2_enabled
            && context.hcr & transfer.interrupt_override != 0;
        // Common registers require both SCR_EL3 routing bits. Group-specific
        // registers require only the corresponding IRQ or FIQ bit.
        let scr_routing = match transfer.interrupt_override {
            FMO => 1 << 2,
            IMO => 1 << 1,
            0 => 0,
            _ => 3 << 1,
        };
        let el3_override = context.have_el3
            && scr_routing != 0
            && self.sysregs.scr_el3 & scr_routing == scr_routing;
        if el2_override || el3_override {
            return Err(ArmError::UnsupportedExecutionState(
                "AArch32 GIC interface with interrupt routing overrides".into(),
            ));
        }
        if read {
            let Some(value) = self.read_icc(transfer.register) else {
                return Ok(Some(ExecResult::Undefined));
            };
            if register == 15 {
                state.cpsr.n = value & (1 << 31) != 0;
                state.cpsr.z = value & (1 << 30) != 0;
                state.cpsr.c = value & (1 << 29) != 0;
                state.cpsr.v = value & (1 << 28) != 0;
            } else {
                state.regs[register] = value as u32;
            }
        } else {
            let mut value = u64::from(state.regs[register]);
            if let Some(high) = transfer.high_word {
                value |= u64::from(state.regs[high]) << 32;
            }
            if !self.write_icc(transfer.register, value) {
                return Ok(Some(ExecResult::Undefined));
            }
        }
        Ok(Some(ExecResult::Continue))
    }
}
