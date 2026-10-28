//! Admission of existing AArch32 semantics over a mixed-width PE. In
//! particular, the standalone v7 CPU's reset CP15 values are not guest state.

use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::exception_return::uses_aarch32;
use crate::isa::arm::common::cpu::ArmError;
use crate::isa::arm::decoder::{DecodedInsn, Mnemonic};

impl AArch64Cpu {
    pub(super) fn check_aarch32_translation_regime(&self) -> Result<(), ArmError> {
        let controls = self.pauth_controls();
        let regime = controls.regime_el();
        if controls.sctlr[regime] & 1 != 0
            && uses_aarch32(controls, self.sysregs.id_aa64pfr0_el1, regime as u8) == Some(true)
        {
            // The enclosing walk implements AArch64 descriptors. Neither
            // AArch32 short descriptors nor TTBCR.EAE may enter that walk.
            return Err(ArmError::UnsupportedExecutionState(
                "AArch32 translation regime".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn check_aarch32_instruction(&self, insn: &DecodedInsn) -> Result<(), ArmError> {
        let transfer = matches!(
            insn.mnemonic,
            Mnemonic::MCR
                | Mnemonic::MRC
                | Mnemonic::MCRR
                | Mnemonic::MRRC
                | Mnemonic::VMSR
                | Mnemonic::VMRS
        );
        if transfer {
            let cp = (insn.raw >> 8) & 15;
            let crn = (insn.raw >> 16) & 15;
            let opc1 = (insn.raw >> 21) & 7;
            let crm = insn.raw & 15;
            let opc2 = (insn.raw >> 5) & 7;
            let scalar = matches!(insn.mnemonic, Mnemonic::MRC | Mnemonic::MCR);
            let fp_system = matches!(cp, 10 | 11);
            let fp_control = scalar
                && cp == 15
                && ((opc1, crn, crm, opc2) == (0, 1, 0, 2)
                    || (opc1, crn, crm, opc2) == (4, 1, 1, 2)
                    || (opc1, crn, crm, opc2) == (4, 1, 1, 0));
            let fhm_id = insn.mnemonic == Mnemonic::MRC
                && cp == 15
                && (opc1, crn, crm, opc2) == (0, 0, 2, 7);
            let thread_id =
                scalar && cp == 15 && opc1 == 0 && crn == 13 && crm == 0 && matches!(opc2, 2 | 3);
            let frequency = insn.mnemonic == Mnemonic::MRC
                && cp == 15
                && (opc1, crn, crm, opc2) == (0, 14, 0, 0);
            let counter = insn.mnemonic == Mnemonic::MRRC
                && cp == 15
                && (insn.raw >> 4) & 15 <= 1
                && crm == 14;
            if !(fp_system || fp_control || fhm_id || thread_id || frequency || counter) {
                return Err(ArmError::UnsupportedExecutionState(format!(
                    "AArch32 coprocessor transfer {:#010x}",
                    insn.raw
                )));
            }
        }
        // The shared A32 executor checks FP permissions using an enclosing-PE
        // control view before performing any register or memory effects.
        Ok(())
    }
}

/// Faults raised by the executor before the memory trait is called (notably
/// exclusive alignment checks) still retain their read/write intent.
pub(super) fn data_access(mnemonic: Mnemonic) -> crate::isa::arm::common::cpu::AccessType {
    use crate::isa::arm::common::cpu::AccessType;
    if matches!(
        mnemonic,
        Mnemonic::STR
            | Mnemonic::STRB
            | Mnemonic::STRH
            | Mnemonic::STP
            | Mnemonic::STXR
            | Mnemonic::STLXR
            | Mnemonic::STXRB
            | Mnemonic::STLXRB
            | Mnemonic::STXRH
            | Mnemonic::STLXRH
            | Mnemonic::STXP
            | Mnemonic::STLXP
            | Mnemonic::STLR
            | Mnemonic::STLRB
            | Mnemonic::STLRH
            | Mnemonic::STM
            | Mnemonic::STMIA
            | Mnemonic::STMIB
            | Mnemonic::STMDA
            | Mnemonic::STMDB
            | Mnemonic::PUSH
            | Mnemonic::SRS
            | Mnemonic::VSTR
            | Mnemonic::VSTM
            | Mnemonic::VPUSH
            | Mnemonic::VST1
            | Mnemonic::VST2
            | Mnemonic::VST3
            | Mnemonic::VST4
    ) {
        AccessType::Write
    } else {
        AccessType::Read
    }
}
