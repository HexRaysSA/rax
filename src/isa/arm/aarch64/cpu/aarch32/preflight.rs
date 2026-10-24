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
            let fp_system = cp == 10 && opc1 == 7 && matches!(crn, 1 | 8);
            let thread_id =
                scalar && cp == 15 && opc1 == 0 && crn == 13 && crm == 0 && matches!(opc2, 2 | 3);
            let frequency = insn.mnemonic == Mnemonic::MRC
                && cp == 15
                && (opc1, crn, crm, opc2) == (0, 14, 0, 0);
            let counter = insn.mnemonic == Mnemonic::MRRC
                && cp == 15
                && (insn.raw >> 4) & 15 <= 1
                && crm == 14;
            if !(fp_system || thread_id || frequency || counter) {
                return Err(ArmError::UnsupportedExecutionState(format!(
                    "AArch32 coprocessor transfer {:#010x}",
                    insn.raw
                )));
            }
        }
        // Every A32/T32 Advanced SIMD and VFP mnemonic uses the V namespace.
        // System transfers are decoded as VMRS/VMSR or as MRC/MCR to CP10.
        let fp =
            insn.mnemonic.as_str().starts_with('v') || (transfer && (insn.raw >> 8) & 15 == 10);
        if fp
            && self.current_el == 0
            && uses_aarch32(self.pauth_controls(), self.sysregs.id_aa64pfr0_el1, 1) != Some(true)
        {
            let fpen = (self.sysregs.el1.cpacr >> 20) & 3;
            if fpen != 3 {
                let target = self.pauth_controls().local_exception_target();
                return Err(ArmError::ArchitecturalException {
                    ec: if target == 2 { 0 } else { 7 },
                    iss: if target == 2 {
                        0
                    } else {
                        (1 << 24) | (u32::from(insn.cond.map_or(14, |cond| cond as u8)) << 20)
                    },
                    target_el: Some(target),
                });
            }
        }
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
