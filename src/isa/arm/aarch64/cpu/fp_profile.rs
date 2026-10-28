//! Selected FP16/FHM capabilities, decode admission and legacy profile migration.
use super::*;

const HALF_FIELDS: u64 = (15 << 16) | (15 << 20);
const FHM_FIELD: u64 = 15 << 48;
mod admission;
mod fp16;

fn has_fhm(features: ArmFeatures) -> bool {
    features.contains(ArmFeatures::FP16 | ArmFeatures::FHM)
}

fn fields(features: ArmFeatures) -> (u64, u64) {
    let half = u64::from(features.contains(ArmFeatures::FP16));
    (
        (half << 16) | (half << 20),
        u64::from(has_fhm(features)) << 48,
    )
}

fn update_ids(sysregs: &mut SystemRegisters, features: ArmFeatures) {
    let (half, fhm) = fields(features);
    sysregs.id_aa64pfr0_el1 = (sysregs.id_aa64pfr0_el1 & !HALF_FIELDS) | half;
    sysregs.id_aa64isar0_el1 = (sysregs.id_aa64isar0_el1 & !FHM_FIELD) | fhm;
}

fn migrate_legacy(sysregs: &mut SystemRegisters, features: &mut ArmFeatures) {
    // Old records had no FHM flag. Its independently reported field carries
    // optional support, subject to the architectural FP16 dependency.
    features.set(
        ArmFeatures::FHM,
        features.contains(ArmFeatures::FP16) && (sysregs.id_aa64isar0_el1 >> 48) & 15 == 1,
    );
    update_ids(sysregs, *features);
}

/// Recognize the two AdvSIMD FHM encoding classes. Some(false) is a reserved
/// size in that class; it must be rejected before FP access-control traps.
pub(super) fn fhm_encoding(insn: u32) -> Option<bool> {
    let vector = insn & 0x1f20_0400 == 0x0e20_0400;
    let u = (insn >> 29) & 1;
    let opcode = (insn >> 11) & 31;
    if vector && ((u == 0 && opcode == 29) || (u == 1 && opcode == 25)) {
        return Some(insn & ((1 << 31) | (1 << 22)) == 0);
    }
    let indexed = insn & 0x1fc0_3400 == 0x0f80_0000 && (insn >> 15) & 1 == u;
    indexed.then_some(insn & (1 << 31) == 0)
}

/// Feature dependencies of an original instruction, before IR optimization.
/// None denotes a reserved encoding that must never be promoted.
pub(super) fn instruction_features(insn: u32) -> Option<ArmFeatures> {
    if admission::reserved(insn) {
        return None;
    }
    match fhm_encoding(insn) {
        Some(false) => None,
        Some(true) => Some(ArmFeatures::FP16 | ArmFeatures::FHM),
        None if fp16::required(insn) => Some(ArmFeatures::FP16),
        None => Some(ArmFeatures::empty()),
    }
}

impl AArch64Cpu {
    pub(crate) fn fhm_supported(&self) -> bool {
        has_fhm(self.config.features)
    }

    pub(super) fn update_fp_id_registers(&mut self) {
        update_ids(&mut self.sysregs, self.config.features);
    }

    pub(super) fn check_fhm_instruction(&self, insn: u32) -> Result<(), ArmError> {
        if let Some(legal) = fhm_encoding(insn)
            && (!legal || !self.fhm_supported())
        {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        Ok(())
    }

    pub(super) fn check_fp_instruction(&self, insn: u32) -> Result<(), ArmError> {
        self.check_fhm_instruction(insn)?;
        if admission::reserved(insn)
            || (!self.config.features.contains(ArmFeatures::FP16) && fp16::required(insn))
        {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        Ok(())
    }

    pub(crate) fn validate_fp_profile(&self) -> Result<(), ArmError> {
        let (half, fhm) = fields(self.config.features);
        if self.sysregs.id_aa64pfr0_el1 & HALF_FIELDS != half
            || self.sysregs.id_aa64isar0_el1 & FHM_FIELD != fhm
        {
            return Err(ArmError::Configuration(
                "FP16/FHM IDs disagree with the selected profile".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn migrate_legacy_fp_profile(&mut self) {
        migrate_legacy(&mut self.sysregs, &mut self.config.features);
        self.clear_jit_cache();
    }

    /// Upgrade the FP capability fields in a legacy public register-only
    /// checkpoint. Current private records validate their original projections
    /// before performing this migration; callers must not apply it to them.
    pub fn migrate_legacy_fp_state(system: &mut Aarch64SystemRegisters) {
        if let Some(execution) = &mut system.execution {
            let mut features = ArmFeatures::from_bits_retain(execution.features);
            migrate_legacy(&mut execution.sysregs, &mut features);
            execution.features = features.bits();
        }
    }
}

#[cfg(test)]
mod half_tests;
#[cfg(test)]
mod tests;
