//! Selected FP/SIMD capabilities, decode admission and legacy profile migration.
use super::*;

const HALF_FIELDS: u64 = (15 << 16) | (15 << 20);
const FHM_FIELD: u64 = 15 << 48;
mod admission;
mod allocation;
mod fp16;
mod optional;

const SELECTABLE_FEATURES: ArmFeatures = ArmFeatures::from_bits_retain(
    optional::FEATURES.bits() | ArmFeatures::FP16.bits() | ArmFeatures::FHM.bits(),
);

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

fn update_half_ids(sysregs: &mut SystemRegisters, features: ArmFeatures) {
    let (half, fhm) = fields(features);
    sysregs.id_aa64pfr0_el1 = (sysregs.id_aa64pfr0_el1 & !HALF_FIELDS) | half;
    sysregs.id_aa64isar0_el1 = (sysregs.id_aa64isar0_el1 & !FHM_FIELD) | fhm;
}

fn update_ids(sysregs: &mut SystemRegisters, features: ArmFeatures) {
    update_half_ids(sysregs, features);
    optional::update_ids(sysregs, features);
}

fn migrate_legacy(sysregs: &mut SystemRegisters, features: &mut ArmFeatures) {
    // Old records had no FHM flag. Its independently reported field carries
    // optional support, subject to the architectural FP16 dependency.
    features.set(
        ArmFeatures::FHM,
        features.contains(ArmFeatures::FP16) && (sysregs.id_aa64isar0_el1 >> 48) & 15 == 1,
    );
    update_half_ids(sysregs, *features);
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
    if (insn >> 25) & 15 == 2 {
        return Some(ArmFeatures::SVE);
    }
    if !allocation::allocated(insn) || admission::reserved(insn) {
        return None;
    }
    let mut features = optional::instruction_features(insn)?;
    match fhm_encoding(insn) {
        Some(false) => return None,
        Some(true) => features |= ArmFeatures::FP16 | ArmFeatures::FHM,
        None => {}
    }
    if fp16::required(insn) {
        features |= ArmFeatures::FP16;
    }
    Some(features)
}

impl AArch64Cpu {
    /// Raw selected flags; effective FHM support also requires FP16.
    pub(crate) fn selected_fp_features(&self) -> ArmFeatures {
        self.config.features & SELECTABLE_FEATURES
    }

    /// A host policy change retains all architectural and pending private
    /// execution state. Only the selected flags, IDs and derived cache change.
    pub(crate) fn select_fp_features(&mut self, features: ArmFeatures) -> Result<(), ArmError> {
        if features.bits() & !SELECTABLE_FEATURES.bits() != 0 {
            return Err(ArmError::Configuration(
                "unsupported FP/SIMD selection bits".into(),
            ));
        }
        let retained = self.config.features.bits() & !SELECTABLE_FEATURES.bits();
        self.config.features = ArmFeatures::from_bits_retain(retained | features.bits());
        self.update_fp_id_registers();
        self.clear_jit_cache();
        Ok(())
    }

    pub(crate) fn fhm_supported(&self) -> bool {
        has_fhm(self.config.features)
    }

    pub(super) fn update_fp_id_registers(&mut self) {
        update_ids(&mut self.sysregs, self.config.features);
    }

    pub(super) fn check_fp_instruction(&self, insn: u32) -> Result<(), ArmError> {
        match instruction_features(insn) {
            Some(features)
                if self.fp_instruction_version_supported(insn)
                    && (self.config.features.contains(features)
                        || features == ArmFeatures::SVE
                            && self.config.features.contains(ArmFeatures::SME)) =>
            {
                Ok(())
            }
            _ => Err(ArmError::UndefinedInstruction(insn)),
        }
    }

    pub(super) fn fp_instruction_version_supported(&self, insn: u32) -> bool {
        !allocation::indexed_fp8_fma(insn) || self.config.version >= ArmVersion::V9_4A
    }

    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(super) fn fp_profile_key(&self) -> u64 {
        (self.selected_fp_features()
            | (self.config.features & (ArmFeatures::SVE | ArmFeatures::SME)))
            .bits()
    }

    pub(super) fn validate_optional_fp_levels(system: &SystemRegisters) -> Result<(), ArmError> {
        if !optional::supported_levels(system) {
            return Err(ArmError::Configuration(
                "unsupported optional FP/SIMD ID level".into(),
            ));
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
        if !optional::coherent(&self.sysregs, self.config.features) {
            return Err(ArmError::Configuration(
                "optional FP/SIMD IDs disagree with the selected profile".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn migrate_legacy_fp_profile(&mut self) {
        migrate_legacy(&mut self.sysregs, &mut self.config.features);
        self.clear_jit_cache();
    }

    pub(crate) fn migrate_legacy_optional_fp_profile(&mut self) -> Result<(), ArmError> {
        optional::migrate_ids(&self.sysregs, &mut self.config.features)?;
        self.clear_jit_cache();
        Ok(())
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
mod optional_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod allocation_tests;
