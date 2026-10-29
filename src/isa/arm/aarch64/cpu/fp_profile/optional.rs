//! Selected non-SVE FP/SIMD capability fields and original instruction needs.
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::common::cpu::ArmError;
use crate::isa::arm::common::features::ArmFeatures;

#[path = "optional_admission.rs"]
mod admission;
include!("optional_encodings.rs");

pub(super) const FEATURES: ArmFeatures = ArmFeatures::from_bits_retain(
    ArmFeatures::JSCVT.bits()
        | ArmFeatures::FCMA.bits()
        | ArmFeatures::FRINTTS.bits()
        | ArmFeatures::BF16.bits()
        | ArmFeatures::I8MM.bits()
        | ArmFeatures::DOTPROD.bits(),
);

// Arm DDI0616 B.a E3.2.11; DP is ID_AA64ISAR0_EL1[47:44].
const FIELDS: [(ArmFeatures, bool, u32); 6] = [
    (ArmFeatures::JSCVT, true, 12),
    (ArmFeatures::FCMA, true, 16),
    (ArmFeatures::FRINTTS, true, 32),
    (ArmFeatures::BF16, true, 44),
    (ArmFeatures::I8MM, true, 52),
    (ArmFeatures::DOTPROD, false, 44),
];

fn value(system: &SystemRegisters, isar1: bool, shift: u32) -> u64 {
    let register = if isar1 {
        system.id_aa64isar1_el1
    } else {
        system.id_aa64isar0_el1
    };
    (register >> shift) & 15
}

pub(super) fn supported_levels(system: &SystemRegisters) -> bool {
    FIELDS
        .iter()
        .all(|&(_, isar1, shift)| value(system, isar1, shift) <= 1)
}

pub(super) fn update_ids(system: &mut SystemRegisters, features: ArmFeatures) {
    for (feature, isar1, shift) in FIELDS {
        let register = if isar1 {
            &mut system.id_aa64isar1_el1
        } else {
            &mut system.id_aa64isar0_el1
        };
        *register = (*register & !(15 << shift)) | (u64::from(features.contains(feature)) << shift);
    }
}

pub(super) fn coherent(system: &SystemRegisters, features: ArmFeatures) -> bool {
    FIELDS.iter().all(|&(feature, isar1, shift)| {
        value(system, isar1, shift) == u64::from(features.contains(feature))
    })
}

pub(super) fn migrate_ids(
    system: &SystemRegisters,
    features: &mut ArmFeatures,
) -> Result<(), ArmError> {
    // Admit the entire source before changing flags. Higher capability levels
    // cannot be represented by these six base-feature flags.
    if !supported_levels(system) {
        return Err(ArmError::Configuration(
            "unsupported legacy optional FP/SIMD ID level".into(),
        ));
    }
    let mut selected = *features;
    for (feature, isar1, shift) in FIELDS {
        selected.set(feature, value(system, isar1, shift) == 1);
    }
    *features = selected;
    Ok(())
}

pub(super) fn instruction_features(word: u32) -> Option<ArmFeatures> {
    if !matches!((word >> 25) & 15, 7 | 15) {
        return Some(ArmFeatures::empty());
    }
    if admission::reserved(word) {
        return None;
    }
    let mut required = ArmFeatures::empty();
    for &(mask, value, feature) in OPTIONAL_ENCODINGS {
        if word & mask == value {
            required |= feature;
        }
    }
    Some(required)
}
