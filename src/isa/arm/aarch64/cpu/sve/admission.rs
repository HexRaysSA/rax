//! Primary-derived SVE encoding, capability, and normal-execution admission.
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::common::cpu::{ArmError, CpuExit};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::fp_access::FpAccessClass;

include!("profile_encodings.rs");

pub(in crate::isa::arm::aarch64::cpu) const FEATURES: ArmFeatures =
    ArmFeatures::from_bits_retain(PROFILE_FEATURES);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::isa::arm::aarch64::cpu) enum Access {
    Sve,
    Sme,
    Streaming,
}

pub(in crate::isa::arm::aarch64::cpu) struct Selection {
    pub features: ArmFeatures,
    pub access: Access,
}

fn encodings(instruction: u32) -> &'static [(u32, u32, u64, u8)] {
    if (instruction >> 25) & 15 != 2 {
        return &[];
    }
    let bucket = (((instruction >> 29) << 5)
        | (((instruction >> 24) & 1) << 4)
        | ((instruction >> 12) & 15)) as usize;
    let begin = usize::from(PROFILE_OFFSETS[bucket]);
    let end = usize::from(PROFILE_OFFSETS[bucket + 1]);
    &PROFILE_ENCODINGS[begin..end]
}

/// No represented extension combination allocates this instruction word.
pub(in crate::isa::arm::aarch64::cpu) fn reserved(instruction: u32) -> bool {
    !encodings(instruction)
        .iter()
        .any(|&(mask, value, _, _)| instruction & mask == value)
}

/// Retain a satisfied allocation clause and its selected access-path guards.
/// Native optimization must not erase either kind of dependency.
pub(in crate::isa::arm::aarch64::cpu) fn selected(
    instruction: u32,
    features: ArmFeatures,
) -> Option<Selection> {
    encodings(instruction)
        .iter()
        .find_map(|&(mask, value, required, policy)| {
            let mut required = ArmFeatures::from_bits_retain(required);
            if instruction & mask != value || !features.contains(required) {
                return None;
            }
            let access = match policy {
                1 => Access::Sve,
                2 => Access::Sme,
                3 if features.contains(ArmFeatures::SVE2P1) => {
                    // The SME2 allocation alternative does not imply that
                    // normal SVE access remains valid after SVE2p1 is removed.
                    required |= ArmFeatures::SVE2P1;
                    Access::Sve
                }
                3 => Access::Streaming,
                _ => return None,
            };
            Some(Selection {
                features: required,
                access,
            })
        })
}

impl AArch64Cpu {
    pub(in crate::isa::arm::aarch64::cpu) fn sve_instruction_selection(
        &self,
        instruction: u32,
    ) -> Result<Selection, ArmError> {
        if !self
            .config
            .features
            .intersects(ArmFeatures::SVE | ArmFeatures::SME)
        {
            return Err(ArmError::UndefinedInstruction(instruction));
        }
        selected(instruction, self.config.features)
            .ok_or(ArmError::UndefinedInstruction(instruction))
    }

    pub(crate) fn exec_sve(&mut self, instruction: u32) -> Result<CpuExit, ArmError> {
        if !self
            .config
            .features
            .intersects(ArmFeatures::SVE | ArmFeatures::SME)
        {
            return Err(ArmError::UndefinedInstruction(instruction));
        }
        if reserved(instruction) {
            return Ok(CpuExit::Undefined(instruction));
        }
        let selection = self.sve_instruction_selection(instruction)?;
        match selection.access {
            Access::Sve => self.check_sve_access(instruction)?,
            Access::Sme => {
                if !self.config.features.contains(ArmFeatures::SME) {
                    return Err(ArmError::UndefinedInstruction(instruction));
                }
                self.check_fp_access(FpAccessClass::Sme)?;
                return self.exec_sme_scalar_length(instruction);
            }
            Access::Streaming => self.check_streaming_sve_access(instruction)?,
        }
        self.exec_sve_inner(instruction)
    }
}
