//! Original-word native admission before optimization can erase effects.
use super::*;
use crate::isa::arm::common::fp_access::FpAccessRequirements;
use crate::isa::arm::decoder::{Mnemonic, aarch64::Aarch64Decoder};

// These instructions own CPU wait/event or exclusive-monitor state which the
// generic native register file does not represent. A NOP-shaped lift must not
// erase their interpreter exit, event consumption, or local monitor effects.
fn native_control_requires_interpretation(word: u32) -> bool {
    Aarch64Decoder::decode(word).is_ok_and(|instruction| {
        matches!(
            instruction.mnemonic,
            Mnemonic::WFE
                | Mnemonic::WFI
                | Mnemonic::WFET
                | Mnemonic::WFIT
                | Mnemonic::SEV
                | Mnemonic::SEVL
                | Mnemonic::CLREX
        )
    })
}

impl AArch64Cpu {
    pub(super) fn native_requirements(
        &self,
        function: &crate::smir::ir::SmirFunction,
        entry: u64,
        bytes: &[u8],
    ) -> Option<(FpAccessRequirements, ArmFeatures)> {
        if self.fp_traps_enabled() {
            return None;
        }
        let mut requirements = FpAccessRequirements::default();
        let mut features = ArmFeatures::empty();
        for op in function.blocks.iter().flat_map(|b| &b.ops) {
            let Some(offset) = op
                .guest_pc
                .checked_sub(entry)
                .and_then(|n| usize::try_from(n).ok())
            else {
                continue;
            };
            let Some(end) = offset.checked_add(4) else {
                continue;
            };
            if let Some(word) = bytes.get(offset..end) {
                let word = u32::from_le_bytes(word.try_into().unwrap());
                if native_control_requires_interpretation(word) {
                    return None;
                }
                if !self.fp_instruction_version_supported(word) {
                    return None;
                }
                // This native register image has no streaming-mode state.
                // SME-only SVE words must reach the interpreter's access and
                // NotStreaming checks before any effects.
                if (word >> 25) & 15 == 2 {
                    let selection = self.sve_instruction_selection(word).ok()?;
                    if !self.config.features.contains(ArmFeatures::SVE)
                        || selection.access != super::sve::admission::Access::Sve
                    {
                        return None;
                    }
                    features |= selection.features | ArmFeatures::SVE;
                } else {
                    features |= super::fp_profile::instruction_features(word)?;
                }
                requirements.observe(word);
            }
        }
        // Preserve the existing policy for helper-generated FP operations that
        // do not carry an instruction PC inside the supplied lift window.
        if !requirements.data
            && !requirements.system
            && crate::smir::lower::aarch64::uses_aarch64_fp_trampoline(function)
        {
            requirements.data = true;
        }
        Some((requirements, features))
    }
}
