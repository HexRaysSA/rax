//! Optional synchronous whole-instruction FP exception policy.
use super::{
    cpu::Armv7Cpu,
    fp_controls::fp_access_kind,
    instructions::{ExceptionType, ExecResult},
    vfp::{Fpscr, VfpState},
};
use crate::isa::arm::decoder::{DecodedInsn, Mnemonic};
pub(crate) const STATUS: u32 = 0x9f;
pub(crate) const ENABLES: u32 = STATUS << 8;
/// Storage/system transfers never process IEEE operands. In particular their
/// memory and read-only-register effects must not be replayed or masked.
pub(crate) fn is_computation(insn: &DecodedInsn) -> bool {
    fp_access_kind(insn).is_some_and(|kind| !kind.advsimd)
        && !matches!(
            insn.mnemonic,
            Mnemonic::VMRS
                | Mnemonic::VMSR
                | Mnemonic::MRC
                | Mnemonic::MCR
                | Mnemonic::MRRC
                | Mnemonic::MCRR
                | Mnemonic::MRC2
                | Mnemonic::MCR2
                | Mnemonic::CDP
                | Mnemonic::CDP2
                | Mnemonic::VMOV
                | Mnemonic::VMOV_F16_CORE
                | Mnemonic::VMOVX_F16
                | Mnemonic::VINS_F16
                | Mnemonic::VLDR
                | Mnemonic::VSTR
                | Mnemonic::VLDM
                | Mnemonic::VSTM
                | Mnemonic::VPUSH
                | Mnemonic::VPOP
                | Mnemonic::VLD1
                | Mnemonic::VLD2
                | Mnemonic::VLD3
                | Mnemonic::VLD4
                | Mnemonic::VST1
                | Mnemonic::VST2
                | Mnemonic::VST3
                | Mnemonic::VST4
        )
}
pub(crate) struct Transaction {
    saved: VfpState,
    enabled: u32,
}
impl Transaction {
    pub(crate) fn begin(cpu: &mut Armv7Cpu, insn: &DecodedInsn) -> Option<Self> {
        let mut enabled = (cpu.vfp.fpscr.bits() >> 8) & STATUS;
        if super::fp_admission::output_flushes(insn, &cpu.vfp) {
            enabled &= !8;
        }
        if enabled == 0 || !cpu.vfp.trapping_profile() || !is_computation(insn) {
            return None;
        }
        let saved = cpu.vfp.clone();
        cpu.vfp.fpscr = Fpscr::from_bits(saved.fpscr.bits() & !STATUS);
        Some(Self { saved, enabled })
    }
    pub(crate) fn finish(self, cpu: &mut Armv7Cpu, result: ExecResult) -> ExecResult {
        if !matches!(result, ExecResult::Continue) {
            cpu.vfp = self.saved;
            return result;
        }
        let current = cpu.vfp.fpscr.bits();
        let exceptions = current & STATUS;
        if exceptions & self.enabled == 0 {
            cpu.vfp.fpscr =
                Fpscr::from_bits(current | (self.saved.fpscr.bits() & (STATUS | ENABLES)));
            return result;
        }
        cpu.vfp = self.saved;
        cpu.vfp.fpscr = Fpscr::from_bits(cpu.vfp.fpscr.bits() | (exceptions & !self.enabled));
        let context = cpu.fp_control_context();
        let to_el2 = context.el2_enabled && context.el2_aarch64 && context.hcr & (1 << 27) != 0;
        if context.current_el == 0 && context.el1_aarch64 || to_el2 {
            return ExecResult::FpAccessTrap {
                target_el: if to_el2 { 2 } else { 1 },
                syndrome: (0x28 << 26)
                    | (1 << 25)
                    | (1 << 23)
                    | 0x700
                    | (exceptions & self.enabled),
                undefined: false,
            };
        }
        cpu.vfp.fpexc =
            (cpu.vfp.read_fpexc() & !STATUS) | 0x2400_0700 | (exceptions & self.enabled);
        ExecResult::Exception(ExceptionType::FloatingPoint(
            (exceptions & self.enabled) as u8,
        ))
    }
}
