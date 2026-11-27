//! Shared standalone/mixed-width FP access classification and policy.
use super::*;
use crate::isa::arm::aarch32::fp_admission;
use crate::isa::arm::aarch32::fp_controls::{FpAccessFault, fp_access_kind};

fn thumb_fp_transfer_uses_sp(insn: &DecodedInsn, system_transfer: bool) -> bool {
    let raw = insn.raw;
    let rt_is_sp = (raw >> 12) & 15 == 13;
    if system_transfer {
        return rt_is_sp;
    }
    match insn.mnemonic {
        // Core transfer of a doubleword or two consecutive singlewords.
        Mnemonic::VMOV if raw & 0x0fe0_0000 == 0x0c40_0000 => rt_is_sp || (raw >> 16) & 15 == 13,
        // Singleword or lane VMOV and core-to-vector VDUP use Rt in [15:12].
        Mnemonic::VMOV | Mnemonic::VDUP => raw & 0x0f00_0010 == 0x0e00_0010 && rt_is_sp,
        _ => false,
    }
}

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn fp_data_enabled(&self) -> bool {
        self.cpu.fp_control_context().effective_fpexc_enabled()
    }

    pub(super) fn fp_access_fault(&self, insn: &DecodedInsn) -> Option<ExecResult> {
        let mut kind = fp_access_kind(insn)?;
        let in_it = insn.state.is_thumb() && self.cpu.cpsr.in_it_block();
        let standalone = self.cpu.fp_access_context.is_none();
        let arm11 = standalone && self.cpu.vfp.is_arm11();
        // Predicate failure has already skipped the instruction. Choose
        // Undefined for executed restricted encodings before FP access traps.
        if arm11 && insn.state.is_thumb()
            || !fp_admission::predicate_supported(insn, kind.advsimd, in_it)
        {
            return Some(ExecResult::Undefined);
        }
        // Capability absence is a decode failure, before FP access traps and
        // before the handler can modify any architectural state.
        if !fp_admission::instruction_supported(
            insn,
            kind.advsimd,
            &self.cpu.vfp,
            self.cpu.cp15.id_isar[5],
            self.cpu.cp15.id_isar6,
        ) {
            return Some(ExecResult::Undefined);
        }
        if in_it {
            kind.condition = self.cpu.cpsr.it_condition();
        }
        let vfpv2 = matches!((self.cpu.vfp.mvfr0 >> 4) & 0xff, 0x01 | 0x11);
        let legacy_transfers = standalone && self.cpu.legacy_fp_transfers.unwrap_or(vfpv2);
        // Arm DDI0406C.d Table B1-24 reserves selector 5. Its VMRS, VMSR,
        // VMOV and VDUP Thumb encodings also constrain the core SP operand.
        if legacy_transfers
            && (kind.system_read == Some(5)
                || insn.state.is_thumb() && thumb_fp_transfer_uses_sp(insn, kind.system_transfer))
        {
            return Some(ExecResult::Undefined);
        }
        if kind.system_transfer && legacy_transfers && vfpv2 {
            // ARM1176 Table 20-4 permits User reads of FPSID and MVFR0/1
            // while enabled. Other VFPv2 profiles follow DDI0406C.d B1.11.2.
            let user_read = if arm11 {
                matches!(kind.system_read, Some(0 | 6 | 7)) && self.cpu.vfp.is_enabled()
            } else {
                kind.system_read == Some(0)
            };
            if user_read {
                kind.privileged_only = false;
            }
        }
        let access = self
            .cpu
            .fp_control_context()
            .check(kind, self.cpu.cpsr.mode)
            .map(|fault| match fault {
                FpAccessFault::UndefinedEncoding => ExecResult::Undefined,
                FpAccessFault::Undefined => {
                    ExecResult::Exception(ExceptionType::UndefinedInstruction)
                }
                FpAccessFault::Trap {
                    target_el,
                    syndrome,
                    undefined,
                } => ExecResult::FpAccessTrap {
                    target_el,
                    syndrome,
                    undefined,
                },
            });
        if access.is_some() {
            return access;
        }
        if !fp_admission::execution_supported(insn, kind.advsimd, &self.cpu.vfp) {
            // This PE synchronously bounces an unsupported scalar operating
            // mode to guest support code, after access checks, before effects.
            return Some(ExecResult::Exception(ExceptionType::UndefinedInstruction));
        }
        None
    }
}
