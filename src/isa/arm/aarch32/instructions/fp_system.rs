//! CP15 access policy for the represented FP/security/virtualization controls.
use super::*;
use crate::isa::arm::aarch32::fp_admission::{effective_id_isar5, effective_id_isar6};
use crate::isa::arm::aarch64::aarch32_state::system_trap_rt;
use crate::isa::arm::common::sysreg::Cp15Encoding;

const CPACR: (u8, u8, u8, u8) = (1, 0, 0, 2);
const HCPTR: (u8, u8, u8, u8) = (1, 4, 1, 2);
const HSTR: (u8, u8, u8, u8) = (1, 4, 1, 3);
const NSACR: (u8, u8, u8, u8) = (1, 0, 1, 2);
const NSACR_NONSECURE_DEFAULT: u32 = (1 << 10) | (1 << 11);

fn key(enc: Cp15Encoding) -> (u8, u8, u8, u8) {
    (enc.crn, enc.op1, enc.crm, enc.op2)
}

impl<'a, M: ArmMemory> Executor<'a, M> {
    fn fp_cp15_trap(&self, insn: &DecodedInsn, target_el: u8, target_aarch64: bool) -> ExecResult {
        let raw = insn.raw;
        let cond = if insn.state.is_thumb() && self.cpu.cpsr.in_it_block() {
            u32::from(self.cpu.cpsr.it_condition())
        } else {
            insn.cond.map_or(14, |value| value as u32)
        };
        let read = raw & (1 << 20) != 0;
        let register = |shift: u32| {
            let r = ((raw >> shift) & 15) as u8;
            u32::from(if target_aarch64 {
                system_trap_rt(r, self.cpu.cpsr.mode, read)
            } else {
                r
            })
        };
        let (class, fields) = if matches!(insn.mnemonic, Mnemonic::MRRC | Mnemonic::MCRR) {
            (4, (((raw >> 4) & 15) << 16) | (register(16) << 10))
        } else {
            (
                3,
                (((raw >> 5) & 7) << 17) | (((raw >> 21) & 7) << 14) | (((raw >> 16) & 15) << 10),
            )
        };
        let iss = (1 << 24)
            | (cond << 20)
            | fields
            | (register(12) << 5)
            | ((raw & 15) << 1)
            | u32::from(read);
        ExecResult::FpAccessTrap {
            target_el,
            syndrome: (class << 26) | (1 << 25) | iss,
            undefined: false,
        }
    }

    pub(super) fn fp_cp15_pair_fault(&self, insn: &DecodedInsn) -> Option<ExecResult> {
        let context = self.cpu.fp_control_context();
        context
            .traps_cp15((insn.raw & 15) as u8)
            .then(|| self.fp_cp15_trap(insn, 2, context.el2_aarch64))
    }

    pub(super) fn fp_cp15_fault(
        &self,
        insn: &DecodedInsn,
        enc: Cp15Encoding,
        read: bool,
    ) -> Option<ExecResult> {
        let k = key(enc);
        let context = self.cpu.fp_control_context();
        let standalone_hstr = k == HSTR && self.cpu.standalone_hstr.is_some();
        if !self.cpu.is_privileged() && !self.pl0_cp15(insn, read, enc) {
            return Some(if standalone_hstr {
                ExecResult::Exception(ExceptionType::UndefinedInstruction)
            } else {
                ExecResult::Undefined
            });
        }
        if context.traps_cp15(enc.crn) {
            // The scalar transfer already passed its predicate and EL0
            // privilege checks. The selector precedes register-specific traps.
            return Some(self.fp_cp15_trap(insn, 2, context.el2_aarch64));
        }
        if standalone_hstr {
            let monitor = context.current_el == 3 && context.have_el3 && self.cpu.cp15.scr & 1 != 0;
            return if (context.current_el == 2 && context.have_el2) || monitor {
                None
            } else {
                Some(ExecResult::Exception(ExceptionType::UndefinedInstruction))
            };
        }
        if k == HSTR && context.el3_aarch64 && context.current_el != 2 {
            return Some(ExecResult::Undefined);
        }
        if k == NSACR && context.el3_aarch64 {
            // The mixed-width PE has no AArch32 EL3 register bank. Its
            // Non-secure reads expose the architected default at EL1/EL2.
            return match context.current_el {
                1 if context.secure && context.el2_enabled && context.el2_aarch64 => {
                    Some(self.fp_cp15_trap(insn, 2, true))
                }
                1 if context.secure => Some(self.fp_cp15_trap(insn, 3, true)),
                1 | 2 if read && !context.secure => None,
                _ => Some(ExecResult::Undefined),
            };
        }
        let hyp = matches!(
            k,
            (1, 4, 1, 0) | (1, 4, 1, 2) | (1, 4, 0, 0) | (12, 4, 0, 0) | (5, 4, 2, 0)
        );
        if hyp {
            let monitor =
                self.cpu.cpsr.mode == ProcessorMode::Monitor as u8 && self.cpu.cp15.scr & 1 != 0;
            if !context.have_el2 || !(context.current_el == 2 || monitor) {
                return Some(ExecResult::Undefined);
            }
        }
        if matches!(k, (1, 0, 1, 0) | (1, 0, 1, 1) | NSACR) {
            if !context.have_el3 || context.el3_aarch64 || !context.secure && (k != NSACR || !read)
            {
                return Some(ExecResult::Undefined);
            }
        }
        if read && context.traps_cp15_id_group3(enc, self.cpu.fp_access_context.is_some()) {
            return Some(self.fp_cp15_trap(insn, 2, context.el2_aarch64));
        }
        if k == CPACR && context.current_el == 1 && context.el2_enabled {
            let cptr = if context.el2_aarch64 {
                context.cptr_el2
            } else {
                u64::from(context.hcptr)
            };
            if cptr & (1 << 31) != 0 {
                return Some(self.fp_cp15_trap(insn, 2, context.el2_aarch64));
            }
        }
        if context.have_el3
            && context.el3_aarch64
            && context.cptr_el3 & (1 << 31) != 0
            && (k == CPACR && matches!(context.current_el, 1 | 2)
                || k == HCPTR && context.current_el == 2)
        {
            return Some(self.fp_cp15_trap(insn, 3, true));
        }
        None
    }

    fn fp_cp15_access_masks(&self, enc: Cp15Encoding) -> (u32, u32) {
        let register = key(enc);
        let (mut zero, mut one) = (0, 0);
        let arm11 = self.cpu.fp_access_context.is_none() && self.cpu.vfp.is_arm11();
        if arm11 {
            // DDI0301H Tables 3-44 and 3-51 predate the Armv7 SIMD and
            // D32 disable bits. There are no attached external coprocessors.
            zero |= match register {
                CPACR => !0x00f0_0000,
                NSACR => !0x0007_3fff,
                _ => 0,
            };
        } else if self.cpu.fp_access_context.is_none() {
            let bank = self.cpu.vfp.mvfr0 & 15;
            // DDI0406C.d B4.1: D16 lacks D16-D31. The D32 model leaves
            // D32DIS unimplemented, so NSD32DIS is also RAZ/WI.
            match (bank, register) {
                (1, CPACR) => one |= 1 << 30,
                (1, NSACR) => one |= 1 << 14,
                (2, NSACR) => zero |= 1 << 14,
                _ => {}
            }
            // CP10/CP11 exist when the profile has an execution unit.
            // The imported register bank can also exist on its own.
            if register == CPACR && !self.cpu.vfp.has_scalar_fp() && !self.cpu.vfp.has_advsimd() {
                zero |= 0x00f0_0000;
            }
            if !self.cpu.vfp.has_advsimd() {
                one |= match (bank, register) {
                    (1 | 2, CPACR) => 1 << 31,
                    (1 | 2, NSACR) | (0..=2, HCPTR) => 1 << 15,
                    _ => 0,
                };
            }
        }
        let c = self.cpu.fp_control_context();
        if !c.have_el3 || c.el3_aarch64 || c.secure {
            return (zero, one);
        }
        match register {
            CPACR => {
                if c.nsacr & (1 << 10) == 0 {
                    zero |= 3 << 20;
                }
                if c.nsacr & (1 << 11) == 0 {
                    zero |= 3 << 22;
                }
                if !arm11 && c.nsacr & (1 << 15) != 0 {
                    one |= 1 << 31;
                }
            }
            HCPTR => {
                if c.nsacr & (1 << 10) == 0 {
                    one |= 1 << 10;
                }
                if c.nsacr & (1 << 11) == 0 {
                    one |= 1 << 11;
                }
                if c.nsacr & (1 << 15) != 0 {
                    one |= 1 << 15;
                }
            }
            _ => {}
        }
        (zero, one)
    }

    pub(super) fn fp_cp15_read(&self, enc: Cp15Encoding) -> Option<u32> {
        if key(enc) == HSTR
            && (self.cpu.fp_access_context.is_some() || self.cpu.standalone_hstr.is_some())
        {
            return Some(self.cpu.fp_control_context().hstr);
        }
        let mut value = self.cpu.cp15.read(enc)?;
        let vfp = &self.cpu.vfp;
        value = match key(enc) {
            NSACR if self.cpu.fp_control_context().el3_aarch64 => NSACR_NONSECURE_DEFAULT,
            (0, 0, 2, 5) => effective_id_isar5(value, vfp.mvfr0, vfp.mvfr1),
            (0, 0, 2, 7) => effective_id_isar6(value, vfp.mvfr0, vfp.mvfr1),
            _ => value,
        };
        let (zero, one) = self.fp_cp15_access_masks(enc);
        Some((value & !zero) | one)
    }

    pub(super) fn fp_cp15_write(&mut self, enc: Cp15Encoding, value: u32) -> bool {
        if key(enc) == HSTR {
            if let Some(context) = &mut self.cpu.fp_access_context {
                context.hstr = value;
                return true;
            }
            let mask = self.cpu.standalone_hstr_mask();
            if let Some(hstr) = &mut self.cpu.standalone_hstr {
                *hstr = value & mask;
                return true;
            }
        }
        let (zero, one) = self.fp_cp15_access_masks(enc);
        // RAZ/WI and RAO/WI views leave the underlying shared register intact.
        let ignored = zero | one;
        let previous = self.cpu.cp15.read(enc).unwrap_or(0);
        self.cpu
            .cp15
            .write(enc, (value & !ignored) | (previous & ignored))
    }
}
