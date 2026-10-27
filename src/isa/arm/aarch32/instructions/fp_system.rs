//! CP15 access policy for the represented FP/security/virtualization controls.
use super::*;
use crate::isa::arm::common::sysreg::Cp15Encoding;

const CPACR: (u8, u8, u8, u8) = (1, 0, 0, 2);
const HCPTR: (u8, u8, u8, u8) = (1, 4, 1, 2);

fn key(enc: Cp15Encoding) -> (u8, u8, u8, u8) {
    (enc.crn, enc.op1, enc.crm, enc.op2)
}

impl<'a, M: ArmMemory> Executor<'a, M> {
    fn fp_cp15_trap(&self, insn: &DecodedInsn, target_el: u8) -> ExecResult {
        let raw = insn.raw;
        let cond = if insn.state.is_thumb() && self.cpu.cpsr.in_it_block() {
            u32::from(self.cpu.cpsr.it_condition())
        } else {
            insn.cond.map_or(14, |value| value as u32)
        };
        // Arm AArch32_SystemAccessTrapSyndrome, EC=0b000011.
        let iss = (1 << 24)
            | (cond << 20)
            | (((raw >> 5) & 7) << 17)
            | (((raw >> 21) & 7) << 14)
            | (((raw >> 16) & 15) << 10)
            | (((raw >> 12) & 15) << 5)
            | ((raw & 15) << 1)
            | ((raw >> 20) & 1);
        ExecResult::FpAccessTrap {
            target_el,
            syndrome: (3 << 26) | (1 << 25) | iss,
            undefined: false,
        }
    }

    pub(super) fn fp_cp15_fault(
        &self,
        insn: &DecodedInsn,
        enc: Cp15Encoding,
        read: bool,
    ) -> Option<ExecResult> {
        let k = key(enc);
        let context = self.cpu.fp_control_context();
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
        if matches!(k, (1, 0, 1, 0) | (1, 0, 1, 1) | (1, 0, 1, 2)) {
            if !context.have_el3
                || context.el3_aarch64
                || !context.secure && (k != (1, 0, 1, 2) || !read)
            {
                return Some(ExecResult::Undefined);
            }
        }
        if k == CPACR && context.current_el == 1 && context.el2_enabled {
            let cptr = if context.el2_aarch64 {
                context.cptr_el2
            } else {
                u64::from(context.hcptr)
            };
            if cptr & (1 << 31) != 0 {
                return Some(self.fp_cp15_trap(insn, 2));
            }
        }
        if context.have_el3
            && context.el3_aarch64
            && context.cptr_el3 & (1 << 31) != 0
            && (k == CPACR && matches!(context.current_el, 1 | 2)
                || k == HCPTR && context.current_el == 2)
        {
            return Some(self.fp_cp15_trap(insn, 3));
        }
        None
    }

    fn fp_ns_cp15_clamp(&self, enc: Cp15Encoding) -> (u32, u32) {
        let c = self.cpu.fp_control_context();
        if !c.have_el3 || c.el3_aarch64 || c.secure {
            return (0, 0);
        }
        let mut zero = 0;
        let mut one = 0;
        match key(enc) {
            CPACR => {
                if c.nsacr & (1 << 10) == 0 {
                    zero |= 3 << 20;
                }
                if c.nsacr & (1 << 11) == 0 {
                    zero |= 3 << 22;
                }
                if c.nsacr & (1 << 15) != 0 {
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
        let value = self.cpu.cp15.read(enc)?;
        let (zero, one) = self.fp_ns_cp15_clamp(enc);
        Some((value & !zero) | one)
    }

    pub(super) fn fp_cp15_write(&mut self, enc: Cp15Encoding, value: u32) -> bool {
        let (zero, one) = self.fp_ns_cp15_clamp(enc);
        // RAZ/WI and RAO/WI views leave the underlying shared register intact.
        let ignored = zero | one;
        let previous = self.cpu.cp15.read(enc).unwrap_or(0);
        self.cpu
            .cp15
            .write(enc, (value & !ignored) | (previous & ignored))
    }
}
