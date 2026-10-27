//! FP controls owned by the enclosing PE, rather than standalone reset state.
use super::super::AArch64Cpu;
use crate::isa::arm::aarch32::fp_controls::FpAccessContext;
use crate::isa::arm::aarch64::exception_return::uses_aarch32;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;

impl AArch64Cpu {
    pub(super) fn aarch32_fp_context(&self) -> FpAccessContext {
        let controls = self.pauth_controls();
        let have_el2 = controls.implemented_els & 4 != 0;
        let have_el3 = controls.implemented_els & 8 != 0;
        let register = |op1| {
            self.sysregs
                .impl_defined
                .get(&Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode())
                .copied()
                .unwrap_or(0)
        };
        let cptr_el2 = register(4);
        FpAccessContext {
            current_el: self.current_el,
            secure: have_el3 && (self.current_el == 3 || controls.scr_el3 & 1 == 0),
            have_el2,
            have_el3,
            el1_aarch64: uses_aarch32(controls, self.sysregs.id_aa64pfr0_el1, 1) != Some(true),
            el2_aarch64: uses_aarch32(controls, self.sysregs.id_aa64pfr0_el1, 2) != Some(true),
            // This PE resets EL3 in A64 and does not admit Monitor state.
            el3_aarch64: true,
            el2_enabled: controls.el2_enabled(),
            vhe: controls.vhe,
            cpacr: self.sysregs.el1.cpacr as u32,
            fpexc: self
                .sysregs
                .impl_defined
                .get(&Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode())
                .copied()
                .unwrap_or(0) as u32,
            nsacr: 0,
            hcptr: cptr_el2 as u32,
            hcr: controls.hcr_el2,
            cptr_el2,
            cptr_el3: register(6),
        }
    }
    pub(super) fn commit_aarch32_fp_controls(
        &mut self,
        cpu: &crate::isa::arm::aarch32::cpu::Armv7Cpu,
    ) {
        let before =
            (self.sysregs.el1.cpacr as u32) | (((self.sysregs.el1.cpacr >> 20) as u32 & 3) << 22);
        if cpu.cp15.cpacr.bits() != before {
            self.sysregs.el1.cpacr = (self.sysregs.el1.cpacr & !0x80f0_0000)
                | u64::from(cpu.cp15.cpacr.bits() & 0x80f0_0000);
        }
        let enc = Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode();
        let cptr = self.sysregs.impl_defined.get(&enc).copied().unwrap_or(0);
        if cpu.cp15.hcptr != ((cptr as u32) & 0x8000_8c00) | 0x33ff {
            self.sysregs.impl_defined.insert(
                enc,
                (cptr & !0x8000_8c00) | u64::from(cpu.cp15.hcptr & 0x8000_8c00),
            );
        }
        if cpu.cp15.hcr != self.sysregs.hcr_el2 as u32 {
            self.sysregs.hcr_el2 = (self.sysregs.hcr_el2 & !0xffff_ffff) | u64::from(cpu.cp15.hcr);
        }
    }
}
