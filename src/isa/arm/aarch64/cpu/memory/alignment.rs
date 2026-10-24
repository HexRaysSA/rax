//! Stack-pointer checks precede effective-address formation and data alignment.

use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::sctlr;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};

impl AArch64Cpu {
    pub(crate) fn sp_alignment_enabled(&self) -> bool {
        let control = if self.current_el == 0 {
            sctlr::SA0
        } else {
            sctlr::SA
        };
        let controls = self.pauth_controls();
        controls.sctlr[controls.regime_el()] & control != 0
    }

    pub(crate) fn checked_sp(&self, access: AccessType) -> Result<u64, ArmError> {
        let sp = self.current_sp();
        if self.sp_alignment_enabled() && sp & 15 != 0 {
            return Err(ArmError::MemoryError(MemoryFaultInfo {
                address: sp,
                access,
                fault_type: MemoryFaultType::SpAlignment,
                stage2: false,
            }));
        }
        Ok(sp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::arm::aarch64::AArch64Config;
    use crate::isa::arm::common::memory::FlatMemory;

    #[test]
    fn stack_controls_use_the_register_bank_at_every_exception_level() {
        for el in 0..=3 {
            for controls in [0, sctlr::SA, sctlr::SA0, sctlr::SA | sctlr::SA0] {
                let mut cpu = AArch64Cpu::new(
                    AArch64Config {
                        initial_el: el,
                        ..AArch64Config::default()
                    },
                    Box::new(FlatMemory::new(0, 0x10000)),
                );
                cpu.sysregs.bank_mut(el).sctlr = controls;
                cpu.set_current_sp(0x1008);
                let enabled = controls & if el == 0 { sctlr::SA0 } else { sctlr::SA } != 0;
                for access in [AccessType::Read, AccessType::Write, AccessType::Atomic] {
                    let result = cpu.checked_sp(access);
                    assert_eq!(result.is_err(), enabled, "EL{el} controls={controls:#x}");
                    if let Err(ArmError::MemoryError(info)) = result {
                        assert_eq!(info.fault_type, MemoryFaultType::SpAlignment);
                        assert_eq!(info.access, access);
                        assert_eq!(info.address, 0x1008);
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
mod native_tests {
    use super::*;
    use crate::isa::arm::aarch64::AArch64Config;
    use crate::isa::arm::common::cpu::ArmCpu;
    use crate::isa::arm::common::memory::FlatMemory;

    fn loop_cpu(el: u8, memory: bool) -> AArch64Cpu {
        let mut cpu = AArch64Cpu::new(
            AArch64Config {
                initial_el: el,
                ..AArch64Config::default()
            },
            Box::new(FlatMemory::new(0, 0x10000)),
        );
        let program = [
            if memory { 0xf94003e0u32 } else { 0x91000400 }, // LDR X0,[SP] / ADD X0,X0,#1
            0xf1000442,                                      // SUBS X2,X2,#1
            0x54ffffc1,                                      // B.NE 0
            0xd4200000,                                      // BRK #0: native frontier
        ];
        let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
        cpu.write_memory(0, &bytes).unwrap();
        cpu.set_current_sp(0x1008);
        cpu.set_x(2, 1);
        cpu.set_pc(0);
        cpu.set_jit_mem(true);
        cpu
    }

    #[test]
    fn cached_memory_regions_observe_sa_and_sa0_transitions() {
        for el in [0, 1] {
            let mut cpu = loop_cpu(el, true);
            let region = cpu
                .jit_compile_region()
                .expect("unchecked scalar memory loop");
            assert!(region.uses_memory);
            let disabled_tag = cpu.jit_mode_tag();
            cpu.sysregs.el1.sctlr = if el == 0 { sctlr::SA0 } else { sctlr::SA };
            assert_ne!(cpu.jit_mode_tag(), disabled_tag);
            assert!(!cpu.jit_run_region(&region));
            assert_eq!(cpu.get_pc(), 0);
            assert_eq!(cpu.get_x(2), 1);
            assert!(cpu.jit_compile_region().is_none());
            assert!(matches!(cpu.step(), Err(ArmError::MemoryError(info))
                if info.fault_type == MemoryFaultType::SpAlignment));

            // The other EL's control has no effect on the current policy.
            cpu.sysregs.el1.sctlr = if el == 0 { sctlr::SA } else { sctlr::SA0 };
            assert_eq!(cpu.jit_mode_tag(), disabled_tag);
            assert!(cpu.jit_run_region(&region));
            assert_eq!(cpu.get_pc(), 12);
            assert_eq!(cpu.get_x(2), 0);
        }
    }

    #[test]
    fn register_only_native_regions_remain_available_with_stack_checks() {
        for el in [0, 1] {
            let mut cpu = loop_cpu(el, false);
            cpu.sysregs.el1.sctlr = sctlr::SA | sctlr::SA0;
            let region = cpu.jit_compile_region().expect("register-only loop");
            assert!(!region.uses_memory);
            assert!(cpu.jit_run_region(&region));
            assert_eq!(cpu.get_pc(), 12);
            assert_eq!(cpu.get_x(0), 1);
        }
    }
}
