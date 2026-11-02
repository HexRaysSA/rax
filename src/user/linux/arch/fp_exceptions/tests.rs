use super::*;
use crate::isa::arm::aarch32::vfp::Fpscr;
use crate::user::cpu::arm::A32UserCpu;
use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};

#[test]
fn arm_thumb_user_adapter_preserves_fault_pc_it_and_linux_fault_record() {
    for thumb in [false, true] {
        for (lhs, rhs, enables, expected) in [
            (0, 0, 0x100, code::FPE_FLTINV),
            (0x3f800000, 0, 0x200, code::FPE_FLTDIV),
        ] {
            let space = AddressSpace::new(SpaceConfig {
                va_limit: 1 << 32,
                arena_bytes: 8 * PAGE_SIZE,
                reserved_phys: Vec::new(),
            })
            .unwrap();
            space
                .map(
                    0x10000,
                    PAGE_SIZE,
                    Mapping::anonymous(Perms::READ | Perms::EXEC),
                )
                .unwrap();
            let raw = 0xee810a02u32;
            space
                .write_raw(
                    0x10000,
                    &if thumb { raw.rotate_left(16) } else { raw }.to_le_bytes(),
                )
                .unwrap();
            let mut cpu = A32UserCpu::new(&space);
            cpu.set_pc(0x10000);
            cpu.core_mut().cpsr.t = thumb;
            if thumb {
                cpu.core_mut().cpsr.z = true;
                cpu.core_mut().cpsr.set_it_state(0, 8);
            }
            cpu.core_mut().vfp.mvfr0 |= 1 << 12;
            cpu.core_mut().vfp.fpscr = Fpscr::from_bits(enables);
            cpu.core_mut().vfp.write_s_bits(2, lhs);
            cpu.core_mut().vfp.write_s_bits(4, rhs);
            cpu.core_mut().vfp.write_s_bits(0, 0xdeadbeef);
            let before = (cpu.core().regs, cpu.core().cpsr.to_u32());
            let event = super::super::arm::run(&mut cpu, 1);
            assert_eq!(
                event,
                CpuEvent::Signal(SigInfo::fault(SIGFPE, expected, 0x10000), FaultUpdate::None)
            );
            assert_eq!((cpu.core().regs, cpu.core().cpsr.to_u32()), before);
            assert_eq!(cpu.core().vfp.read_s_bits(0), 0xdeadbeef);
        }
    }
}
