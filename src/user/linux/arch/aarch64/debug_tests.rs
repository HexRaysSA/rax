use super::*;
use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};

#[test]
fn arm64_instruction_debug_reports_hardware_sigtrap_without_retirement() {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * PAGE_SIZE,
        reserved_phys: vec![],
    })
    .unwrap();
    space
        .map(
            0x10000,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::EXEC),
        )
        .unwrap();
    space
        .write_raw(0x10000, &0x91000400u32.to_le_bytes())
        .unwrap();
    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(0x10000);
    cpu.core_mut().set_x(0, 41);
    let mut debug = cpu.core().user_debug_registers();
    debug.breakpoint_control[0] = 0x1e5;
    debug.breakpoint_value[0] = 0x10000;
    cpu.core_mut().set_user_debug_registers(debug);
    assert_eq!(
        run(&mut cpu, 1),
        CpuEvent::Signal(
            SigInfo::fault(SIGTRAP, code::TRAP_HWBKPT, 0x10000),
            FaultUpdate::None,
        )
    );
    assert_eq!((cpu.core().get_pc(), cpu.core().get_x(0)), (0x10000, 41));
    let mut child = cpu.clone_thread();
    assert_eq!(run(&mut child, 1), CpuEvent::Yield);
    assert_eq!(child.core().get_x(0), 42);
    let mut debug = cpu.core().user_debug_registers();
    debug.breakpoint_control[0] = 0;
    cpu.core_mut().set_user_debug_registers(debug);
    assert_eq!(run(&mut cpu, 1), CpuEvent::Yield);
    assert_eq!(cpu.core().get_x(0), 42);
}
