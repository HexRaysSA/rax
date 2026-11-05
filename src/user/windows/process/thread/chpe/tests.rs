use super::*;
use crate::user::mm::SpaceConfig;
use crate::user::windows::arch::{CpuStop, InstructionRoute};
use crate::user::windows::context::RegContext;

fn memory() -> VirtualMemory {
    VirtualMemory::new(
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 4 << 20,
            reserved_phys: crate::user::cpu::x86_64::RESERVED_PHYS.to_vec(),
        })
        .unwrap(),
        65536,
        1 << 47,
    )
}

#[test]
fn thread_area_owns_real_guest_context_stack_guard_and_doorbell() {
    let mut vm = memory();
    let area = Area::allocate(&mut vm).unwrap();
    assert_eq!(
        vm.space().u64(area.base + 8).unwrap(),
        area.base + 7 * PAGE_SIZE
    );
    assert_eq!(
        vm.space().u64(area.base + 16).unwrap(),
        area.base + 2 * PAGE_SIZE
    );
    assert_eq!(vm.space().u64(area.base + 24).unwrap(), area.context);
    let doorbell = vm.space().u64(area.base + 32).unwrap();
    assert_eq!(vm.space().u32(doorbell).unwrap(), 0);
    assert_eq!(vm.query(area.base).unwrap().kind, mem::PRIVATE);
    assert_eq!(
        vm.query(area.base + PAGE_SIZE).unwrap().protect,
        prot::READWRITE | prot::GUARD
    );
    assert_eq!(
        vm.query(area.base + 7 * PAGE_SIZE).unwrap().state,
        mem::RESERVE
    );
    assert!(area.owns_space(vm.space()));
}

#[test]
fn partial_thread_area_allocation_returns_every_committed_page_and_reservation() {
    let original = memory();
    let mut vm = VirtualMemory::new_with_commit_limit(
        original.space().clone(),
        65536,
        1 << 47,
        2 * PAGE_SIZE,
    );
    assert!(matches!(
        Area::allocate(&mut vm),
        Err(STATUS_COMMITMENT_LIMIT)
    ));
    assert_eq!(vm.committed_bytes(), 0);
    assert!(vm.is_free(65536, 65536));
}

#[test]
fn guest_context_write_changes_the_next_arm64_instruction_and_preserves_live_work() {
    let mut vm = memory();
    let area = Area::allocate(&mut vm).unwrap();
    let code = 0x4000_0000;
    vm.allocate(
        Some(code),
        2 * PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    // STR X0,[X1] writes the shared CONTEXT.Rax; the following MOV X2,X8
    // must see the corresponding live ARM64 register before the slice ends.
    vm.space().w32(code, 0xf900_0020).unwrap();
    vm.space().w32(code + 4, 0xaa08_03e2).unwrap();
    vm.space().w8(code + PAGE_SIZE, 0x90).unwrap();
    vm.protect(code, 2 * PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, vm.space());
    cpu.set_pc(code);
    cpu.set_sp(area.base + 7 * PAGE_SIZE - 64);
    cpu.set_gpr(1, 0x1234);
    cpu.set_gpr(2, area.context + x64::RAX as u64);
    cpu.bind_chpe_area(area.clone()).unwrap();
    assert_eq!(vm.space().u8(area.base).unwrap(), 1);
    let result = cpu.run_routed(2, |_, active, _| {
        Ok(if active == WinArch::X64 {
            InstructionRoute::ResumeArm64
        } else {
            InstructionRoute::Stay
        })
    });
    assert!(matches!(result, CpuStop::Yield), "{result:?}");
    assert_eq!(cpu.call_gpr(2), 0x1234);
    assert_eq!(cpu.gpr(0), 0x1234);
    assert_eq!(cpu.pc(), code + 8);
    assert_eq!(vm.space().u8(area.base).unwrap(), 0);
    assert_eq!(
        RegContext::read(vm.space(), WinArch::X64, area.context).unwrap(),
        RegContext::capture(&cpu)
    );
    cpu.ec_exit(code + PAGE_SIZE, cpu.sp()).unwrap();
    assert!(matches!(
        cpu.run_routed(1, |_, _, _| Ok(InstructionRoute::Stay)),
        CpuStop::Yield
    ));
    assert_eq!(vm.space().u8(area.base).unwrap(), 1);
}

#[test]
fn replaced_area_and_invalid_context_cannot_overwrite_a_new_owner_or_cpu_state() {
    let mut vm = memory();
    let area = Area::allocate(&mut vm).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, vm.space());
    cpu.set_gpr(0, 0x5a);
    cpu.bind_chpe_area(area.clone()).unwrap();
    let before = RegContext::capture(&cpu);
    vm.space()
        .w32(area.context + x64::FLAGS as u64, 0xdead_0000)
        .unwrap();
    assert!(cpu.sync_chpe_area(false).is_err());
    assert_eq!(RegContext::capture(&cpu), before);
    vm.release(area.base).unwrap();
    vm.reserve(
        Some(area.base),
        65536,
        prot::READWRITE,
        AllocKind::Private,
        false,
        Some(Arc::from("[CHPE thread context]")),
    )
    .unwrap();
    vm.commit(area.base, PAGE_SIZE, prot::READWRITE).unwrap();
    vm.space().w8(area.base, 0x7b).unwrap();
    assert!(!area.owns_space(vm.space()));
    assert!(cpu.sync_chpe_area(true).is_err());
    assert_eq!(vm.space().u8(area.base).unwrap(), 0x7b);
}
