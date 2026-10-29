//! Event consumption at direct and system instruction boundaries.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

#[test]
fn waiting_wfe_consumes_one_signal_and_executes_the_next_instruction() {
    for system in [false, true] {
        let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
        cpu.write_memory(0, &0xd503_205fu32.to_le_bytes()).unwrap();
        cpu.write_memory(4, &0xd503_201fu32.to_le_bytes()).unwrap();
        let step = |cpu: &mut AArch64Cpu| {
            if system {
                cpu.step_system()
            } else {
                cpu.step()
            }
        };
        assert!(matches!(step(&mut cpu).unwrap(), CpuExit::Wfe));
        assert_eq!((cpu.pc, cpu.insn_count), (4, 1));
        cpu.set_event();
        assert!(matches!(step(&mut cpu).unwrap(), CpuExit::Continue));
        assert_eq!((cpu.pc, cpu.insn_count), (8, 2));
        assert!(!cpu.event_pending());
        assert!(!cpu.wfe);
    }
}

#[test]
fn reset_clears_its_latch_without_replacing_the_platform_binding() {
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    let handle = cpu.event_register_handle();
    cpu.set_event();
    cpu.reset();
    assert!(std::sync::Arc::ptr_eq(
        &handle,
        &cpu.event_register_handle()
    ));
    assert!(!cpu.event_pending());
    handle.store(true, std::sync::atomic::Ordering::Release);
    assert!(cpu.event_pending());
}
