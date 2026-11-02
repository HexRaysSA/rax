//! Timer output publication across architectural reset and controller failure.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;
use crate::vm::timing::{ClockMode, TimingContext};
use std::sync::{Arc, Mutex};

const VIRTUAL: u32 = 1 << 27;
const PHYSICAL: u32 = 1 << 30;

fn machine(shared: bool, bound: bool) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    cpu.write_memory(0, &0xd503_201fu32.to_le_bytes()).unwrap();
    if shared {
        let gic = Arc::new(Mutex::new(Gic::new(GicConfig {
            num_cpus: 2,
            ..Default::default()
        })));
        let line = gic.lock().unwrap().irq_line(0).unwrap();
        cpu.bind_platform_gic(gic, 0, line);
    }
    if bound {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        clock.set_resume_base(1600);
        cpu.bind_system_counter(clock);
    }
    let gic = cpu.gic_handle().unwrap();
    let mut controller = gic.lock().unwrap();
    controller.write_redist(0, 0x14, 0);
    controller.write_dist(0, 2);
    controller.write_redist(0, 0x10100, VIRTUAL | PHYSICAL);
    controller.set_group_enable(0, true, true);
    if shared {
        controller.write_redist(1, 0x14, 0);
        controller.write_redist(1, 0x10100, PHYSICAL);
        controller.set_group_enable(1, true, true);
        controller.set_ppi_level(1, 30, true);
    }
    cpu
}

fn arm(cpu: &mut AArch64Cpu, virtual_timer: bool, physical_timer: bool) {
    cpu.sysregs.cntv_ctl_el0 = u64::from(virtual_timer);
    cpu.sysregs.cntp_ctl_el0 = u64::from(physical_timer);
    cpu.sysregs.cntv_cval_el0 = 0;
    cpu.sysregs.cntp_cval_el0 = 0;
    cpu.tick_system(0).unwrap();
}

fn pending(cpu: &AArch64Cpu, id: usize) -> u32 {
    cpu.gic_handle()
        .unwrap()
        .lock()
        .unwrap()
        .read_redist(id, 0x10200)
}

#[test]
fn shared_reset_keeps_the_owed_timer_deassertion_until_a_zero_retirement_poll() {
    for bound in [false, true] {
        let mut cpu = machine(true, bound);
        arm(&mut cpu, true, true);
        assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), VIRTUAL | PHYSICAL);
        let gic = cpu.gic_handle().unwrap();
        let own_line = gic.lock().unwrap().irq_line(0).unwrap();
        let peer_line = gic.lock().unwrap().irq_line(1).unwrap();
        assert!(own_line.load(std::sync::atomic::Ordering::Acquire));
        cpu.reset();
        assert!(Arc::ptr_eq(&gic, &cpu.gic_handle().unwrap()));
        let controller = gic.lock().unwrap().checkpoint();
        let raw = crate::codec::serialize(&CoreCheckpoint::capture(&cpu).unwrap()).unwrap();
        let image: CoreCheckpoint =
            crate::codec::deserialize_limited::<_, { 16 * 1024 * 1024 }>(&raw).unwrap();
        let mut restored = machine(true, bound);
        image.install_in_prepared(&mut restored).unwrap();
        restored
            .gic_handle()
            .unwrap()
            .lock()
            .unwrap()
            .restore_checkpoint(controller);
        cpu.tick_system(0).unwrap();
        restored.tick_system(0).unwrap();
        assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), 0);
        assert_eq!(pending(&restored, 0) & (VIRTUAL | PHYSICAL), 0);
        assert!(!own_line.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(pending(&cpu, 1) & PHYSICAL, PHYSICAL);
        assert_eq!(pending(&restored, 1) & PHYSICAL, PHYSICAL);
        assert!(peer_line.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(cpu.instruction_count(), 0);
    }
}

#[test]
fn successful_owned_controller_reset_and_absent_controller_have_no_owed_output() {
    let mut cpu = machine(false, true);
    arm(&mut cpu, true, true);
    let gic = cpu.gic_handle().unwrap();
    cpu.reset();
    assert!(Arc::ptr_eq(&gic, &cpu.gic_handle().unwrap()));
    assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), 0);
    assert_eq!(cpu.timer_levels, (false, false));
    cpu.tick_system(0).unwrap();
    assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), 0);

    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            gic_config: None,
            ..Default::default()
        },
        Box::new(FlatMemory::new(0, 4096)),
    );
    arm(&mut cpu, true, true);
    cpu.reset();
    assert!(cpu.gic_handle().is_none());
    assert_eq!(cpu.timer_levels, (false, false));
    cpu.tick_system(0).unwrap();
    assert_eq!(cpu.instruction_count(), 0);
}

#[test]
fn changing_one_timer_output_preserves_software_pending_on_the_unchanged_ppi() {
    for bound in [false, true] {
        for virtual_timer in [false, true] {
            let mut cpu = machine(true, bound);
            arm(&mut cpu, virtual_timer, !virtual_timer);
            let (changed, unchanged) = if virtual_timer {
                (VIRTUAL, PHYSICAL)
            } else {
                (PHYSICAL, VIRTUAL)
            };
            cpu.gic_handle()
                .unwrap()
                .lock()
                .unwrap()
                .write_redist(0, 0x10200, unchanged);
            assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), changed | unchanged);
            cpu.sysregs.cntv_ctl_el0 = 0;
            cpu.sysregs.cntp_ctl_el0 = 0;
            cpu.tick_system(0).unwrap();
            assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), unchanged);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn retained_poisoned_controller_cannot_silently_discard_reset_timer_outputs() {
    for shared in [false, true] {
        for bound in [false, true] {
            let mut cpu = machine(shared, bound);
            arm(&mut cpu, true, true);
            let gic = cpu.gic_handle().unwrap();
            assert!(
                std::panic::catch_unwind(|| {
                    let _guard = gic.lock().unwrap();
                    panic!("test-only timer controller poison");
                })
                .is_err()
            );
            cpu.reset();
            assert!(cpu.step_system().is_err());
            assert_eq!(cpu.instruction_count(), 0);
            gic.clear_poison();
            cpu.tick_system(0).unwrap();
            assert_eq!(pending(&cpu, 0) & (VIRTUAL | PHYSICAL), 0);
            if shared {
                assert_eq!(pending(&cpu, 1) & PHYSICAL, PHYSICAL);
            }
        }
    }
}

#[test]
fn direct_cpu_does_not_bypass_a_disabled_gic_for_the_physical_timer() {
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    let words = [0xd51be25fu32, 0xd51be220, 0xd503201f];
    cpu.write_memory(
        0,
        &words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    cpu.set_gpr(0, 1);
    let mut state = cpu.get_pstate();
    state.i = false;
    cpu.set_pstate(state);
    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
    assert!(
        matches!(cpu.step().unwrap(), CpuExit::Continue),
        "A disabled default controller must gate its timer input"
    );
    assert_eq!(cpu.get_pc(), 12);
}

#[test]
fn direct_timer_poll_respects_each_controller_gate_and_preserves_controllerless_fallback() {
    for shared in [false, true] {
        for bound in [false, true] {
            let mut cpu = machine(shared, bound);
            arm(&mut cpu, false, true);
            cpu.daif = 0;
            let handle = cpu.gic_handle().unwrap();
            assert!(cpu.check_pending_interrupts().unwrap().is_some());
            handle.lock().unwrap().write_dist(0, 0);
            assert!(cpu.check_pending_interrupts().unwrap().is_none());
            handle.lock().unwrap().write_dist(0, 2);
            assert!(cpu.check_pending_interrupts().unwrap().is_some());
            handle.lock().unwrap().set_group_enable(0, true, false);
            assert!(cpu.check_pending_interrupts().unwrap().is_none());
            handle.lock().unwrap().set_group_enable(0, true, true);
            handle.lock().unwrap().write_redist(0, 0x10180, PHYSICAL);
            assert!(cpu.check_pending_interrupts().unwrap().is_none());
            handle.lock().unwrap().write_redist(0, 0x10100, PHYSICAL);
            assert!(cpu.check_pending_interrupts().unwrap().is_some());
            cpu.gic = None;
            cpu.gic_irq_line = None;
            assert!(cpu.check_pending_interrupts().unwrap().is_some());
        }
    }
}

#[test]
fn direct_cpu_delivers_a_timer_through_an_enabled_gic_without_external_tick() {
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    let words = [0xd51be25fu32, 0xd51be220, 0xd503201f];
    cpu.write_memory(
        0,
        &words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    cpu.set_gpr(0, 1);
    let mut state = cpu.get_pstate();
    state.i = false;
    cpu.set_pstate(state);
    let handle = cpu.gic_handle().unwrap();
    {
        let mut gic = handle.lock().unwrap();
        gic.write_redist(0, 0x14, 0);
        gic.write_dist(0, 2);
        gic.set_group_enable(0, true, true);
        gic.write_redist(0, 0x10100, 1 << 30);
    }
    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
    assert!(
        matches!(cpu.step().unwrap(), CpuExit::InterruptPending),
        "An enabled controller must receive the current timer output"
    );
    assert_eq!(cpu.get_pc(), 8);
}
