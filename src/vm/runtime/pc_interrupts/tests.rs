//! Actual VMM source/controller ownership and detached checkpoint continuation.
use super::super::execution_tests::{BSP, Fixture};
use super::*;
use crate::config::CliConfig;
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct RemoveFile(PathBuf);
impl RemoveFile {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "rax-ioapic-eoi-{}-{}.rxc",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn triggered_pit_modes_continue_from_a_detached_file() {
    let at_tick = |clock: &crate::vm::timing::TimingContext, tick: u64| {
        clock.set_resume_base((tick * 1_000_000_000).div_ceil(crate::vm::timing::PIT_FREQUENCY_HZ));
    };
    let read = |vm: &mut Vmm, port| {
        let mut byte = [0];
        vm.io_bus.read(port, &mut byte).unwrap();
        byte[0]
    };
    for (command, capture_tick) in [(0x92, 1), (0x92, 3), (0x9a, 1), (0x9a, 3)] {
        let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
        let source = &mut fixture.vm;
        let clock = source.timing_context.clone();
        let scope = clock.enter();
        at_tick(&clock, 1);
        source.io_bus.write(0x43, &[command]).unwrap();
        source.io_bus.write(0x42, &[4]).unwrap();
        source.io_bus.write(0x61, &[1]).unwrap();
        source.io_bus.write(0x61, &[0]).unwrap();
        if capture_tick == 3 {
            at_tick(&clock, 3);
            // The first reload has reached the counter. Its replacement has
            // been written, but no trigger has selected that replacement.
            source.io_bus.write(0x42, &[2]).unwrap();
        }
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(scope);
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        let clock = target.timing_context.clone();
        let _scope = clock.enter();
        let one_shot = command == 0x92;
        // Load at tick 2 despite the falling GATE. Terminal count is tick 6.
        for (tick, out, count) in [
            (2, !one_shot, 4),
            (3, !one_shot, 3),
            (6, one_shot, 0),
            (7, true, 0xff),
            (10, true, 0xfc),
        ] {
            if tick < capture_tick {
                continue;
            }
            at_tick(&clock, tick);
            assert_eq!(read(&mut target, 0x61) & 0x21, u8::from(out) << 5);
            assert_eq!(read(&mut target, 0x42), count);
        }
        target.io_bus.write(0x61, &[1]).unwrap();
        at_tick(&clock, 11);
        assert_eq!(
            read(&mut target, 0x42),
            if capture_tick == 3 { 2 } else { 4 }
        );
    }
}

#[test]
fn speaker_gate_and_counter_phase_survive_a_detached_checkpoint() {
    for legacy in [false, true] {
        let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
        let source = &mut fixture.vm;
        let clock = source.timing_context.clone();
        let scope = clock.enter();
        if legacy {
            // Historical PC records stored the port latch while the PIT was disconnected.
            *source.pc_devices.as_ref().unwrap().sysctl.lock().unwrap() =
                crate::devices::sysctl::SystemControl::new();
        }
        let port_b = |vm: &mut Vmm| {
            let mut data = [0];
            vm.io_bus.read(0x61, &mut data).unwrap();
            data[0]
        };
        source.io_bus.write(0x43, &[0xb0]).unwrap(); // Channel 2, mode 0.
        source.io_bus.write(0x42, &[100]).unwrap();
        source.io_bus.write(0x42, &[0]).unwrap();
        source.io_bus.write(0x61, &[3]).unwrap();
        assert_eq!(port_b(source) & 0x23, 3);
        // Capture at oscillator tick 74, after the load and 73 decrements.
        clock.set_resume_base(62_500);
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(scope);
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        let clock = target.timing_context.clone();
        let _scope = clock.enter();
        // Exactly the next refresh phase and the same gate and speaker latches.
        assert_eq!(port_b(&mut target), 3);
        target.io_bus.write(0x61, &[3]).unwrap(); // Unchanged GATE cannot reload.
        clock.set_resume_base(125_000);
        assert_eq!(port_b(&mut target) & 0x23, if legacy { 3 } else { 0x23 });
        // An old record starts counting from its imported epoch, 62.5 µs.
        clock.set_resume_base(150_000);
        assert_eq!(port_b(&mut target) & 0x23, 0x23);
    }
}

#[test]
fn mode0_resumes_a_partial_reload_from_a_detached_file() {
    let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
    let source = &mut fixture.vm;
    let clock = source.timing_context.clone();
    let scope = clock.enter();
    let at_tick = |clock: &crate::vm::timing::TimingContext, tick: u64| {
        clock.set_resume_base((tick * 1_000_000_000).div_ceil(crate::vm::timing::PIT_FREQUENCY_HZ));
    };
    let read = |vm: &mut Vmm, port| {
        let mut byte = [0];
        vm.io_bus.read(port, &mut byte).unwrap();
        byte[0]
    };
    let count = |vm: &mut Vmm| {
        vm.io_bus.write(0x43, &[0x80]).unwrap();
        u16::from_le_bytes([read(vm, 0x42), read(vm, 0x42)])
    };
    at_tick(&clock, 0);
    source.io_bus.write(0x43, &[0xb0]).unwrap();
    source.io_bus.write(0x42, &[4]).unwrap();
    source.io_bus.write(0x42, &[0]).unwrap();
    at_tick(&clock, 3); // The divisor has transferred with GATE low.
    source.io_bus.write(0x43, &[0xe8]).unwrap();
    assert_eq!(read(source, 0x42), 0x30);
    assert_eq!(count(source), 4);
    source.io_bus.write(0x61, &[1]).unwrap();
    at_tick(&clock, 5);
    source.io_bus.write(0x42, &[2]).unwrap(); // Freeze the old count at two.
    let file = RemoveFile::new();
    source
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&file.0)
        .unwrap();
    drop(scope);
    drop(fixture);

    let bundle = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    let clock = target.timing_context.clone();
    let _scope = clock.enter();
    at_tick(&clock, 25);
    assert_eq!(count(&mut target), 2);
    assert_eq!(read(&mut target, 0x61) & 0x21, 1);
    target.io_bus.write(0x42, &[0]).unwrap();
    for (tick, ce, port_b) in [(26, 2, 1), (27, 1, 1), (28, 0, 0x21), (29, 0xffff, 0x21)] {
        at_tick(&clock, tick);
        assert_eq!(count(&mut target), ce);
        assert_eq!(read(&mut target, 0x61) & 0x21, port_b);
    }
}

#[test]
fn pit_restore_drains_status_and_count_before_resuming_live_reads() {
    let read_counter = |vm: &mut Vmm| {
        let mut byte = [0];
        vm.io_bus.read(0x42, &mut byte).unwrap();
        byte[0]
    };
    for (low_consumed, live_high_pending) in [(false, false), (true, false), (true, true)] {
        let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
        let source = &mut fixture.vm;
        // The power-on count of 11932 stays frozen with GATE low.
        if live_high_pending {
            assert_eq!(read_counter(source), 0x9c);
        }
        if low_consumed {
            source.io_bus.write(0x43, &[0xd8]).unwrap(); // Count only.
            assert_eq!(read_counter(source), 0x9c);
            source.io_bus.write(0x43, &[0xe8]).unwrap(); // Status only.
        } else {
            source.io_bus.write(0x43, &[0xc8]).unwrap(); // Count and status.
        }
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        assert_eq!(read_counter(&mut target), 0xb4);
        if !low_consumed {
            assert_eq!(read_counter(&mut target), 0x9c);
        }
        assert_eq!(read_counter(&mut target), 0x2e);
        if live_high_pending {
            assert_eq!(read_counter(&mut target), 0x2e);
        }
        assert_eq!(read_counter(&mut target), 0x9c);
    }
}

fn program(vm: &mut Vmm, pin: u8, vector: u8, destination: u8, level: bool) {
    vm.mmio_bus
        .write(0xfec0_0000, &u32::from(0x11 + 2 * pin).to_le_bytes())
        .unwrap();
    vm.mmio_bus
        .write(0xfec0_0010, &(u32::from(destination) << 24).to_le_bytes())
        .unwrap();
    vm.mmio_bus
        .write(0xfec0_0000, &u32::from(0x10 + 2 * pin).to_le_bytes())
        .unwrap();
    let low = u32::from(vector) | (u32::from(level) << 15);
    vm.mmio_bus.write(0xfec0_0010, &low.to_le_bytes()).unwrap();
}

fn prepare_retired_timer_guest(fixture: &mut Fixture, cpu_index: usize, vector: u8, finish: &[u8]) {
    let mut guest = vec![0x90; 16];
    guest.extend_from_slice(finish);
    fixture.write(BSP, &guest);
    // Copy the interrupted EIP out of the 32-bit interrupt frame.
    let mut handler = vec![0x8b, 0x04, 0x24, 0xa3, 0, 0x70, 0, 0];
    handler.extend_from_slice(finish);
    fixture.write(0xa000, &handler);
    fixture.write(u64::from(vector) * 8, &[0, 0xa0, 8, 0, 0, 0x8e, 0, 0]);
    let vm = &mut fixture.vm;
    let CpuState::X86_64(mut state) = vm.vcpus[0].get_state().unwrap() else {
        unreachable!();
    };
    state.regs.rflags = 0x202;
    state.sregs.gdt.base = 0x7300;
    state.sregs.gdt.limit = 23;
    state.sregs.idt.base = 0;
    state.sregs.idt.limit = 2047;
    vm.vcpus[cpu_index]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
}

fn assert_retired_timer_delivery(vm: &Vmm, retired: u64) {
    let mut saved_eip = [0; 4];
    vm.guest_mem
        .memory()
        .read_slice(&mut saved_eip, vm_memory::GuestAddress(0x7000))
        .unwrap();
    assert_eq!(u64::from(u32::from_le_bytes(saved_eip)), BSP + 6);
    assert_eq!(vm.coordinator.retired, retired);
    assert_eq!(vm.timing_context.checkpoint_state().retired_units, retired);
}

fn retired_timer_delivery(vector: u8, program_timer: impl FnOnce(&mut Vmm)) {
    let mut fixture = Fixture::with_retired_clock();
    prepare_retired_timer_guest(&mut fixture, 0, vector, &[0xf4]);
    let vm = &mut fixture.vm;
    let clock = vm.timing_context.clone();
    let _scope = clock.enter();
    program_timer(vm);
    let turn = vm.execute_turn().unwrap().unwrap();
    assert!(matches!(turn.exit, VcpuExit::Hlt));
    assert_retired_timer_delivery(vm, 9); // Six NOPs and three handler instructions.
}

#[test]
fn retired_lapic_expiry_interrupts_the_next_guest_instruction() {
    retired_timer_delivery(0x41, |vm| {
        let mut lapic = vm.local_apics[0].lock().unwrap();
        lapic.write_register(0x3e0, 0xb); // Divide by one, 1 GHz.
        lapic.write_register(0x320, 0x41);
        lapic.write_register(0x380, 2); // 2 ns = six retired instructions.
    });
}

fn program_retired_pit_edge(vm: &mut Vmm) {
    // Mode 0 loads at oscillator tick 1 and expires at tick 3.
    vm.io_bus.write(0x43, &[0x10]).unwrap();
    vm.io_bus.write(0x40, &[2]).unwrap();
    let edge = 3_000_000_000u64.div_ceil(crate::vm::timing::PIT_FREQUENCY_HZ);
    vm.timing_context.set_resume_base(edge - 2);
}

#[test]
fn retired_pit_expiry_interrupts_the_next_guest_instruction_through_pic() {
    retired_timer_delivery(0x40, |vm| {
        for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
            vm.io_bus.write(port, &[byte]).unwrap();
        }
        program_retired_pit_edge(vm);
    });
}

#[test]
fn retired_pit_expiry_interrupts_the_next_guest_instruction_through_ioapic() {
    retired_timer_delivery(0x41, |vm| {
        vm.io_bus.write(0x21, &[0xff]).unwrap();
        program(vm, 2, 0x41, 0, false);
        program_retired_pit_edge(vm);
    });
}

fn assert_pc_nmi_delivery_priority(cpu_index: usize) {
    const NMI_HANDLER: u64 = 0xa100;
    const IRQ_HANDLER: u64 = 0xa000;
    let power_off = [0x66, 0xef]; // OUT DX, AX
    for retired in [false, true] {
        let mut fixture = if retired {
            Fixture::with_retired_cpus(2)
        } else {
            Fixture::new(2)
        };
        prepare_retired_timer_guest(&mut fixture, cpu_index, 0x40, &power_off);
        fixture.write(IRQ_HANDLER, &power_off);
        fixture.write(0x51 * 8, &[0, 0xa0, 8, 0, 0, 0x8e, 0, 0]);
        // The trap gate preserves IF. The first handler instruction powers
        // off, so the result observes the initial arbitration boundary.
        fixture.write(2 * 8, &[0, 0xa1, 8, 0, 0, 0x8f, 0, 0]);
        fixture.write(NMI_HANDLER, &power_off);
        fixture.write(0xa200, &[0xe6, 0x80, 0xf4]); // Peer runs first on wall clock.

        let vm = &mut fixture.vm;
        let CpuState::X86_64(mut initial) = vm.vcpus[cpu_index].get_state().unwrap() else {
            unreachable!();
        };
        let initial_rsp = initial.regs.rsp;
        initial.regs.rax = 0x2000;
        initial.regs.rdx = 0x604;
        vm.vcpus[cpu_index]
            .set_state(&CpuState::X86_64(initial.clone()))
            .unwrap();
        vm.coordinator.online.fill(true);
        vm.coordinator.cursor = cpu_index;
        if !retired {
            initial.regs.rip = 0xa200;
            let peer = 1 - cpu_index;
            vm.vcpus[peer]
                .set_state(&CpuState::X86_64(initial))
                .unwrap();
            vm.coordinator.cursor = peer;
        }
        if cpu_index == 0 {
            for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
                vm.io_bus.write(port, &[byte]).unwrap();
            }
            vm.pic.lock().unwrap().pulse_irq(0);
        }
        {
            let mut apic = vm.local_apics[cpu_index].lock().unwrap();
            apic.set_irr(0x51);
            apic.set_pending_nmi();
        }

        vm.run().unwrap();
        let CpuState::X86_64(after) = vm.vcpus[cpu_index].get_state().unwrap() else {
            unreachable!();
        };
        assert_eq!(
            (after.regs.rip, after.regs.rsp),
            (NMI_HANDLER + 2, initial_rsp - 12),
            "retired={retired} cpu={cpu_index}"
        );
        let mut interrupted_eip = [0; 4];
        vm.guest_mem
            .memory()
            .read_slice(
                &mut interrupted_eip,
                vm_memory::GuestAddress(after.regs.rsp),
            )
            .unwrap();
        assert_eq!(u64::from(u32::from_le_bytes(interrupted_eip)), BSP);
        assert_eq!(vm.pic.lock().unwrap().has_pending(), cpu_index == 0);
        let apic = vm.local_apics[cpu_index].lock().unwrap();
        assert!(!apic.has_pending_nmi());
        assert_eq!(apic.get_pending_vector(), Some(0x51));
    }
}

#[test]
fn pc_bsp_nmi_precedes_pic_and_lapic_at_the_same_boundary() {
    assert_pc_nmi_delivery_priority(0);
}

#[test]
fn bsp_pic_request_waits_for_unmasked_lint0_extint_when_apic_is_globally_enabled() {
    let mut fixture = Fixture::with_retired_cpus(1);
    prepare_retired_timer_guest(&mut fixture, 0, 0x40, &[0xf4]);
    let vm = &mut fixture.vm;
    for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
        vm.io_bus.write(port, &[byte]).unwrap();
    }
    vm.pic.lock().unwrap().pulse_irq(0);
    let set_lint0 = |vm: &mut Vmm, value: u32| {
        vm.mmio_bus
            .write(0xfee0_0350, &value.to_le_bytes())
            .unwrap();
    };
    for lint0 in [0x1_0700, 0x51] {
        set_lint0(vm, lint0);
        vm.service_pc_interrupts(0).unwrap();
        assert_eq!(vm.vcpus[0].current_pc(), BSP, "LINT0={lint0:#x}");
        assert!(vm.pic.lock().unwrap().has_pending());
    }
    set_lint0(vm, 0x1_0700);
    let file = RemoveFile::new();
    vm.take_snapshot_bundle(0).unwrap().save(&file.0).unwrap();
    drop(fixture);

    let bundle = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut restored = Vmm::new_resume_bundle(config, &bundle).unwrap();
    restored.service_pc_interrupts(0).unwrap();
    assert_eq!(restored.vcpus[0].current_pc(), BSP);
    assert!(restored.pic.lock().unwrap().has_pending());
    set_lint0(&mut restored, 0x700);
    restored.service_pc_interrupts(0).unwrap();
    assert_eq!(restored.vcpus[0].current_pc(), 0xa000);
    assert!(!restored.pic.lock().unwrap().has_pending());
}

#[test]
fn pc_ap_nmi_precedes_lapic_at_the_same_boundary() {
    assert_pc_nmi_delivery_priority(1);
}

#[test]
fn pc_blocked_nmi_leaves_the_controller_pending_and_allows_a_pic_irq() {
    let mut fixture = Fixture::with_retired_clock();
    prepare_retired_timer_guest(&mut fixture, 0, 0x40, &[0xf4]);
    fixture.write(2 * 8, &[0, 0xa1, 8, 0, 0, 0x8f, 0, 0]);
    let vm = &mut fixture.vm;
    assert!(vm.vcpus[0].inject_nmi().unwrap());
    vm.local_apics[0].lock().unwrap().set_pending_nmi();
    for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
        vm.io_bus.write(port, &[byte]).unwrap();
    }
    vm.pic.lock().unwrap().pulse_irq(0);

    vm.service_pc_interrupts(0).unwrap();
    assert_eq!(vm.vcpus[0].current_pc(), 0xa000);
    assert!(vm.local_apics[0].lock().unwrap().has_pending_nmi());
    assert!(!vm.pic.lock().unwrap().has_pending());
}

#[test]
fn detached_retired_pc_delivers_pit_to_the_selected_ap_at_the_same_instruction() {
    let power_off = [0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef];
    for count in [2, 4] {
        let mut fixture = Fixture::with_retired_cpus(count);
        let cpu_index = usize::from(count - 1);
        prepare_retired_timer_guest(&mut fixture, cpu_index, 0x41, &power_off);
        let source = &mut fixture.vm;
        source.coordinator.online.fill(true);
        source.coordinator.cursor = cpu_index;
        let clock = source.timing_context.clone();
        let scope = clock.enter();
        source.io_bus.write(0x21, &[0xff]).unwrap();
        program(source, 2, 0x41, count - 1, false);
        program_retired_pit_edge(source);
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(scope);
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &bundle).unwrap();
        restored.run().unwrap();
        assert_retired_timer_delivery(&restored, 11); // Six NOPs and five handler instructions.
        for (id, cpu) in restored.vcpus.iter().enumerate() {
            assert_eq!(
                cpu.instruction_count(),
                if id == cpu_index { 11 } else { 0 }
            );
        }
    }
}

fn remote(vm: &mut Vmm, pin: u8) -> bool {
    vm.mmio_bus
        .write(0xfec0_0000, &u32::from(0x10 + 2 * pin).to_le_bytes())
        .unwrap();
    let mut low = [0; 4];
    vm.mmio_bus.read(0xfec0_0010, &mut low).unwrap();
    u32::from_le_bytes(low) & (1 << 14) != 0
}

fn complete_level(vm: &mut Vmm, cpu: usize, vector: u8) {
    vm.local_apics[cpu].lock().unwrap().ack_interrupt(vector);
    vm.mmio_bus
        .with_stopped(|bus| {
            mmio::write(
                bus,
                &vm.local_apics,
                cpu,
                LAPIC_BASE + 0xb0,
                &0u32.to_le_bytes(),
            )
        })
        .unwrap();
}

#[test]
fn detached_one_two_four_cpu_files_retain_eoi_broadcasts_until_real_vmm_routing() {
    for count in [1, 2, 4] {
        let mut fixture = super::super::execution_tests::Fixture::with_memory(count, 128 << 20);
        let cpu = usize::from(count) - 1;
        program(&mut fixture.vm, 20, 0x51, cpu as u8, true);
        fixture.vm.vm.set_irq_line(20, true).unwrap();
        fixture.vm.route_pc_interrupts().unwrap();
        assert!(remote(&mut fixture.vm, 20));
        complete_level(&mut fixture.vm, cpu, 0x51);
        assert!(
            fixture.vm.local_apics[cpu]
                .lock()
                .unwrap()
                .has_pending_eoi()
        );
        let saved = fixture.vm.take_snapshot_bundle(53).unwrap();
        assert_eq!(saved.execution().unwrap().local_apics[cpu].eois, [0x51]);
        let file = RemoveFile::new();
        saved.save(&file.0).unwrap();
        drop(saved);
        drop(fixture); // All source owners and the original kernel file are gone.
        let loaded = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert!(target.local_apics[cpu].lock().unwrap().has_pending_eoi());
        assert!(remote(&mut target, 20));
        target.route_interprocessor_requests().unwrap();
        assert!(!target.local_apics[cpu].lock().unwrap().has_pending_eoi());
        assert_eq!(
            target.local_apics[cpu].lock().unwrap().get_pending_vector(),
            Some(0x51)
        );
        assert!(remote(&mut target, 20));
        target.vm.set_irq_line(20, false).unwrap();
        complete_level(&mut target, cpu, 0x51);
        target.route_interprocessor_requests().unwrap();
        assert!(!remote(&mut target, 20));
        assert_eq!(
            target.local_apics[cpu].lock().unwrap().get_pending_vector(),
            None
        );
    }
}

#[test]
fn backend_line_publication_conserves_edges_levels_and_invalid_source_failures() {
    for level in [false, true] {
        let mut fixture = super::super::execution_tests::Fixture::new(2);
        program(&mut fixture.vm, 20, 0x51, 1, level);
        fixture.vm.vm.set_irq_line(20, true).unwrap();
        fixture.vm.vm.set_irq_line(20, true).unwrap();
        fixture.vm.vm.set_irq_line(20, false).unwrap();
        for invalid in [24, 256, u32::MAX] {
            assert!(fixture.vm.vm.set_irq_line(invalid, true).is_err());
            assert!(fixture.vm.vm.set_irq_line(invalid, false).is_err());
        }
        fixture.vm.route_pc_interrupts().unwrap();
        assert_eq!(
            fixture.vm.local_apics[1]
                .lock()
                .unwrap()
                .get_pending_vector(),
            (!level).then_some(0x51)
        );
        fixture.vm.vm.set_irq_line(20, true).unwrap();
        fixture.vm.route_pc_interrupts().unwrap();
        assert_eq!(
            fixture.vm.local_apics[1]
                .lock()
                .unwrap()
                .get_pending_vector(),
            Some(0x51)
        );
    }
}

#[test]
fn uart_iir_acknowledgement_deasserts_the_same_source_used_by_ioapic_routing() {
    let mut fixture = super::super::execution_tests::Fixture::new(1);
    program(&mut fixture.vm, 4, 0x54, 0, true);
    for (port, value) in [(0x3fc, 8), (0x3f9, 2)] {
        // OUT2 enables the PC UART line; IER then enables its THRE source.
        super::super::port_io::write(
            fixture.vm.io_bus.get_mut().unwrap(),
            &fixture.vm.serial,
            &fixture.vm.pic,
            &*fixture.vm.vm,
            fixture.vm.backend_kind,
            fixture.vm.serial_irq,
            None,
            port,
            &[value],
        )
        .unwrap();
    }
    assert!(fixture.vm.serial.lock().unwrap().has_pending_interrupt());
    fixture.vm.route_pc_interrupts().unwrap();
    assert_eq!(
        fixture.vm.local_apics[0]
            .lock()
            .unwrap()
            .get_pending_vector(),
        Some(0x54)
    );
    assert!(remote(&mut fixture.vm, 4));
    let iir = super::super::port_io::read(
        fixture.vm.io_bus.get_mut().unwrap(),
        &fixture.vm.serial,
        fixture.vm.backend_kind,
        None,
        0x3fa,
        1,
        1,
    )
    .unwrap();
    assert_eq!(iir[0] & 0xf, 2);
    fixture.vm.refresh_pc_irq_sources().unwrap();
    complete_level(&mut fixture.vm, 0, 0x54);
    fixture.vm.route_pc_interrupts().unwrap();
    assert!(!remote(&mut fixture.vm, 4));
    assert_eq!(
        fixture.vm.local_apics[0]
            .lock()
            .unwrap()
            .get_pending_vector(),
        None
    );
}

#[test]
fn rtc_periodic_phase_and_irq8_survive_detached_checkpoint_and_acknowledgement() {
    use crate::vm::vcpu::CheckpointIoReply;
    let mut fixture = Fixture::with_retired_clock();
    let vm = &mut fixture.vm;
    program(vm, 8, 0x58, 0, true);
    vm.io_bus.write(0x21, &[0xfb]).unwrap(); // Unmask the PIC cascade.
    vm.io_bus.write(0xa1, &[0xfe]).unwrap(); // Unmask the slave RTC pin.
    vm.io_bus.write(0x70, &[0x0b, 0xc2]).unwrap(); // SET, PIE, 24-hour mode.
    vm.timing_context.set_resume_base(488_282);
    vm.route_pc_interrupts().unwrap();
    assert!(!remote(vm, 8));
    assert!(!vm.pic.lock().unwrap().has_pending());

    let file = RemoveFile::new();
    vm.take_snapshot_bundle(0).unwrap().save(&file.0).unwrap();
    drop(fixture);
    let bundle = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();

    target.timing_context.set_resume_base(976_562);
    target.route_pc_interrupts().unwrap();
    assert!(!remote(&mut target, 8));
    target.timing_context.set_resume_base(976_563);
    target.route_pc_interrupts().unwrap();
    assert!(
        remote(&mut target, 8),
        "RTC IRQ8 missing at the first full period"
    );
    assert!(target.pic.lock().unwrap().has_pending());
    assert_eq!(
        target.local_apics[0].lock().unwrap().get_pending_vector(),
        Some(0x58)
    );
    assert_eq!(target.pic.lock().unwrap().get_pending_vector(), Some(0x28));

    // Both controllers have accepted this line. A detached restore must keep
    // the saved input high without creating another edge in the PIC.
    let asserted = RemoveFile::new();
    target
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&asserted.0)
        .unwrap();
    drop(target);
    let bundle = SnapshotBundle::load(&asserted.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    assert!(remote(&mut target, 8));
    target.io_bus.write(0xa0, &[0x20]).unwrap();
    target.io_bus.write(0x20, &[0x20]).unwrap();
    assert_eq!(target.pic.lock().unwrap().get_pending_vector(), None);

    target.io_bus.write(0x70, &[0x0c]).unwrap();
    let CheckpointIoReply::Input(status) = target
        .checkpoint_io_service(
            0,
            VcpuExit::IoIn {
                port: 0x71,
                size: 1,
            },
        )
        .unwrap()
    else {
        panic!("expected RTC input");
    };
    assert_eq!(status, [0xc0]);
    complete_level(&mut target, 0, 0x58);
    target.route_pc_interrupts().unwrap();
    assert!(
        !remote(&mut target, 8),
        "RTC IRQ8 reappeared after acknowledgement"
    );
    target.timing_context.set_resume_base(1_953_125);
    target.route_pc_interrupts().unwrap();
    assert!(remote(&mut target, 8));
}

#[test]
fn pit_publishes_the_gsi2_edge_even_while_the_legacy_pic_is_busy() {
    let mut fixture = super::super::execution_tests::Fixture::new(1);
    let clock = fixture.vm.timing_context.clone();
    let _scope = clock.enter();
    program(&mut fixture.vm, 2, 0x52, 0, false);
    fixture.vm.io_bus.write(0x21, &[0xdf]).unwrap(); // Unmask the busy IRQ5.
    fixture.vm.pic.lock().unwrap().set_irq(5, true);
    assert!(fixture.vm.pic.lock().unwrap().has_active_irq());
    fixture.vm.io_bus.write(0x43, &[0x30]).unwrap();
    fixture.vm.io_bus.write(0x40, &[10]).unwrap();
    fixture.vm.io_bus.write(0x40, &[0]).unwrap();
    clock.set_resume_base(clock.elapsed_nanos().wrapping_add(1_000_000));
    fixture.vm.poll_pc_pit().unwrap();
    fixture.vm.route_pc_interrupts().unwrap();
    assert_eq!(
        fixture.vm.local_apics[0]
            .lock()
            .unwrap()
            .get_pending_vector(),
        Some(0x52)
    );
    assert!(!fixture.vm.pit.lock().unwrap().has_pending_interrupt());
}

#[test]
fn detached_periodic_pit_keeps_the_active_cycle_and_replacement_irq_deadline() {
    let nanos_at =
        |ticks: u64| (ticks * 1_000_000_000).div_ceil(crate::vm::timing::PIT_FREQUENCY_HZ);
    let read_counter = |vm: &mut Vmm| {
        let mut byte = [0];
        vm.io_bus.read(0x40, &mut byte).unwrap();
        byte[0]
    };
    for (command, divisor, replacement, observations) in [
        (
            0x34,
            4,
            6,
            [
                (4, 0x74, 1, None),
                (5, 0xb4, 6, Some(0x53)),
                (6, 0xb4, 5, None),
                (10, 0x34, 1, None),
                (11, 0xb4, 6, Some(0x53)),
            ],
        ),
        (
            0x36,
            5,
            8,
            [
                (3, 0xf6, 0, None),
                (4, 0x36, 8, None),
                (7, 0x36, 2, None),
                (8, 0xb6, 8, Some(0x53)),
                (9, 0xb6, 6, None),
            ],
        ),
    ] {
        let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
        let source = &mut fixture.vm;
        let clock = source.timing_context.clone();
        let scope = clock.enter();
        program(source, 2, 0x53, 0, false);
        source.io_bus.write(0x43, &[command]).unwrap();
        source.io_bus.write(0x40, &[divisor]).unwrap();
        source.io_bus.write(0x40, &[0]).unwrap();
        clock.set_resume_base(nanos_at(2));
        source.io_bus.write(0x40, &[replacement]).unwrap();
        source.io_bus.write(0x40, &[0]).unwrap();
        clock.set_resume_base(nanos_at(observations[0].0));
        source.poll_pc_pit().unwrap();
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(scope);
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        let clock = target.timing_context.clone();
        let _scope = clock.enter();
        for (tick, status, count, vector) in observations {
            clock.set_resume_base(nanos_at(tick));
            target.poll_pc_pit().unwrap();
            target.route_pc_interrupts().unwrap();
            target.io_bus.write(0x43, &[0xc2]).unwrap();
            assert_eq!(read_counter(&mut target), status, "tick {tick}");
            let bytes = [read_counter(&mut target), read_counter(&mut target)];
            assert_eq!(u16::from_le_bytes(bytes), count, "tick {tick}");
            let mut lapic = target.local_apics[0].lock().unwrap();
            assert_eq!(lapic.get_pending_vector(), vector, "tick {tick}");
            if let Some(vector) = vector {
                lapic.ack_interrupt(vector);
                lapic.write_register(0xb0, 0);
            }
        }
    }
}

#[test]
fn software_pit_strobe_rising_edge_is_delivered_once_after_detached_restore() {
    let mut fixture = super::super::execution_tests::Fixture::with_retired_clock();
    let source = &mut fixture.vm;
    let clock = source.timing_context.clone();
    let scope = clock.enter();
    program(source, 2, 0x53, 0, false);
    source.io_bus.write(0x43, &[0x18]).unwrap(); // Channel 0, LSB, mode 4.
    source.io_bus.write(0x40, &[10]).unwrap();
    let nanos_at =
        |ticks: u64| (ticks * 1_000_000_000).div_ceil(crate::vm::timing::PIT_FREQUENCY_HZ);
    clock.set_resume_base(nanos_at(11)); // OUT is low; the rising edge is still pending.
    source.poll_pc_pit().unwrap();
    source.route_pc_interrupts().unwrap();
    assert_eq!(
        source.local_apics[0].lock().unwrap().get_pending_vector(),
        None
    );

    let file = RemoveFile::new();
    source
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&file.0)
        .unwrap();
    drop(scope);
    drop(fixture);

    let bundle = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
    let clock = target.timing_context.clone();
    let _scope = clock.enter();
    for (ticks, expected) in [(12, Some(0x53)), (20, None), (100, None)] {
        clock.set_resume_base(nanos_at(ticks));
        target.poll_pc_pit().unwrap();
        target.route_pc_interrupts().unwrap();
        let mut lapic = target.local_apics[0].lock().unwrap();
        assert_eq!(lapic.get_pending_vector(), expected);
        if let Some(vector) = expected {
            lapic.ack_interrupt(vector);
            lapic.write_register(0xb0, 0);
        }
    }
    target.io_bus.write(0x40, &[10]).unwrap(); // A new count starts a new strobe.
    clock.set_resume_base(nanos_at(112));
    target.poll_pc_pit().unwrap();
    target.route_pc_interrupts().unwrap();
    assert_eq!(
        target.local_apics[0].lock().unwrap().get_pending_vector(),
        Some(0x53)
    );
}

#[test]
fn base_capture_and_base_file_publication_reject_unrepresented_eoi_broadcasts() {
    let fixture = super::super::execution_tests::Fixture::new(1);
    let mut base = fixture.vm.take_snapshot(0).unwrap();
    {
        let mut apic = fixture.vm.local_apics[0].lock().unwrap();
        apic.receive_external_interrupt(0x51, true);
        apic.ack_interrupt(0x51);
        apic.write_register(0xb0, 0);
    }
    assert!(fixture.vm.take_snapshot(0).is_err());
    base.devices.lapic.receive_external_interrupt(0x51, true);
    base.devices.lapic.ack_interrupt(0x51);
    base.devices.lapic.write_register(0xb0, 0);
    let file = RemoveFile::new();
    std::fs::write(&file.0, b"existing checkpoint").unwrap();
    assert!(base.save(&file.0).is_err());
    assert_eq!(std::fs::read(&file.0).unwrap(), b"existing checkpoint");
}

#[test]
fn nmi_handler_and_pending_nmi_continue_from_a_detached_checkpoint() {
    const HANDLER: u64 = 0xa000;
    const RETURN_PCS: u64 = 0x7060;
    for count in [1, 2, 4] {
        let mut fixture = Fixture::with_retired_cpus(count);
        let cpu_index = usize::from(count - 1);
        let power_off = [0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef];
        prepare_retired_timer_guest(&mut fixture, cpu_index, 2, &power_off);
        // Record each handler's interrupted EIP at [0x7060 + ECX*4].
        // The guest starts with ECX=0, increments after each record, then IRETDs.
        fixture.write(
            HANDLER,
            &[
                0x8b, 0x04, 0x24, 0x89, 0x04, 0x8d, 0x60, 0x70, 0, 0, 0x41, 0xcf,
            ],
        );
        let source = &mut fixture.vm;
        source.coordinator.online.fill(true);
        source.coordinator.cursor = cpu_index;
        assert!(source.vcpus[cpu_index].inject_nmi().unwrap());
        source.local_apics[cpu_index]
            .lock()
            .unwrap()
            .set_pending_nmi();
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        target.poll_local_apic(cpu_index, false).unwrap();
        assert!(
            target.local_apics[cpu_index]
                .lock()
                .unwrap()
                .has_pending_nmi()
        );
        assert_eq!(target.vcpus[cpu_index].current_pc(), HANDLER);
        target.run().unwrap();
        assert!(
            !target.local_apics[cpu_index]
                .lock()
                .unwrap()
                .has_pending_nmi()
        );
        let mut return_pcs = [0; 8];
        target
            .guest_mem
            .memory()
            .read_slice(&mut return_pcs, vm_memory::GuestAddress(RETURN_PCS))
            .unwrap();
        let expected = (BSP as u32).to_le_bytes();
        assert_eq!(return_pcs[..4], expected);
        assert_eq!(return_pcs[4..], expected);
    }
}

#[test]
fn restored_ioapic_nmi_reaches_the_target_with_its_lapic_software_disabled() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::with_retired_cpus(count);
        let cpu_index = usize::from(count - 1);
        let power_off = [0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef];
        prepare_retired_timer_guest(&mut fixture, cpu_index, 2, &power_off);
        fixture.write(0xa000, &[0x8b, 0x04, 0x24, 0xa3, 0, 0x70, 0, 0, 0x41, 0xcf]); // Record interrupted EIP, increment ECX, IRETD.
        let source = &mut fixture.vm;
        source.coordinator.online.fill(true);
        source.coordinator.cursor = cpu_index;
        source.local_apics[cpu_index]
            .lock()
            .unwrap()
            .write_register(0xf0, 0xff);
        program(source, 20, 0, cpu_index as u8, false);
        source
            .mmio_bus
            .write(0xfec0_0010, &0x400u32.to_le_bytes())
            .unwrap(); // Delivery mode NMI, independent of the vector field.
        program(source, 21, 0x51, cpu_index as u8, false);
        {
            let mut ioapic = source.pc_devices.as_ref().unwrap().ioapic.lock().unwrap();
            for pin in [20, 21] {
                ioapic.set_irq(pin, true);
                ioapic.set_irq(pin, false);
            }
        }
        let file = RemoveFile::new();
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&file.0)
            .unwrap();
        drop(fixture);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        target.route_pc_interrupts().unwrap();
        for (index, lapic) in target.local_apics.iter().enumerate() {
            let lapic = lapic.lock().unwrap();
            assert_eq!(lapic.has_pending_nmi(), index == cpu_index, "count={count}");
            assert_eq!(lapic.get_pending_vector(), None);
        }
        target.run().unwrap();
        let CpuState::X86_64(after) = target.vcpus[cpu_index].get_state().unwrap() else {
            unreachable!();
        };
        assert_eq!(after.regs.rcx, 1);
        let mut interrupted_eip = [0; 4];
        target
            .guest_mem
            .memory()
            .read_slice(&mut interrupted_eip, vm_memory::GuestAddress(0x7000))
            .unwrap();
        assert_eq!(u64::from(u32::from_le_bytes(interrupted_eip)), BSP);
        let ioapic = target.pc_devices.as_ref().unwrap().ioapic.lock().unwrap();
        assert_eq!(ioapic.pending().len(), 1);
        assert_eq!(ioapic.pending()[0].gsi, 21);
    }
}

#[test]
fn i8042_irq12_reaches_the_guest_interrupt_controller_on_normal_port_output() {
    let mut fixture = Fixture::new(1);
    program(&mut fixture.vm, 12, 0x5c, 0, false);
    fixture.write(
        BSP,
        &[
            0xb0, 0x60, 0xe6, 0x64, // Arm the command-byte write.
            0xb0, 0x22, 0xe6, 0x60, // IRQ12 enabled, external auxiliary port disabled.
            0xb0, 0xd3, 0xe6, 0x64, // Arm internal auxiliary output.
            0xb0, 0x5a, 0xe6, 0x60, // Queue an auxiliary byte.
            0xba, 0x04, 0x06, 0, 0, // mov edx, 0x604
            0x66, 0xb8, 0, 0x20, // mov ax, 0x2000
            0x66, 0xef, // ACPI S5, handled by the ordinary run loop.
        ],
    );
    fixture.vm.run().unwrap();
    fixture.vm.route_pc_interrupts().unwrap();
    assert_eq!(
        fixture.vm.local_apics[0]
            .lock()
            .unwrap()
            .get_pending_vector(),
        Some(0x5c)
    );
}

#[test]
fn i8042_irq12_reedges_when_a_detached_output_latch_refills_during_batched_input() {
    use crate::vm::vcpu::CheckpointIoReply;

    let mut fixture = Fixture::with_memory(1, 128 << 20);
    program(&mut fixture.vm, 12, 0x5c, 0, false);
    for (port, value) in [
        (0x64, 0x60),
        (0x60, 0x22),
        (0x64, 0xd3),
        (0x60, 0x5a),
        (0x64, 0xd3),
        (0x60, 0x6b),
    ] {
        let outcome = fixture
            .vm
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                },
            )
            .unwrap();
        assert!(matches!(outcome, CheckpointIoReply::Output));
    }
    fixture.vm.route_pc_interrupts().unwrap();
    assert_eq!(
        fixture.vm.local_apics[0]
            .lock()
            .unwrap()
            .get_pending_vector(),
        Some(0x5c)
    );
    complete_level(&mut fixture.vm, 0, 0x5c);
    fixture.vm.route_pc_interrupts().unwrap();
    let file = RemoveFile::new();
    fixture
        .vm
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&file.0)
        .unwrap();
    drop(fixture);

    let image = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&image, CliConfig::default()).unwrap();
    let target = Vmm::new_resume_bundle(config, &image).unwrap();
    assert_eq!(
        target.local_apics[0].lock().unwrap().get_pending_vector(),
        None
    );
    let outcome = target
        .checkpoint_io_service(
            0,
            VcpuExit::IoInString {
                port: 0x60,
                size: 1,
                count: 2,
            },
        )
        .unwrap();
    assert!(matches!(outcome, CheckpointIoReply::Input(bytes) if bytes == [0x5a, 0x6b]));
    target.route_pc_interrupts().unwrap();
    assert_eq!(
        target.local_apics[0].lock().unwrap().get_pending_vector(),
        Some(0x5c),
        "Consuming the first byte lowers the line. Refilling it raises a second edge."
    );
}

#[test]
fn i8042_irq1_tracks_the_command_gate_while_the_output_latch_stays_full() {
    use crate::vm::vcpu::CheckpointIoReply;

    let mut fixture = Fixture::new(1);
    let vm = &mut fixture.vm;
    let vector = 0x51;
    program(vm, 1, vector, 0, true);
    let write = |vm: &Vmm, port, value| {
        let reply = vm
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                },
            )
            .unwrap();
        assert!(matches!(reply, CheckpointIoReply::Output));
    };
    let command = |vm: &Vmm, value| {
        write(vm, 0x64, 0x60);
        write(vm, 0x60, value);
    };
    let pending = |vm: &Vmm| {
        vm.route_pc_interrupts().unwrap();
        vm.local_apics[0].lock().unwrap().get_pending_vector()
    };
    command(vm, 0);
    write(vm, 0x60, 0xf4); // Keyboard ACK fills the latch with IRQ1 disabled.
    assert_eq!(pending(vm), None);
    command(vm, 1);
    assert_eq!(pending(vm), Some(vector));
    assert!(remote(vm, 1));

    command(vm, 0);
    complete_level(vm, 0, vector);
    assert_eq!(pending(vm), None);
    assert!(!remote(vm, 1));

    command(vm, 1);
    assert_eq!(pending(vm), Some(vector));
    let reply = vm
        .checkpoint_io_service(
            0,
            VcpuExit::IoIn {
                port: 0x60,
                size: 1,
            },
        )
        .unwrap();
    assert!(matches!(reply, CheckpointIoReply::Input(bytes) if bytes == [0xfa]));
    complete_level(vm, 0, vector);
    assert_eq!(pending(vm), None);
    assert!(!remote(vm, 1));
}

#[test]
fn failed_native_rtc_acknowledgement_disables_guest_entry() {
    use crate::backend::Vm;
    use crate::vm::vcpu::VCpu;
    use std::any::Any;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use vm_memory::GuestMemoryMmap;

    struct FaultedRtcIrq {
        calls: Arc<Mutex<Vec<bool>>>,
        entry_disabled: Arc<AtomicBool>,
    }

    impl Vm for FaultedRtcIrq {
        fn uses_native_x86_irqchip(&self) -> bool {
            true
        }

        fn create_vcpu(&self, _id: u32, _mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
            unreachable!()
        }

        fn set_irq_line(&self, irq: u32, asserted: bool) -> Result<()> {
            assert_eq!(irq, u32::from(RTC_IRQ));
            self.calls.lock().unwrap().push(asserted);
            if asserted {
                Ok(())
            } else {
                Err(Error::Emulator("injected RTC IRQ8 deassert failure".into()))
            }
        }

        fn poison_checkpoint_restore(&self) {
            self.entry_disabled.store(true, Ordering::Release);
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let mut fixture = Fixture::with_retired_clock();
    let vm = &mut fixture.vm;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let entry_disabled = Arc::new(AtomicBool::new(false));
    vm.vm = Box::new(FaultedRtcIrq {
        calls: calls.clone(),
        entry_disabled: entry_disabled.clone(),
    });
    vm.io_bus.write(0x70, &[0x0b, 0xc2]).unwrap();
    vm.timing_context.set_resume_base(976_563);
    vm.poll_pc_rtc().unwrap();
    assert!(!entry_disabled.load(Ordering::Acquire));

    vm.io_bus.write(0x70, &[0x0c]).unwrap();
    let read = || {
        vm.checkpoint_io_service(
            0,
            VcpuExit::IoIn {
                port: 0x71,
                size: 1,
            },
        )
    };
    assert!(matches!(read(), Err(Error::Emulator(msg))
        if msg == "injected RTC IRQ8 deassert failure"));
    assert!(entry_disabled.load(Ordering::Acquire));
    assert_eq!(*calls.lock().unwrap(), vec![true, false]);
    let mut status = [0xff];
    vm.io_bus.read(0x71, &mut status).unwrap();
    assert_eq!(status, [0], "the device already consumed Register C");
}

#[test]
fn held_i8042_output_does_not_retrigger_the_pic_after_detached_restore() {
    use crate::vm::vcpu::CheckpointIoReply;

    let write = |vm: &Vmm, port, value| {
        let outcome = vm
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                },
            )
            .unwrap();
        assert!(matches!(outcome, CheckpointIoReply::Output));
    };
    let queue_byte = |vm: &Vmm, irq, value| {
        // A keyboard command produces ACK. D3 loops the byte back on AUX.
        if irq == 12 {
            write(vm, 0x64, 0xd3);
        }
        write(vm, 0x60, value);
    };
    for (irq, gate, vector, reply_byte) in [(1, 1, 0x21, 0xfa), (12, 2, 0x2c, 0x69)] {
        let mut source = Fixture::with_memory(1, 128 << 20);
        let vm = &mut source.vm;
        vm.io_bus.write(0x21, &[0xf9]).unwrap();
        vm.io_bus.write(0xa1, &[0xef]).unwrap();
        write(vm, 0x64, 0x60);
        write(vm, 0x60, gate);
        queue_byte(vm, irq, 0x69);
        assert_eq!(vm.pic.lock().unwrap().get_pending_vector(), Some(vector));
        let file = RemoveFile::new();
        vm.take_snapshot_bundle(0).unwrap().save(&file.0).unwrap();
        drop(source);

        let bundle = SnapshotBundle::load(&file.0).unwrap();
        drop(file);
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        if irq == 12 {
            target.io_bus.write(0xa0, &[0x20]).unwrap();
        }
        target.io_bus.write(0x20, &[0x20]).unwrap();
        {
            let mut pic = target.pic.lock().unwrap();
            assert_eq!(pic.get_pending_vector(), None);
            pic.set_irq(irq, true);
            assert_eq!(
                pic.get_pending_vector(),
                None,
                "refreshing the still-high IRQ{irq} wire cannot create a rising edge"
            );
        }
        let reply = target
            .checkpoint_io_service(
                0,
                VcpuExit::IoIn {
                    port: 0x60,
                    size: 1,
                },
            )
            .unwrap();
        assert!(matches!(reply, CheckpointIoReply::Input(bytes) if bytes == [reply_byte]));
        queue_byte(&target, irq, 0x74);
        assert_eq!(
            target.pic.lock().unwrap().get_pending_vector(),
            Some(vector)
        );
    }
}

#[test]
fn reading_the_uart_iir_releases_a_level_pic_input_at_the_pio_boundary() {
    use crate::vm::vcpu::CheckpointIoReply;

    for count in [1, 2] {
        let mut fixture = Fixture::new(1);
        let vm = &mut fixture.vm;
        // A single, level-triggered master at vectors 0x20..0x27, IRQ4 unmasked.
        for (port, byte) in [(0x20, 0x1b), (0x21, 0x20), (0x21, 1), (0x21, 0xef)] {
            vm.io_bus.write(port, &[byte]).unwrap();
        }
        for (port, value) in [(0x3fc, 8), (0x3f9, 2)] {
            assert!(matches!(
                vm.checkpoint_io_service(
                    0,
                    VcpuExit::IoOut {
                        port,
                        data: vec![value]
                    }
                )
                .unwrap(),
                CheckpointIoReply::Output
            ));
        }
        vm.route_pc_interrupts().unwrap();
        assert!(vm.pic.lock().unwrap().has_pending());

        let event = if count == 1 {
            VcpuExit::IoIn {
                port: 0x3fa,
                size: 1,
            }
        } else {
            VcpuExit::IoInString {
                port: 0x3fa,
                size: 1,
                count,
            }
        };
        let CheckpointIoReply::Input(bytes) = vm.checkpoint_io_service(0, event).unwrap() else {
            panic!("expected UART interrupt-identification input");
        };
        let expected = [2, 1];
        assert_eq!(
            bytes.iter().map(|byte| byte & 0xf).collect::<Vec<_>>(),
            expected[..count as usize]
        );
        assert!(!vm.serial.lock().unwrap().has_pending_interrupt());
        assert!(
            !vm.pic.lock().unwrap().has_pending(),
            "PIC kept the UART input asserted after the IIR acknowledgement"
        );
    }
}

#[test]
fn detached_uart_irq_rebinds_the_pic_input_without_replaying_its_edge() {
    use crate::vm::vcpu::CheckpointIoReply;

    let mut fixture = Fixture::with_retired_clock();
    let source = &mut fixture.vm;
    source.io_bus.write(0x21, &[0xef]).unwrap();
    for (port, value) in [(0x3fc, 8), (0x3f9, 2)] {
        source
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port,
                    data: vec![value],
                },
            )
            .unwrap();
    }
    assert_eq!(source.pic.lock().unwrap().get_pending_vector(), Some(0x24));
    let file = RemoveFile::new();
    source
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&file.0)
        .unwrap();
    drop(fixture);

    let image = SnapshotBundle::load(&file.0).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&image, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &image).unwrap();
    target.io_bus.write(0x20, &[0x20]).unwrap(); // Retire the original ISR bit.
    // Accessing the scratch register republishes the same held UART input.
    target
        .checkpoint_io_service(
            0,
            VcpuExit::IoOut {
                port: 0x3ff,
                data: vec![0x77],
            },
        )
        .unwrap();
    assert_eq!(
        target.pic.lock().unwrap().get_pending_vector(),
        None,
        "restoration replayed an already acknowledged UART edge"
    );

    assert!(matches!(
        target.checkpoint_io_service(0, VcpuExit::IoIn { port: 0x3fa, size: 1 })
            .unwrap(),
        CheckpointIoReply::Input(bytes) if bytes[0] & 0xf == 2
    ));
    for value in [0, 2] {
        target
            .checkpoint_io_service(
                0,
                VcpuExit::IoOut {
                    port: 0x3f9,
                    data: vec![value],
                },
            )
            .unwrap();
    }
    assert_eq!(target.pic.lock().unwrap().get_pending_vector(), Some(0x24));
}
