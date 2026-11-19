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

#[test]
fn retired_pc_delivers_a_pending_nmi_before_the_pic_handler_executes() {
    let mut fixture = Fixture::with_retired_clock();
    prepare_retired_timer_guest(&mut fixture, 0, 0x40, &[0xf4]);
    fixture.write(0xa000, &[0xc6, 0x05, 0, 0x70, 0, 0, 0x11, 0xf4]);
    fixture.write(0xa100, &[0xc6, 0x05, 1, 0x70, 0, 0, 0x22, 0xf4]);
    fixture.write(2 * 8, &[0, 0xa1, 8, 0, 0, 0x8e, 0, 0]);
    let vm = &mut fixture.vm;
    for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
        vm.io_bus.write(port, &[byte]).unwrap();
    }
    vm.pic.lock().unwrap().pulse_irq(0);
    vm.local_apics[0].lock().unwrap().set_pending_nmi();

    let turn = vm.execute_turn().unwrap().unwrap();
    assert!(matches!(turn.exit, VcpuExit::Hlt));
    let mut markers = [0; 2];
    vm.guest_mem
        .memory()
        .read_slice(&mut markers, vm_memory::GuestAddress(0x7000))
        .unwrap();
    assert_eq!(markers, [0, 0x22]);
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
