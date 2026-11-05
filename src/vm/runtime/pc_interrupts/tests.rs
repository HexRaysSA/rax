//! Actual VMM source/controller ownership and detached checkpoint continuation.
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
