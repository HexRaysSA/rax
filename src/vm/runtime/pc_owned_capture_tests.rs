//! PC device state survives coordinated restore and a detached file/new-VM path.
use super::*;
use crate::config::CliConfig;
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn port(vm: &mut Vmm, address: u16) -> u8 {
    let mut byte = [0];
    vm.io_bus.read(address, &mut byte).unwrap();
    byte[0]
}

fn cmos_observation(vm: &mut Vmm) -> (u8, u8) {
    let index_and_nmi = port(vm, 0x70);
    vm.io_bus.write(0x70, &[0xb8]).unwrap();
    (index_and_nmi, port(vm, 0x71))
}

fn seed_cmos(vm: &mut Vmm) {
    vm.io_bus.write(0x70, &[0xb8]).unwrap();
    vm.io_bus.write(0x71, &[0xa5]).unwrap();
    assert_eq!(cmos_observation(vm), (0xb8, 0xa5));
}

#[test]
fn complete_restore_recovers_cmos_ram_index_and_nmi_latch() {
    let mut fixture = super::execution_tests::Fixture::new(2);
    seed_cmos(&mut fixture.vm);
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    fixture.vm.io_bus.write(0x70, &[0x38]).unwrap();
    fixture.vm.io_bus.write(0x71, &[0x5a]).unwrap();
    fixture.vm.io_bus.write(0x70, &[0x39]).unwrap();
    fixture.vm.restore_snapshot_bundle(&saved).unwrap();
    assert_eq!(cmos_observation(&mut fixture.vm), (0xb8, 0xa5));
}

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn actual_file_new_vmm_recovers_cmos_ram_index_and_nmi_latch() {
    let mut fixture = super::execution_tests::Fixture::with_memory(2, 128 * 1024 * 1024);
    seed_cmos(&mut fixture.vm);
    let media: Vec<u8> = (0..8192)
        .map(|index| (index as u8).wrapping_mul(37))
        .collect();
    fixture
        .vm
        .pc_devices
        .as_ref()
        .unwrap()
        .ide_primary
        .lock()
        .unwrap()
        .attach_cdrom(Arc::new(media));
    for (port, byte) in [(0x1f6, 0xe0), (0x1f4, 0), (0x1f5, 2), (0x1f7, 0xa0)] {
        fixture.vm.io_bus.write(port, &[byte]).unwrap();
    }
    // READ(10), LBA1, one2048-byte block. Freeze after5 of12 packet bytes.
    let packet = [0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0];
    for byte in &packet[..5] {
        fixture.vm.io_bus.write(0x1f0, &[*byte]).unwrap();
    }
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    let file = RemoveFile(std::env::temp_dir().join(format!(
        "rax-pc-device-image-{}-{}.rxc",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    saved.save(&file.0).unwrap();
    let loaded = SnapshotBundle::load(&file.0).unwrap();
    drop(fixture); // Detached resume must not reopen the original kernel path.
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert_eq!(cmos_observation(&mut target), (0xb8, 0xa5));
    for byte in &packet[5..] {
        target.io_bus.write(0x1f0, &[*byte]).unwrap();
    }
    for index in 2048..4096 {
        assert_eq!(
            port(&mut target, 0x1f0),
            (index as u8).wrapping_mul(37),
            "restored ATAPI byte {index}"
        );
    }
}

#[test]
fn complete_restore_recovers_firmware_configuration_read_cursor() {
    let mut fixture = super::execution_tests::Fixture::new(2);
    fixture.vm.io_bus.write(0x510, &0u16.to_le_bytes()).unwrap();
    assert_eq!(port(&mut fixture.vm, 0x511), b'Q');
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    for expected in [b'E', b'M', b'U', 0] {
        assert_eq!(port(&mut fixture.vm, 0x511), expected);
    }
    fixture.vm.restore_snapshot_bundle(&saved).unwrap();
    assert_eq!(port(&mut fixture.vm, 0x511), b'E');
}

fn ioapic_write(vm: &mut Vmm, value: u32) {
    vm.mmio_bus
        .write(0xfec0_0000, &0x10u32.to_le_bytes())
        .unwrap();
    vm.mmio_bus
        .write(0xfec0_0010, &value.to_le_bytes())
        .unwrap();
}

fn ioapic_read(vm: &mut Vmm) -> u32 {
    vm.mmio_bus
        .write(0xfec0_0000, &0x10u32.to_le_bytes())
        .unwrap();
    let mut bytes = [0; 4];
    vm.mmio_bus.read(0xfec0_0010, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn complete_restore_recovers_ioapic_redirection_state() {
    let mut fixture = super::execution_tests::Fixture::new(2);
    ioapic_write(&mut fixture.vm, 0x51);
    assert_eq!(ioapic_read(&mut fixture.vm), 0x51);
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    ioapic_write(&mut fixture.vm, 0x52);
    assert_eq!(ioapic_read(&mut fixture.vm), 0x52);
    fixture.vm.restore_snapshot_bundle(&saved).unwrap();
    assert_eq!(ioapic_read(&mut fixture.vm), 0x51);
}

#[test]
fn missing_pc_component_is_rejected_before_cpu_ram_or_cmos_changes() {
    let mut fixture = super::execution_tests::Fixture::new(1);
    let mut saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    let mut execution = saved.take_execution().unwrap();
    execution.pc = None;
    saved = saved.with_execution(execution).unwrap();
    seed_cmos(&mut fixture.vm);
    fixture.vm.io_bus.write(0x71, &[0x5a]).unwrap();
    fixture.write(0x7800, &[0x45]);
    let mut state = fixture.vm.vcpus[0].get_state().unwrap();
    let CpuState::X86_64(cpu) = &mut state else {
        unreachable!()
    };
    cpu.regs.rax = 0x12345678;
    fixture.vm.vcpus[0].set_state(&state).unwrap();
    let error = fixture
        .vm
        .restore_snapshot_bundle(&saved)
        .unwrap_err()
        .to_string();
    assert!(error.contains("PC component"), "{error}");
    assert_eq!(
        crate::codec::serialize(&state).unwrap(),
        crate::codec::serialize(&fixture.vm.vcpus[0].get_state().unwrap()).unwrap()
    );
    let mut byte = [0];
    fixture
        .vm
        .guest_mem
        .memory()
        .read_slice(&mut byte, vm_memory::GuestAddress(0x7800))
        .unwrap();
    assert_eq!(byte, [0x45]);
    assert_eq!(cmos_observation(&mut fixture.vm), (0xb8, 0x5a));
}

#[test]
fn missing_pc_media_rejects_before_device_mutation() {
    let mut fixture = super::execution_tests::Fixture::new(1);
    let mut saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    assert!(saved.take_resources().is_some());
    seed_cmos(&mut fixture.vm);
    let error = fixture
        .vm
        .restore_snapshot_bundle(&saved)
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing checkpoint media"), "{error}");
    assert_eq!(cmos_observation(&mut fixture.vm), (0xb8, 0xa5));
}

#[test]
fn pc_resources_are_bound_when_cpu_producers_have_no_private_payload() {
    struct NoPrivate {
        id: u32,
        state: CpuState,
    }
    impl crate::vm::vcpu::VCpu for NoPrivate {
        fn id(&self) -> u32 {
            self.id
        }
        fn run(&mut self) -> Result<VcpuExit> {
            panic!("capture must not execute this CPU")
        }
        fn get_state(&self) -> Result<CpuState> {
            Ok(self.state.clone())
        }
        fn set_state(&mut self, state: &CpuState) -> Result<()> {
            self.state = state.clone();
            Ok(())
        }
        fn complete_io_in(&mut self, _: &[u8]) {}
    }
    let mut fixture = super::execution_tests::Fixture::new(2);
    for (index, cpu) in fixture.vm.vcpus.iter_mut().enumerate() {
        *cpu = Box::new(NoPrivate {
            id: index as u32,
            state: cpu.get_state().unwrap(),
        });
    }
    let saved = fixture.vm.take_snapshot_bundle(0).unwrap();
    assert!(saved.backend_contexts().is_none());
    assert_eq!(saved.cpus().unwrap().entries().len(), 2);
    assert!(saved.resources().is_some());
    assert!(saved.execution().unwrap().pc.is_some());
    let file = RemoveFile(
        std::env::temp_dir().join(format!("rax-pc-empty-slots-{}.rxc", std::process::id())),
    );
    saved.save(&file.0).unwrap();
    let loaded = SnapshotBundle::load(&file.0).unwrap();
    assert!(loaded.backend_contexts().is_none());
    assert_eq!(loaded.cpus().unwrap().entries().len(), 2);
    assert!(loaded.resources().is_some());
    let original = std::fs::read(&file.0).unwrap();
    let count = u32::from_le_bytes(original[16..20].try_into().unwrap()) as usize;
    let mut at = 20;
    let mut rows = Vec::new();
    for _ in 0..count {
        let kind = u32::from_le_bytes(original[at..at + 4].try_into().unwrap());
        let length = u64::from_le_bytes(original[at + 8..at + 16].try_into().unwrap()) as usize;
        rows.push((kind, original[at..at + 16 + length].to_vec()));
        at += 16 + length;
    }
    assert_eq!(at, original.len());
    let pc = rows.iter().position(|(kind, _)| *kind == 13).unwrap();
    let media = rows.iter().position(|(kind, _)| *kind == 15).unwrap();
    rows.swap(pc, media);
    let mut reordered = original[..20].to_vec();
    for (_, row) in rows {
        reordered.extend_from_slice(&row);
    }
    std::fs::write(&file.0, reordered).unwrap();
    assert!(
        SnapshotBundle::load(&file.0)
            .unwrap_err()
            .to_string()
            .contains("preceding CPU and backend or PC owner")
    );
    std::fs::write(&file.0, &original).unwrap();
    let mut orphan = loaded;
    orphan.take_execution();
    let error = orphan.save(&file.0).unwrap_err().to_string();
    assert!(error.contains("backend or PC owner"), "{error}");
    assert_eq!(std::fs::read(&file.0).unwrap(), original);
}
