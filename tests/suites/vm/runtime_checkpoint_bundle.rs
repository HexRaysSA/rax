//! Public represented-state runtime restore without replaying guest work.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::devices::bus::IoDevice;
use rax::vm::memory::vm::{Bytes, GuestAddress, GuestMemoryMmap};
use rax::vm::runtime::{
    Vmm,
    pci_state::{PciDeviceCheckpoint, PciDevices},
};
use rax::vm::snapshot::{PhysicalMemorySnapshot, Snapshot, SnapshotBundle};
use rax::vm::vcpu::state::CpuState;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
const RAM: usize = 4096;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rax-runtime-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, [0; 64]).unwrap();
        Self(p)
    }
    fn config(&self, arch: ArchKind, pci: bool) -> VmConfig {
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(arch),
                backend: Some(BackendKind::Emulator),
                kernel: Some(self.0.clone()),
                pci_devices: pci,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(RAM as u64);
        c
    }
    fn vm(&self, arch: ArchKind, pci: bool) -> Vmm {
        Vmm::new_resume(self.config(arch, pci)).unwrap()
    }
    fn base(&self, pci: bool) -> Snapshot {
        let vm = self.vm(ArchKind::X86_64, pci);
        vm.guest_mem().write_all(&vec![0x33; RAM]).unwrap();
        let mut b = vm.take_snapshot(53).unwrap();
        let CpuState::X86_64(cpu) = &mut b.cpu_state else {
            unreachable!()
        };
        cpu.regs.rax = 0x12345678;
        b.devices.pic.set_irq(3, true);
        b.devices.serial.write(0x3f9, 0x0f);
        b
    }
    fn pci(&self, enabled: bool) -> PciDeviceCheckpoint {
        let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
        let mut cp = PciDevices::new(m, &Default::default(), enabled)
            .unwrap()
            .checkpoint()
            .unwrap();
        cp.bridge.state[8..12].copy_from_slice(&0x80000010u32.to_le_bytes());
        cp
    }
    fn bundle(&self, enabled: bool) -> SnapshotBundle {
        SnapshotBundle::new(self.base(enabled))
            .with_pci(self.pci(enabled))
            .unwrap()
    }
    fn target(&self, enabled: bool) -> Vmm {
        let vm = self.vm(ArchKind::X86_64, enabled);
        vm.guest_mem().write_all(&vec![0xa5; RAM]).unwrap();
        vm.guest_mem()
            .memory()
            .write_slice(&[0x6d], GuestAddress(RAM as u64 + 3))
            .unwrap();
        vm
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
fn marker(vm: &Vmm) -> u64 {
    let b = vm.take_snapshot(0).unwrap();
    let CpuState::X86_64(cpu) = b.cpu_state else {
        unreachable!()
    };
    cpu.regs.rax
}
fn unchanged(vm: &Vmm) {
    assert_eq!(marker(vm), 0);
    assert_eq!(vm.guest_mem().try_read_all().unwrap(), vec![0xa5; RAM]);
    let mut b = [0];
    vm.guest_mem()
        .memory()
        .read_slice(&mut b, GuestAddress(RAM as u64 + 3))
        .unwrap();
    assert_eq!(b, [0x6d]);
}
#[test]
fn pci_bundle_restores_cpu_legacy_devices_and_reported_ram() {
    for enabled in [false, true] {
        let f = Fixture::new();
        let b = f.bundle(enabled);
        let mut target = f.target(enabled);
        target.restore_snapshot_bundle(&b).unwrap();
        assert_eq!(marker(&target), 0x12345678);
        assert_eq!(target.guest_mem().try_read_all().unwrap(), vec![0x33; RAM]);
        let after = target.take_snapshot(0).unwrap();
        assert_eq!(
            bincode::serialize(&after.devices).unwrap(),
            bincode::serialize(&b.base().devices).unwrap()
        );
        assert_eq!(
            bincode::serialize(&after.emulator_state).unwrap(),
            bincode::serialize(&b.base().emulator_state).unwrap()
        );
    }
}
#[test]
fn old_base_bundle_uses_existing_restore_contract() {
    let f = Fixture::new();
    let b = SnapshotBundle::new(f.base(false));
    let mut target = f.target(false);
    target.restore_snapshot_bundle(&b).unwrap();
    assert_eq!(marker(&target), 0x12345678);
    let mut b = [0];
    target
        .guest_mem()
        .memory()
        .read_slice(&mut b, GuestAddress(RAM as u64 + 3))
        .unwrap();
    assert_eq!(b, [0x6d]);
}
#[test]
fn invalid_private_cpu_state_precedes_ram_and_pci_mutation() {
    let f = Fixture::new();
    let mut base = f.base(false);
    base.emulator_state.mxcsr = 0x80000000;
    let b = SnapshotBundle::new(base).with_pci(f.pci(false)).unwrap();
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn mismatched_cpu_count_precedes_mutation() {
    let f = Fixture::new();
    let mut base = f.base(false);
    base.config.vcpus = 2;
    let b = SnapshotBundle::new(base).with_pci(f.pci(false)).unwrap();
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn mismatched_ram_geometry_precedes_mutation() {
    let f = Fixture::new();
    let mut base = f.base(false);
    base.config.memory_bytes = 8192;
    base.memory_size = 8192;
    let b = SnapshotBundle::new(base).with_pci(f.pci(false)).unwrap();
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn mismatched_pci_profile_precedes_mutation() {
    let f = Fixture::new();
    let b = f.bundle(true);
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn bad_ram_frame_precedes_cpu_and_pci_mutation() {
    let f = Fixture::new();
    let mut base = f.base(false);
    base.memory_data = vec![0xff];
    let b = SnapshotBundle::new(base).with_pci(f.pci(false)).unwrap();
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn invalid_bridge_candidate_precedes_cpu_and_ram_mutation() {
    let f = Fixture::new();
    let mut cp = f.pci(false);
    cp.bridge.state[21] = 31;
    let b = SnapshotBundle::new(f.base(false)).with_pci(cp).unwrap();
    let mut t = f.target(false);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn late_invalid_endpoint_candidate_precedes_cpu_and_ram_mutation() {
    let f = Fixture::new();
    let mut cp = f.pci(true);
    cp.endpoints.as_mut().unwrap().ac97.state[264] = 1;
    let b = SnapshotBundle::new(f.base(true)).with_pci(cp).unwrap();
    let mut t = f.target(true);
    assert!(t.restore_snapshot_bundle(&b).is_err());
    unchanged(&t);
}
#[test]
fn absent_required_runtime_pci_component_precedes_physical_layout_check() {
    let f = Fixture::new();
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap();
    memory
        .write_slice(&vec![0x33; RAM], GuestAddress(0))
        .unwrap();
    let b = SnapshotBundle::new(f.base(false))
        .with_physical_memory(PhysicalMemorySnapshot::capture(&memory).unwrap())
        .unwrap();
    let mut t = f.target(false);
    assert!(
        t.restore_snapshot_bundle(&b)
            .unwrap_err()
            .to_string()
            .contains("PCI component")
    );
    unchanged(&t);
}
#[test]
fn wrong_physical_layout_precedes_cpu_and_pci_mutation() {
    let f = Fixture::new();
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap();
    memory
        .write_slice(&vec![0x33; RAM], GuestAddress(0))
        .unwrap();
    let b = f
        .bundle(false)
        .with_physical_memory(PhysicalMemorySnapshot::capture(&memory).unwrap())
        .unwrap();
    let mut t = f.target(false);
    assert!(
        t.restore_snapshot_bundle(&b)
            .unwrap_err()
            .to_string()
            .contains("physical layout")
    );
    unchanged(&t);
}
fn full_case(arch: ArchKind, address: u64, elf: bool) {
    let f = Fixture::new();
    let source = if elf {
        std::fs::write(
            &f.0,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/checkpoint/high-riscv.elf"
            )),
        )
        .unwrap();
        Vmm::new(f.config(arch, false)).unwrap()
    } else {
        f.vm(arch, false)
    };
    if !elf {
        source
            .guest_mem()
            .memory()
            .write_slice(&[0xab], GuestAddress(address))
            .unwrap();
    }
    let bundle = source.take_snapshot_bundle(53).unwrap();
    let mut target = f.vm(arch, false);
    target
        .guest_mem()
        .memory()
        .write_slice(&[0x6d], GuestAddress(address))
        .unwrap();
    target.restore_snapshot_bundle(&bundle).unwrap();
    let mut b = [0];
    target
        .guest_mem()
        .memory()
        .read_slice(&mut b, GuestAddress(address))
        .unwrap();
    assert_eq!(b, [0xab]);
}
#[test]
fn coordinated_x86_padding_restore_survives_full_bundle() {
    full_case(ArchKind::X86_64, RAM as u64 + 3, false);
}
#[test]
fn coordinated_aarch64_offset_ram_survives_full_bundle() {
    full_case(ArchKind::Aarch64, 0x40000003, false);
}
#[test]
fn coordinated_actual_riscv_elf_segment_survives_full_bundle() {
    full_case(ArchKind::Riscv64, 0x80000004, true);
}
/// No guest instructions. Retain raw CPU marker/RAM bytes for independent checks.
pub fn emit_reference(directory: &std::path::Path) {
    for (index, enabled) in [false, true].into_iter().enumerate() {
        let f = Fixture::new();
        let b = f.bundle(enabled);
        let mut target = f.target(enabled);
        target.restore_snapshot_bundle(&b).unwrap();
        std::fs::write(
            directory.join(format!("case-{index}.ram")),
            target.guest_mem().try_read_all().unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join(format!("case-{index}.cpu")),
            marker(&target).to_le_bytes(),
        )
        .unwrap();
        let mut pad = [0];
        target
            .guest_mem()
            .memory()
            .read_slice(&mut pad, GuestAddress(RAM as u64 + 3))
            .unwrap();
        std::fs::write(directory.join(format!("case-{index}.padding")), pad).unwrap();
        println!("{index}\t1");
    }
    for index in 2..6 {
        let f = Fixture::new();
        let mut base = f.base(false);
        let mut cp = f.pci(false);
        match index {
            2 => base.emulator_state.mxcsr = 0x80000000,
            3 => base.memory_data = vec![0xff],
            4 => cp.bridge.state[21] = 31,
            5 => base.config.vcpus = 2,
            _ => unreachable!(),
        };
        let b = SnapshotBundle::new(base).with_pci(cp).unwrap();
        let mut t = f.target(false);
        let accepted = t.restore_snapshot_bundle(&b).is_ok();
        std::fs::write(
            directory.join(format!("case-{index}.ram")),
            t.guest_mem().try_read_all().unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join(format!("case-{index}.cpu")),
            marker(&t).to_le_bytes(),
        )
        .unwrap();
        let mut pad = [0];
        t.guest_mem()
            .memory()
            .read_slice(&mut pad, GuestAddress(RAM as u64 + 3))
            .unwrap();
        std::fs::write(directory.join(format!("case-{index}.padding")), pad).unwrap();
        println!("{index}\t{}", u8::from(accepted));
    }
}
