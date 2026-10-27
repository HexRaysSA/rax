//! Live represented components are observed directly across bundle admission.
use super::*;
use crate::config::{CliConfig, ImageAccess, MemorySize};
use crate::vm::runtime::pci_state::PciDeviceCheckpoint;
use crate::vm::snapshot::SnapshotBundle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    vm: Vmm,
}
impl Fixture {
    fn new(enabled: bool, images: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rax-bundle-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let kernel = dir.join("kernel");
        std::fs::write(&kernel, [0; 64]).unwrap();
        let n = dir.join("n.raw");
        let a = dir.join("a.raw");
        std::fs::write(&n, vec![0xa3; 8192]).unwrap();
        std::fs::write(&a, vec![0xb9; 8192]).unwrap();
        let mut c = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                kernel: Some(kernel),
                pci_devices: enabled,
                nvme_image: images.then_some(n),
                nvme_image_mode: images.then_some(ImageAccess::CopyOnWrite),
                ahci_image: images.then_some(a),
                ahci_image_mode: images.then_some(ImageAccess::ReadOnly),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        c.memory = MemorySize(4096);
        let vm = Vmm::new_resume(c).unwrap();
        vm.guest_mem.write_all(&[0xa5; 4096]).unwrap();
        Self { dir, vm }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn devices(vm: &Vmm) -> DeviceState {
    DeviceState {
        pic: vm.pic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        pit: vm.pit.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        serial: vm.serial.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        lapic: vm.lapic.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    cpu: Vec<u8>,
    private: Vec<u8>,
    legacy: Vec<u8>,
    pci: PciDeviceCheckpoint,
    ram: Vec<u8>,
}
fn state(vm: &Vmm) -> State {
    State {
        cpu: crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap(),
        private: crate::codec::serialize(&vm.vcpus[0].get_emulator_state()).unwrap(),
        legacy: crate::codec::serialize(&devices(vm)).unwrap(),
        pci: vm.pci_devices.as_ref().unwrap().checkpoint().unwrap(),
        ram: vm.guest_mem.try_read_all().unwrap(),
    }
}
fn pending(vm: &Vmm) -> SnapshotBundle {
    let mut cpu = vm.vcpus[0].get_state().unwrap();
    let CpuState::X86_64(x) = &mut cpu else {
        unreachable!()
    };
    x.regs.rax = 0x12345678;
    let mut private = vm.vcpus[0].get_emulator_state().unwrap();
    private.pkru = 0x1234;
    let mut d = devices(vm);
    d.pic.set_irq(3, true);
    d.serial.write(0x3f9, 0x0f);
    let base = Snapshot::new(
        vm.checkpoint_config.clone(),
        53,
        97,
        cpu,
        private,
        d,
        &[0x33; 4096],
    )
    .unwrap();
    let mut cp = vm.pci_devices.as_ref().unwrap().checkpoint().unwrap();
    cp.bridge.state[8..12].copy_from_slice(&0x80000010u32.to_le_bytes());
    if let Some(e) = &mut cp.endpoints {
        e.nvme.state[33..37].copy_from_slice(&0x10u32.to_le_bytes());
        e.ac97.state[12..14].copy_from_slice(&0x16u16.to_le_bytes());
    }
    SnapshotBundle::new(base).with_pci(cp).unwrap()
}
fn poison<T: Send + 'static>(m: Arc<std::sync::Mutex<T>>) {
    assert!(
        std::thread::spawn(move || {
            let _guard = m.lock().unwrap();
            panic!("owned live bundle lock fixture");
        })
        .join()
        .is_err()
    );
}
#[test]
fn poisoned_legacy_locks_preserve_cpu_private_ram_devices_and_pci() {
    for which in 0..4 {
        let mut f = Fixture::new(false, false);
        let before = state(&f.vm);
        let b = pending(&f.vm);
        match which {
            0 => poison(f.vm.pic.clone()),
            1 => poison(f.vm.pit.clone()),
            2 => poison(f.vm.serial.clone()),
            3 => poison(f.vm.lapic.clone()),
            _ => unreachable!(),
        };
        assert!(f.vm.restore_snapshot_bundle(&b).is_err());
        assert_eq!(state(&f.vm), before);
    }
}
#[test]
fn successful_bundle_publishes_exact_cpu_private_ram_legacy_and_pci() {
    for enabled in [false, true] {
        let mut f = Fixture::new(enabled, false);
        let b = pending(&f.vm);
        let expected = State {
            cpu: crate::codec::serialize(&b.base().cpu_state).unwrap(),
            private: crate::codec::serialize(&Some(b.base().emulator_state.clone())).unwrap(),
            legacy: crate::codec::serialize(&b.base().devices).unwrap(),
            pci: b.pci().unwrap().to_devices().unwrap(),
            ram: vec![0x33; 4096],
        };
        assert_eq!(
            b.pci().unwrap().to_devices().unwrap(),
            b.pci().unwrap().clone().into_devices().unwrap()
        );
        f.vm.restore_snapshot_bundle(&b).unwrap();
        assert_eq!(state(&f.vm), expected);
    }
}
#[test]
fn image_media_restore_is_detached_and_does_not_reopen_or_write_missing_sources() {
    let mut f = Fixture::new(true, true);
    let mut cp = pending(&f.vm).pci().unwrap().to_devices().unwrap();
    for (i, b) in cp
        .endpoints
        .as_mut()
        .unwrap()
        .nvme
        .media
        .bytes
        .iter_mut()
        .enumerate()
    {
        *b = (i as u8).wrapping_mul(17) ^ 0x5a;
    }
    let prior = pending(&f.vm);
    let base = Snapshot::new(
        prior.base().config.clone(),
        53,
        97,
        prior.base().cpu_state.clone(),
        prior.base().emulator_state.clone(),
        prior.base().devices.clone(),
        &[0x33; 4096],
    )
    .unwrap();
    let b = SnapshotBundle::new(base).with_pci(cp.clone()).unwrap();
    std::fs::rename(f.dir.join("n.raw"), f.dir.join("n.moved")).unwrap();
    std::fs::rename(f.dir.join("a.raw"), f.dir.join("a.moved")).unwrap();
    f.vm.restore_snapshot_bundle(&b).unwrap();
    assert_eq!(f.vm.pci_devices.as_ref().unwrap().checkpoint().unwrap(), cp);
    assert_eq!(f.vm.guest_mem.try_read_all().unwrap(), vec![0x33; 4096]);
    assert_eq!(
        std::fs::read(f.dir.join("n.moved")).unwrap(),
        vec![0xa3; 8192]
    );
    assert_eq!(
        std::fs::read(f.dir.join("a.moved")).unwrap(),
        vec![0xb9; 8192]
    );
    assert!(cp.endpoints.unwrap().ahci.media.read_only);
}
