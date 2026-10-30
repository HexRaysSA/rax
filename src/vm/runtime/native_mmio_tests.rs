//! Hardware MMIO exits must reach the same PCI models as software accesses.
use super::*;
use crate::config::{CliConfig, MemorySize};

fn fixture() -> Vmm {
    let mut config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            // Resume skips loading; configuration still requires an existing file.
            kernel: Some(std::env::current_exe().unwrap()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    config.memory = MemorySize(65536);
    config.pci_devices = true;
    Vmm::new_resume(config).unwrap()
}

#[test]
fn native_exit_bus_reaches_the_runtime_pci_endpoint() {
    let mut vm = fixture();
    let bridge = vm.pci_devices.as_ref().unwrap().bridge();
    let mut expected = [0; 4];
    assert!(
        bridge
            .lock()
            .unwrap()
            .mmio_read(PCI_MMIO_AP_BASE + 8, &mut expected)
    );
    assert_ne!(expected, [0xff; 4]);
    let mut actual = [0; 4];
    vm.mmio_bus.read(PCI_MMIO_AP_BASE + 8, &mut actual).unwrap();
    assert_eq!(
        actual, expected,
        "native MMIO exit must reach the attached e1000"
    );
}

#[test]
fn full_bundle_restore_rebinds_native_exit_routing_to_the_restored_bar() {
    let mut vm = fixture();
    let mut expected = [0; 4];
    vm.mmio_bus
        .read(PCI_MMIO_AP_BASE + 8, &mut expected)
        .unwrap();
    assert_ne!(expected, [0xff; 4]);
    let bundle = vm.take_snapshot_bundle(0).unwrap();
    vm.io_bus
        .write(0xcf8, &0x8000_0810u32.to_le_bytes())
        .unwrap();
    vm.io_bus
        .write(0xcfc, &0x0200_0000u32.to_le_bytes())
        .unwrap();
    let mut observed = [0; 4];
    vm.mmio_bus
        .read(PCI_MMIO_AP_BASE + 8, &mut observed)
        .unwrap();
    assert_eq!(observed, [0xff; 4]);
    vm.mmio_bus.read(0x0200_0008, &mut observed).unwrap();
    assert_eq!(observed, expected);
    vm.restore_snapshot_bundle(&bundle).unwrap();
    vm.mmio_bus
        .read(PCI_MMIO_AP_BASE + 8, &mut observed)
        .unwrap();
    assert_eq!(observed, expected);
    vm.mmio_bus.read(0x0200_0008, &mut observed).unwrap();
    assert_eq!(observed, [0xff; 4]);
}
