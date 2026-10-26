//! Actual optional PCI attachments and guest-RAM DMA; no CPU/boot substitute.
use super::*;
use crate::config::{ImageAccess, ImageAttachment, StorageConfig};
use crate::devices::{ahci, nvme};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Images {
    directory: PathBuf,
    nvme: PathBuf,
    ahci: PathBuf,
}
impl Images {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-pci-images-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let nvme = directory.join("n.raw");
        let ahci = directory.join("a.raw");
        std::fs::write(&nvme, vec![0xa3; 16384]).unwrap();
        std::fs::write(&ahci, vec![0xb9; 16384]).unwrap();
        Self {
            directory,
            nvme,
            ahci,
        }
    }
    fn config(&self, mode: ImageAccess) -> StorageConfig {
        StorageConfig {
            nvme: Some(ImageAttachment::capture(&self.nvme, mode, 16384).unwrap()),
            ahci: Some(ImageAttachment::capture(&self.ahci, mode, 16384).unwrap()),
        }
    }
}
impl Drop for Images {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn put(bridge: &Arc<std::sync::Mutex<PciStub>>, address: u64, value: u32) {
    assert!(
        bridge
            .lock()
            .unwrap()
            .mmio_write(address, &value.to_le_bytes())
    );
}
fn nvme_io(bridge: &Arc<std::sync::Mutex<PciStub>>, mem: &GuestMemoryMmap, write: bool) {
    let base = PCI_MMIO_AP_BASE + 0x10_0000;
    for (r, v) in [
        (nvme::REG_AQA, 63u32 | (63 << 16)),
        (nvme::REG_ASQ, 0x1000),
        (nvme::REG_ACQ, 0x2000),
        (nvme::REG_CC, 0x00460001),
    ] {
        put(bridge, base + r, v);
    }
    for (slot, op, buffer, flags) in [(0u32, 5u8, 0x4000u64, 1u32), (1, 1, 0x3000, 0x10001)] {
        let mut c = [0; 64];
        c[0] = op;
        c[24..32].copy_from_slice(&buffer.to_le_bytes());
        c[40..44].copy_from_slice(&0x003f0001u32.to_le_bytes());
        c[44..48].copy_from_slice(&flags.to_le_bytes());
        mem.write_slice(&c, GuestAddress(0x1000 + u64::from(slot) * 64))
            .unwrap();
        put(bridge, base + 0x1000, slot + 1);
    }
    let mut c = [0; 64];
    c[0] = if write { 1 } else { 2 };
    c[4..8].copy_from_slice(&1u32.to_le_bytes());
    c[24..32].copy_from_slice(&0x8000u64.to_le_bytes());
    mem.write_slice(&c, GuestAddress(0x3000)).unwrap();
    put(bridge, base + 0x1008, 1);
    let mut status = [0; 2];
    mem.read_slice(&mut status, GuestAddress(0x400e)).unwrap();
    assert_eq!(
        u16::from_le_bytes(status) & 1,
        1,
        "actual CQ phase must be published"
    );
    assert_eq!(u16::from_le_bytes(status) >> 1, 0);
}
fn ahci_io(bridge: &Arc<std::sync::Mutex<PciStub>>, mem: &GuestMemoryMmap, write: bool) {
    let base = PCI_MMIO_AP_BASE + 0x20_0000;
    for (r, v) in [
        (ahci::REG_GHC, 0x80000002u32),
        (ahci::PORT_BASE + ahci::PX_CLB, 0xa000),
        (ahci::PORT_BASE + ahci::PX_FB, 0xb000),
        (ahci::PORT_BASE + ahci::PX_CMD, 0x11),
    ] {
        put(bridge, base + r, v);
    }
    let mut h = [0; 32];
    h[..4].copy_from_slice(&(0x00010005u32 | if write { 1 << 6 } else { 0 }).to_le_bytes());
    h[8..16].copy_from_slice(&0xc000u64.to_le_bytes());
    mem.write_slice(&h, GuestAddress(0xa000)).unwrap();
    let mut fis = [0; 20];
    fis[0] = 0x27;
    fis[1] = 0x80;
    fis[2] = if write { 0x35 } else { 0x25 };
    fis[7] = 0x40;
    fis[12] = 1;
    mem.write_slice(&fis, GuestAddress(0xc000)).unwrap();
    let mut prd = [0; 16];
    prd[..8].copy_from_slice(&0xf000u64.to_le_bytes());
    prd[12..16].copy_from_slice(&511u32.to_le_bytes());
    mem.write_slice(&prd, GuestAddress(0xc080)).unwrap();
    put(bridge, base + ahci::PORT_BASE + ahci::PX_CI, 1);
    let mut ci = [0; 4];
    assert!(
        bridge
            .lock()
            .unwrap()
            .mmio_read(base + ahci::PORT_BASE + ahci::PX_CI, &mut ci)
    );
    assert_eq!(ci, [0; 4]);
}
#[test]
fn runtime_pci_attachments_dma_their_distinct_configured_image_bytes() {
    let images = Images::new();
    let storage = images.config(ImageAccess::CopyOnWrite);
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap());
    let bridge = Arc::new(std::sync::Mutex::new(PciStub::new()));
    attach_pci_devices(&bridge, mem.clone(), &storage).unwrap();
    nvme_io(&bridge, &mem, false);
    ahci_io(&bridge, &mem, false);
    let mut n = [0; 512];
    let mut a = [0; 512];
    mem.read_slice(&mut n, GuestAddress(0x8000)).unwrap();
    mem.read_slice(&mut a, GuestAddress(0xf000)).unwrap();
    assert_eq!(n, [0xa3; 512]);
    assert_eq!(a, [0xb9; 512]);
    assert_eq!(std::fs::read(&images.nvme).unwrap(), vec![0xa3; 16384]);
    assert_eq!(std::fs::read(&images.ahci).unwrap(), vec![0xb9; 16384]);
}
#[test]
fn runtime_pci_guest_writes_reach_the_selected_persistent_files() {
    let images = Images::new();
    let storage = images.config(ImageAccess::ReadWrite);
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap());
    let bridge = Arc::new(std::sync::Mutex::new(PciStub::new()));
    attach_pci_devices(&bridge, mem.clone(), &storage).unwrap();
    mem.write_slice(&[0x27; 512], GuestAddress(0x8000)).unwrap();
    mem.write_slice(&[0x39; 512], GuestAddress(0xf000)).unwrap();
    nvme_io(&bridge, &mem, true);
    ahci_io(&bridge, &mem, true);
    assert_eq!(&std::fs::read(&images.nvme).unwrap()[..512], &[0x27; 512]);
    assert_eq!(&std::fs::read(&images.ahci).unwrap()[..512], &[0x39; 512]);
}
#[test]
fn runtime_attachment_rejects_source_replacement_and_conflicting_image_alias() {
    let images = Images::new();
    let storage = images.config(ImageAccess::ReadWrite);
    std::fs::write(&images.nvme, vec![0x12; 16384]).unwrap();
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap());
    let bridge = Arc::new(std::sync::Mutex::new(PciStub::new()));
    assert!(
        attach_pci_devices(&bridge, mem.clone(), &storage)
            .unwrap_err()
            .to_string()
            .contains("identity changed")
    );
    drop(bridge);
    let mut storage = images.config(ImageAccess::ReadWrite);
    storage.ahci = storage.nvme.clone();
    let bridge = Arc::new(std::sync::Mutex::new(PciStub::new()));
    assert!(attach_pci_devices(&bridge, mem, &storage).is_err());
    drop(bridge);
    storage.nvme.unwrap().open().unwrap();
}
