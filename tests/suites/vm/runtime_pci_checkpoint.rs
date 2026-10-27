//! Actual runtime PCI registrations, coherent guest DMA and atomic state import.
use rax::config::{ImageAccess, ImageAttachment, StorageConfig};
use rax::devices::{ahci, bus::IoDevice, nvme, pci::PciStub};
use rax::vm::memory::vm::{Bytes, GuestAddress, GuestMemoryMmap};
use rax::vm::runtime::pci_state::{PciDeviceCheckpoint, PciDevices};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
const BASE: u64 = 0xfc000000;
const N: u64 = BASE + 0x100000;
const A: u64 = BASE + 0x200000;
const RAM: usize = 0x20000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Images {
    directory: PathBuf,
    n: PathBuf,
    a: PathBuf,
}
impl Images {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-runtime-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let n = directory.join("n.raw");
        let a = directory.join("a.raw");
        std::fs::write(&n, vec![0xa3; 16384]).unwrap();
        std::fs::write(&a, vec![0xb9; 16384]).unwrap();
        Self { directory, n, a }
    }
    fn config(&self, mode: ImageAccess) -> StorageConfig {
        StorageConfig {
            nvme: Some(ImageAttachment::capture(&self.n, mode, 16384).unwrap()),
            ahci: Some(ImageAttachment::capture(&self.a, mode, 16384).unwrap()),
        }
    }
}
impl Drop for Images {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn fresh(storage: &StorageConfig, enabled: bool) -> (PciDevices, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
    let devices = PciDevices::new(mem.clone(), storage, enabled).unwrap();
    (devices, mem)
}
fn put(b: &Arc<Mutex<PciStub>>, address: u64, value: u32) {
    assert!(b.lock().unwrap().mmio_write(address, &value.to_le_bytes()));
}
fn get(b: &Arc<Mutex<PciStub>>, address: u64) -> u32 {
    let mut data = [0; 4];
    assert!(b.lock().unwrap().mmio_read(address, &mut data));
    u32::from_le_bytes(data)
}
fn memory(mem: &GuestMemoryMmap) -> Vec<u8> {
    let mut data = vec![0; RAM];
    mem.read_slice(&mut data, GuestAddress(0)).unwrap();
    data
}
fn config(b: &Arc<Mutex<PciStub>>, device: u32, reg: u32, value: u32) {
    let mut p = b.lock().unwrap();
    for (i, byte) in (0x80000000 | (device << 11) | reg)
        .to_le_bytes()
        .into_iter()
        .enumerate()
    {
        p.write(0xcf8 + i as u16, byte);
    }
    for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
        p.write(0xcfc + i as u16, byte);
    }
}
fn nvme_setup(b: &Arc<Mutex<PciStub>>, m: &GuestMemoryMmap, cq: u32) {
    for (r, v) in [
        (nvme::REG_AQA, 0x00070007),
        (nvme::REG_ASQ, 0x1000),
        (nvme::REG_ACQ, 0x2000),
        (nvme::REG_CC, 0x00460001),
    ] {
        put(b, N + r, v);
    }
    for (slot, op, buffer, size, flags) in
        [(0u32, 5u8, 0x4000u64, cq, 3u32), (1, 1, 0x3000, 8, 0x10001)]
    {
        let mut c = [0; 64];
        c[0] = op;
        c[24..32].copy_from_slice(&buffer.to_le_bytes());
        c[40..44].copy_from_slice(&(((size - 1) << 16) | 1).to_le_bytes());
        c[44..48].copy_from_slice(&flags.to_le_bytes());
        m.write_slice(&c, GuestAddress(0x1000 + u64::from(slot) * 64))
            .unwrap();
        put(b, N + 0x1000, slot + 1);
    }
}
fn nvme_submit(
    b: &Arc<Mutex<PciStub>>,
    m: &GuestMemoryMmap,
    slot: u32,
    op: u8,
    lba: u32,
    buffer: u64,
) {
    let mut c = [0; 64];
    c[0] = op;
    c[2..4].copy_from_slice(&((slot + 1) as u16).to_le_bytes());
    c[4..8].copy_from_slice(&1u32.to_le_bytes());
    c[24..32].copy_from_slice(&buffer.to_le_bytes());
    c[40..44].copy_from_slice(&lba.to_le_bytes());
    m.write_slice(&c, GuestAddress(0x3000 + u64::from(slot) * 64))
        .unwrap();
    put(b, N + 0x1008, slot + 1);
}
fn ahci_issue(b: &Arc<Mutex<PciStub>>, m: &GuestMemoryMmap, op: u8) {
    for (r, v) in [
        (ahci::REG_GHC, 0x80000002),
        (ahci::PORT_BASE + ahci::PX_CLB, 0xa000),
        (ahci::PORT_BASE + ahci::PX_FB, 0xb000),
        (ahci::PORT_BASE + ahci::PX_IE, u32::MAX),
        (ahci::PORT_BASE + ahci::PX_CMD, 0x11),
    ] {
        put(b, A + r, v);
    }
    let mut h = [0; 32];
    h[..4].copy_from_slice(&(0x00010005u32 | if op == 0x35 { 64 } else { 0 }).to_le_bytes());
    h[8..16].copy_from_slice(&0xc000u64.to_le_bytes());
    m.write_slice(&h, GuestAddress(0xa000)).unwrap();
    let mut fis = [0; 20];
    fis[0] = 0x27;
    fis[1] = 0x80;
    fis[2] = op;
    fis[7] = 0x40;
    fis[12] = 1;
    m.write_slice(&fis, GuestAddress(0xc000)).unwrap();
    let mut prd = [0; 16];
    prd[..8].copy_from_slice(&0xf000u64.to_le_bytes());
    prd[12..16].copy_from_slice(&0x800001ffu32.to_le_bytes());
    m.write_slice(&prd, GuestAddress(0xc080)).unwrap();
    put(b, A + ahci::PORT_BASE + ahci::PX_CI, 1);
}
fn changed(d: &PciDevices) {
    let b = d.bridge();
    put(&b, BASE + 0xd0, 4);
    put(&b, BASE + 0xc8, 4);
    put(&b, N + nvme::REG_INTMS, 0x42);
    put(&b, A + ahci::REG_GHC, 0x80000002);
    let mut p = b.lock().unwrap();
    p.io_write(0xc00c, 0xff);
    p.io_write(0xc000, 1);
    p.io_write(0xd002, 0x12);
    p.io_write(0xd003, 0x34);
}
#[test]
fn bridge_only_latch_and_config_survive() {
    let (d, _) = fresh(&StorageConfig::default(), false);
    let b = d.bridge();
    b.lock().unwrap().write(0xcf8, 0xa5);
    let c = d.checkpoint().unwrap();
    assert!(c.endpoints.is_none());
    let (q, _) = fresh(&StorageConfig::default(), false);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    assert_eq!(q.bridge().lock().unwrap().read(0xcf8), 0xa5);
}
#[test]
fn all_registered_endpoint_changes_are_captured_and_restored() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    changed(&d);
    let c = d.checkpoint().unwrap();
    let (q, _) = fresh(&StorageConfig::default(), true);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    assert_eq!(get(&q.bridge(), BASE + 0xd0), 4);
    assert_eq!(get(&q.bridge(), N + nvme::REG_INTMS), 0x42);
    let b = q.bridge();
    assert_eq!(b.lock().unwrap().io_read(0xc00c), Some(0xff));
    assert_eq!(b.lock().unwrap().io_read(0xd002), Some(0x12));
    assert_eq!(b.lock().unwrap().io_read(0xd003), Some(0x34));
}
#[test]
fn cow_media_restores_and_actual_dma_reads_restored_bytes() {
    let images = Images::new();
    let (d, m) = fresh(&images.config(ImageAccess::CopyOnWrite), true);
    let b = d.bridge();
    m.write_slice(&[0x27; 512], GuestAddress(0x8000)).unwrap();
    nvme_setup(&b, &m, 8);
    nvme_submit(&b, &m, 0, 1, 0, 0x8000);
    m.write_slice(&[0x39; 512], GuestAddress(0xf000)).unwrap();
    ahci_issue(&b, &m, 0x35);
    let c = d.checkpoint().unwrap();
    assert_eq!(
        &c.endpoints.as_ref().unwrap().nvme.media.bytes[..512],
        &[0x27; 512]
    );
    assert_eq!(
        &c.endpoints.as_ref().unwrap().ahci.media.bytes[..512],
        &[0x39; 512]
    );
    let (q, qm) = fresh(&StorageConfig::default(), true);
    qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    nvme_submit(&q.bridge(), &qm, 1, 2, 0, 0x9000);
    let mut data = [0; 512];
    qm.read_slice(&mut data, GuestAddress(0x9000)).unwrap();
    assert_eq!(data, [0x27; 512]);
    ahci_issue(&q.bridge(), &qm, 0x25);
    qm.read_slice(&mut data, GuestAddress(0xf000)).unwrap();
    assert_eq!(data, [0x39; 512]);
    assert_eq!(std::fs::read(&images.n).unwrap(), vec![0xa3; 16384]);
    assert_eq!(std::fs::read(&images.a).unwrap(), vec![0xb9; 16384]);
}
#[test]
fn every_corrupt_component_leaves_all_live_state_and_ram_unchanged() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    changed(&d);
    let c = d.checkpoint().unwrap();
    let (q, m) = fresh(&StorageConfig::default(), true);
    m.write_slice(&[0xa5; 512], GuestAddress(0x5000)).unwrap();
    let before = q.checkpoint().unwrap();
    let ram = memory(&m);
    for index in 0..7 {
        let mut bad = c.clone();
        match index {
            0 => bad.bridge.state.push(0),
            1 => bad.endpoints.as_mut().unwrap().e1000.state.push(0),
            2 => bad.endpoints.as_mut().unwrap().uhci.state.push(0),
            3 => bad.endpoints.as_mut().unwrap().nvme.state.push(0),
            4 => bad.endpoints.as_mut().unwrap().ahci.state.push(0),
            5 => bad.endpoints.as_mut().unwrap().ac97.state.push(0),
            6 => bad.endpoints.as_mut().unwrap().nvme.media.bytes.push(0),
            _ => unreachable!(),
        }
        assert!(q.restore_checkpoint(bad).is_err());
        assert_eq!(q.checkpoint().unwrap(), before);
        assert_eq!(memory(&m), ram);
    }
}
#[test]
fn optional_topology_mismatch_is_atomic_in_both_directions() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    let (q, _) = fresh(&StorageConfig::default(), false);
    let yes = d.checkpoint().unwrap();
    let no = q.checkpoint().unwrap();
    assert!(d.restore_checkpoint(no.clone()).is_err());
    assert!(q.restore_checkpoint(yes.clone()).is_err());
    assert_eq!(d.checkpoint().unwrap(), yes);
    assert_eq!(q.checkpoint().unwrap(), no);
}
#[test]
fn pending_cq_backpressure_restores_without_dma_or_completed_write_replay() {
    let images = Images::new();
    let (d, m) = fresh(&images.config(ImageAccess::CopyOnWrite), true);
    let b = d.bridge();
    nvme_setup(&b, &m, 2);
    m.write_slice(&[0x11; 512], GuestAddress(0x8000)).unwrap();
    nvme_submit(&b, &m, 0, 1, 0, 0x8000);
    m.write_slice(&[0x22; 512], GuestAddress(0x9000)).unwrap();
    nvme_submit(&b, &m, 1, 1, 1, 0x9000);
    let c = d.checkpoint().unwrap();
    assert_eq!(
        &c.endpoints.as_ref().unwrap().nvme.media.bytes[512..1024],
        &[0xa3; 512]
    );
    let (q, qm) = fresh(&StorageConfig::default(), true);
    qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
    qm.write_slice(&[0x99; 512], GuestAddress(0x8000)).unwrap();
    let ram = memory(&qm);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(memory(&qm), ram);
    assert_eq!(q.checkpoint().unwrap(), c);
    put(&q.bridge(), N + 0x100c, 1);
    let after = q.checkpoint().unwrap();
    let media = &after.endpoints.unwrap().nvme.media.bytes;
    assert_eq!(&media[..512], &[0x11; 512]);
    assert_eq!(&media[512..1024], &[0x22; 512]);
}
#[test]
fn ahci_fatal_slot_and_interrupts_survive_without_implicit_retry() {
    let images = Images::new();
    let (d, m) = fresh(&images.config(ImageAccess::CopyOnWrite), true);
    ahci_issue(&d.bridge(), &m, 255);
    let c = d.checkpoint().unwrap();
    assert_eq!(get(&d.bridge(), A + ahci::PORT_BASE + ahci::PX_CI), 1);
    let (q, qm) = fresh(&StorageConfig::default(), true);
    qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    put(&q.bridge(), A + ahci::PORT_BASE + ahci::PX_CI, 2);
    assert_eq!(get(&q.bridge(), A + ahci::PORT_BASE + ahci::PX_CI), 3);
    assert_eq!(
        q.checkpoint().unwrap().endpoints.unwrap().ahci.media.bytes,
        vec![0xb9; 16384]
    );
}
#[test]
fn persistent_media_become_detached_and_never_reopen_sources() {
    let images = Images::new();
    let (d, m) = fresh(&images.config(ImageAccess::ReadWrite), true);
    nvme_setup(&d.bridge(), &m, 8);
    m.write_slice(&[0x31; 512], GuestAddress(0x8000)).unwrap();
    nvme_submit(&d.bridge(), &m, 0, 1, 0, 0x8000);
    let c = d.checkpoint().unwrap();
    let (q, qm) = fresh(&StorageConfig::default(), true);
    qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
    q.restore_checkpoint(c).unwrap();
    let host = std::fs::read(&images.n).unwrap();
    std::fs::rename(&images.n, images.directory.join("source-moved.raw")).unwrap();
    m.write_slice(&[0x88; 512], GuestAddress(0x8000)).unwrap();
    qm.write_slice(&[0x42; 512], GuestAddress(0x9000)).unwrap();
    nvme_submit(&q.bridge(), &qm, 1, 1, 1, 0x9000);
    assert_eq!(
        &q.checkpoint().unwrap().endpoints.unwrap().nvme.media.bytes[512..1024],
        &[0x42; 512]
    );
    assert_eq!(
        std::fs::read(images.directory.join("source-moved.raw")).unwrap(),
        host
    );
    assert!(!images.n.exists());
}
#[test]
fn readonly_media_protection_survives_runtime_restore() {
    let images = Images::new();
    let (d, m) = fresh(&images.config(ImageAccess::ReadOnly), true);
    nvme_setup(&d.bridge(), &m, 8);
    let c = d.checkpoint().unwrap();
    let (q, qm) = fresh(&StorageConfig::default(), true);
    qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
    q.restore_checkpoint(c).unwrap();
    qm.write_slice(&[0x55; 512], GuestAddress(0x8000)).unwrap();
    nvme_submit(&q.bridge(), &qm, 0, 1, 0, 0x8000);
    let mut status = [0; 2];
    qm.read_slice(&mut status, GuestAddress(0x400e)).unwrap();
    assert_eq!(u16::from_le_bytes(status) >> 1, 0x20);
    ahci_issue(&q.bridge(), &qm, 0x35);
    assert_ne!(get(&q.bridge(), A + ahci::PORT_BASE + ahci::PX_TFD) & 1, 0);
    let c = q.checkpoint().unwrap();
    let e = c.endpoints.unwrap();
    assert!(e.nvme.media.read_only && e.ahci.media.read_only);
    assert_eq!(e.nvme.media.bytes, vec![0xa3; 16384]);
    assert_eq!(e.ahci.media.bytes, vec![0xb9; 16384]);
}
#[test]
fn untracked_registration_rejects_capture_and_restore() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    let c = d.checkpoint().unwrap();
    d.bridge()
        .lock()
        .unwrap()
        .add_function(0, 7, 0, rax::devices::pci::ConfigSpace::new());
    assert!(d.checkpoint().is_err());
    let before = d.bridge().lock().unwrap().checkpoint().unwrap();
    assert!(d.restore_checkpoint(c).is_err());
    assert_eq!(d.bridge().lock().unwrap().checkpoint().unwrap(), before);
}
#[test]
fn nonzero_bar_relative_origins_are_rejected_before_any_swap() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    changed(&d);
    let c = d.checkpoint().unwrap();
    let (q, _) = fresh(&StorageConfig::default(), true);
    let before = q.checkpoint().unwrap();
    for index in 0..3 {
        let mut bad = c.clone();
        let e = bad.endpoints.as_mut().unwrap();
        match index {
            0 => e.uhci.state[8..10].copy_from_slice(&1u16.to_le_bytes()),
            1 => e.nvme.state[8..16].copy_from_slice(&1u64.to_le_bytes()),
            2 => e.ahci.state[8..16].copy_from_slice(&1u64.to_le_bytes()),
            _ => unreachable!(),
        }
        assert!(q.restore_checkpoint(bad).is_err());
        assert_eq!(q.checkpoint().unwrap(), before);
    }
}
#[test]
fn bar_moves_and_shared_audio_windows_retain_actual_handlers() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    let b = d.bridge();
    config(&b, 3, 0x10, 0xe0000000);
    config(&b, 5, 0x10, 0xe001);
    config(&b, 5, 0x14, 0xe101);
    assert_eq!(get(&b, 0xe0000000 + nvme::REG_VS), 0x00010400);
    b.lock().unwrap().io_write(0xe002, 0x56);
    let c = d.checkpoint().unwrap();
    let (q, _) = fresh(&StorageConfig::default(), true);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    assert_eq!(get(&q.bridge(), 0xe0000000 + nvme::REG_VS), 0x00010400);
    assert_eq!(
        q.bridge().lock().unwrap().io_read(0xe002),
        Some(0x56 & 0x3f)
    );
    assert_eq!(q.bridge().lock().unwrap().io_read(0xe130), Some(0));
}
#[test]
fn correlated_bridge_updates_do_not_tear_during_capture() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    let b = d.bridge();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let start = barrier.clone();
    let worker = std::thread::spawn(move || {
        start.wait();
        for value in 0u32..4096 {
            let mut p = b.lock().unwrap();
            assert!(p.mmio_write(N + nvme::REG_INTMC, &u32::MAX.to_le_bytes()));
            assert!(p.mmio_write(N + nvme::REG_INTMS, &value.to_le_bytes()));
            assert!(p.mmio_write(A + ahci::PORT_BASE + ahci::PX_IE, &value.to_le_bytes()));
        }
    });
    barrier.wait();
    for _ in 0..128 {
        let c = d.checkpoint().unwrap().endpoints.unwrap();
        assert_eq!(&c.nvme.state[33..37], &c.ahci.state[58..62]);
    }
    worker.join().unwrap();
}
#[test]
fn poisoned_bridge_rejects_without_mutating_models() {
    let (d, _) = fresh(&StorageConfig::default(), true);
    let c = d.checkpoint().unwrap();
    let b = d.bridge();
    let other = b.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = other.lock().unwrap();
            panic!("owned poison fixture");
        })
        .join()
        .is_err()
    );
    assert!(d.checkpoint().is_err());
    assert!(d.restore_checkpoint(c.clone()).is_err());
    assert_eq!(
        b.lock().err().unwrap().into_inner().checkpoint().unwrap(),
        c.bridge
    );
}
#[test]
fn disabled_optional_endpoints_do_not_silently_ignore_images() {
    let images = Images::new();
    let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM)]).unwrap());
    assert!(PciDevices::new(m, &images.config(ImageAccess::CopyOnWrite), false).is_err());
}
fn publish_state(directory: &std::path::Path, prefix: &str, state: PciDeviceCheckpoint) {
    std::fs::write(
        directory.join(format!("{prefix}bridge.bin")),
        state.bridge.state,
    )
    .unwrap();
    if let Some(e) = state.endpoints {
        for (name, bytes) in [
            ("e1000.bin", e.e1000.state),
            ("uhci.bin", e.uhci.state),
            ("nvme.bin", e.nvme.state),
            ("ahci.bin", e.ahci.state),
            ("ac97.bin", e.ac97.state),
            ("nvme.raw", e.nvme.media.bytes),
            ("ahci.raw", e.ahci.media.bytes),
        ] {
            std::fs::write(directory.join(format!("{prefix}{name}")), bytes).unwrap();
        }
    }
}
/// Actual runtime bridge/controller/media captures; no guest CPU is executed.
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    for index in 0..5 {
        let images = Images::new();
        let storage = if index == 4 {
            images.config(ImageAccess::CopyOnWrite)
        } else {
            StorageConfig::default()
        };
        let (d, m) = fresh(&storage, index != 0);
        let b = d.bridge();
        match index {
            0 => b.lock().unwrap().write(0xcf8, 0xa5),
            2 => changed(&d),
            3 => {
                config(&b, 3, 0x10, 0xe0000000);
                config(&b, 5, 0x10, 0xe001);
                config(&b, 5, 0x14, 0xe101);
                b.lock().unwrap().io_write(0xe002, 0x56);
            }
            4 => {
                nvme_setup(&b, &m, 8);
                m.write_slice(&[0x27; 512], GuestAddress(0x8000)).unwrap();
                nvme_submit(&b, &m, 0, 1, 0, 0x8000);
                m.write_slice(&[0x39; 512], GuestAddress(0xf000)).unwrap();
                ahci_issue(&b, &m, 0x35);
            }
            _ => {}
        }
        let state = d.checkpoint().unwrap();
        let (q, qm) = fresh(&StorageConfig::default(), index != 0);
        qm.write_slice(&memory(&m), GuestAddress(0)).unwrap();
        q.restore_checkpoint(state.clone()).unwrap();
        assert_eq!(q.checkpoint().unwrap(), state);
        let case = directory.join(format!("case-{index}"));
        std::fs::create_dir_all(&case).unwrap();
        publish_state(&case, "", state);
        std::fs::write(case.join("ram.raw"), memory(&m)).unwrap();
        if index == 4 {
            put(&q.bridge(), N + 0x100c, 1);
            put(&q.bridge(), N + 0x1004, 2);
            put(&q.bridge(), A + ahci::PORT_BASE + ahci::PX_IS, u32::MAX);
            put(&q.bridge(), A + ahci::REG_IS, 1);
            std::fs::copy(&images.n, case.join("host-n.raw")).unwrap();
            std::fs::copy(&images.a, case.join("host-a.raw")).unwrap();
        }
        publish_state(&case, "continued-", q.checkpoint().unwrap());
        std::fs::write(case.join("continued-ram.raw"), memory(&qm)).unwrap();
    }
}
