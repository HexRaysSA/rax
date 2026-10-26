//! Public controller checkpoint APIs, complete private state and no replay.
use rax::devices::bus::MmioDevice;
use rax::devices::virtio::{
    Mem,
    block_image::{BlockImage, ImageCheckpoint, ImageMode},
};
use rax::devices::{ahci, nvme};
use std::sync::{Arc, Mutex};
const BASE: u64 = 0x1000_0000;
#[derive(Clone)]
struct Memory(Arc<Mutex<(Vec<u8>, Vec<(bool, u64, usize)>)>>);
impl Memory {
    fn new() -> Self {
        Self(Arc::new(Mutex::new((vec![0; 0x20000], vec![]))))
    }
    fn put(&self, a: u64, b: &[u8]) {
        self.0.lock().unwrap().0[a as usize..a as usize + b.len()].copy_from_slice(b);
    }
    fn get(&self, a: u64, n: usize) -> Vec<u8> {
        self.0.lock().unwrap().0[a as usize..a as usize + n].to_vec()
    }
    fn fork(&self) -> Self {
        Self(Arc::new(Mutex::new((
            self.0.lock().unwrap().0.clone(),
            vec![],
        ))))
    }
    fn clear(&self) {
        self.0.lock().unwrap().1.clear();
    }
    fn untouched(&self) {
        assert!(
            self.0.lock().unwrap().1.is_empty(),
            "checkpoint must not perform guest DMA"
        );
    }
}
impl Mem for Memory {
    fn read(&self, a: u64, b: &mut [u8]) -> bool {
        let mut s = self.0.lock().unwrap();
        s.1.push((false, a, b.len()));
        let Ok(a) = usize::try_from(a) else {
            return false;
        };
        let Some(end) = a.checked_add(b.len()).filter(|end| *end <= s.0.len()) else {
            return false;
        };
        b.copy_from_slice(&s.0[a..end]);
        true
    }
    fn write(&mut self, a: u64, b: &[u8]) -> bool {
        let mut s = self.0.lock().unwrap();
        s.1.push((true, a, b.len()));
        let Ok(a) = usize::try_from(a) else {
            return false;
        };
        let Some(end) = a.checked_add(b.len()).filter(|end| *end <= s.0.len()) else {
            return false;
        };
        s.0[a..end].copy_from_slice(b);
        true
    }
}
fn read(d: &mut impl MmioDevice, offset: u64) -> u32 {
    let mut v = [0; 4];
    d.read(BASE + offset, &mut v);
    u32::from_le_bytes(v)
}
fn write(d: &mut impl MmioDevice, offset: u64, v: u32) {
    d.write(BASE + offset, &v.to_le_bytes());
}
struct Nvm {
    device: nvme::NvmeController<Memory>,
    memory: Memory,
    admin: u32,
    io: u32,
    cq: u32,
}
impl Nvm {
    fn new(cq: u32) -> Self {
        Self::image(cq, BlockImage::from_bytes(vec![0xa3; 4096]))
    }
    fn image(cq: u32, image: BlockImage) -> Self {
        let memory = Memory::new();
        let mut h = Self {
            device: nvme::NvmeController::with_image(BASE, memory.clone(), image),
            memory,
            admin: 0,
            io: 0,
            cq,
        };
        for (r, v) in [
            (nvme::REG_AQA, 7u32 | (7 << 16)),
            (nvme::REG_ASQ, 0x1000),
            (nvme::REG_ACQ, 0x2000),
            (nvme::REG_CC, 0x00460001),
        ] {
            write(&mut h.device, r, v);
        }
        for (op, base, size, flags) in [(5, 0x4000, cq, 3u32), (1, 0x3000, 4, 0x10001)] {
            let mut c = Self::command(op, base, 0);
            c[40..44].copy_from_slice(&(1u32 | ((size - 1) << 16)).to_le_bytes());
            c[44..48].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(h.submit(true, c, true), 0);
        }
        h
    }
    fn command(op: u8, buffer: u64, lba: u64) -> [u8; 64] {
        let mut c = [0; 64];
        c[0] = op;
        c[4..8].copy_from_slice(&1u32.to_le_bytes());
        c[24..32].copy_from_slice(&buffer.to_le_bytes());
        c[40..48].copy_from_slice(&lba.to_le_bytes());
        c
    }
    fn submit(&mut self, admin: bool, mut c: [u8; 64], ack: bool) -> u16 {
        let slot = if admin { self.admin } else { self.io };
        let (sq, cq, bell, size) = if admin {
            (0x1000, 0x2000, 0x1000, 8)
        } else {
            (0x3000, 0x4000, 0x1008, 4)
        };
        c[2..4].copy_from_slice(&(0x100 + slot as u16).to_le_bytes());
        self.memory.put(sq + u64::from(slot) * 64, &c);
        let next = (slot + 1) % size;
        write(&mut self.device, bell, next);
        let cqslot = if admin { slot } else { slot % self.cq };
        let raw = self.memory.get(cq + u64::from(cqslot) * 16, 16);
        if ack {
            write(
                &mut self.device,
                bell + 4,
                (cqslot + 1) % if admin { 8 } else { self.cq },
            );
        }
        if admin {
            self.admin = next
        } else {
            self.io = next
        };
        u16::from_le_bytes(raw[14..16].try_into().unwrap()) >> 1
    }
    fn restored(&self) -> Self {
        self.memory.clear();
        let checkpoint = self.device.checkpoint().unwrap();
        self.memory.untouched();
        let memory = self.memory.fork();
        let mut device = nvme::NvmeController::new(0, memory.clone(), vec![]);
        device.restore_checkpoint(checkpoint).unwrap();
        memory.untouched();
        Self {
            device,
            memory,
            admin: self.admin,
            io: self.io,
            cq: self.cq,
        }
    }
}
struct Sata {
    device: ahci::AhciController<Memory>,
    memory: Memory,
}
impl Sata {
    fn new() -> Self {
        Self::image(BlockImage::from_bytes(vec![0xb9; 4096]))
    }
    fn image(image: BlockImage) -> Self {
        let memory = Memory::new();
        let mut device = ahci::AhciController::with_image(BASE, memory.clone(), image);
        for (r, v) in [
            (ahci::REG_GHC, 0x80000002u32),
            (ahci::PORT_BASE + ahci::PX_CLB, 0x1000),
            (ahci::PORT_BASE + ahci::PX_FB, 0x2000),
            (ahci::PORT_BASE + ahci::PX_IE, u32::MAX),
            (ahci::PORT_BASE + ahci::PX_CMD, 0x11),
        ] {
            write(&mut device, r, v);
        }
        Self { device, memory }
    }
    fn command(&self, slot: u32, op: u8, lba: u8) {
        let mut h = [0; 32];
        h[..4].copy_from_slice(&(0x10005u32 | if op == 0x35 { 1 << 6 } else { 0 }).to_le_bytes());
        h[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        self.memory.put(0x1000 + u64::from(slot) * 32, &h);
        let mut fis = [0; 20];
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = op;
        fis[4] = lba;
        fis[7] = 0x40;
        fis[12] = 1;
        self.memory.put(0x3000, &fis);
        let mut p = [0; 16];
        p[..8].copy_from_slice(&0x8000u64.to_le_bytes());
        p[12..16].copy_from_slice(&(511u32 | 1 << 31).to_le_bytes());
        self.memory.put(0x3080, &p);
    }
    fn issue(&mut self, slot: u32) {
        write(&mut self.device, ahci::PORT_BASE + ahci::PX_CI, 1 << slot);
    }
    fn restored(&self) -> Self {
        self.memory.clear();
        let checkpoint = self.device.checkpoint().unwrap();
        self.memory.untouched();
        let memory = self.memory.fork();
        let mut device = ahci::AhciController::new(0, memory.clone(), vec![]);
        device.restore_checkpoint(checkpoint).unwrap();
        memory.untouched();
        Self { device, memory }
    }
}
#[test]
fn nvme_control_wire_and_complete_media_roundtrip_without_dma() {
    let h = Nvm::new(4);
    let before = h.device.checkpoint().unwrap();
    assert_eq!(before.state.len(), 353);
    assert_eq!(before.media.bytes.len(), 4096);
    let restored = h.restored();
    assert_eq!(restored.device.checkpoint().unwrap(), before);
}
#[test]
fn nvme_unread_completion_interrupt_survives_restore_until_ack() {
    let mut h = Nvm::new(4);
    assert_eq!(h.submit(false, Nvm::command(0, 0, 0), false), 0);
    assert!(h.device.take_interrupt());
    let mut r = h.restored();
    assert!(r.device.take_interrupt());
    r.memory.clear();
    write(&mut r.device, nvme::REG_DOORBELL_BASE + 12, 1);
    assert!(!r.device.take_interrupt());
    r.memory.untouched();
}
#[test]
fn nvme_full_cq_preserves_pending_sq_and_never_reexecutes_completed_write() {
    let mut h = Nvm::new(2);
    h.memory.put(0x8000, &[0x27; 512]);
    assert_eq!(h.submit(false, Nvm::command(1, 0x8000, 0), false), 0);
    h.memory.put(0x8000, &[0x39; 512]);
    h.submit(false, Nvm::command(1, 0x8000, 1), false);
    assert_eq!(&h.device.disk()[..512], &[0x27; 512]);
    assert_eq!(&h.device.disk()[512..1024], &[0xa3; 512]);
    let mut r = h.restored();
    assert_eq!(&r.device.disk()[512..1024], &[0xa3; 512]);
    write(&mut r.device, nvme::REG_DOORBELL_BASE + 12, 1);
    assert_eq!(&r.device.disk()[..512], &[0x27; 512]);
    assert_eq!(&r.device.disk()[512..1024], &[0x39; 512]);
    let cqe = r.memory.get(0x4010, 16);
    assert_eq!(u16::from_le_bytes(cqe[12..14].try_into().unwrap()), 0x101);
    assert_eq!(u16::from_le_bytes(cqe[14..16].try_into().unwrap()) >> 1, 0);
    assert!(r.device.take_interrupt());
}
#[test]
fn nvme_masks_phase_and_feature_lock_roundtrip_across_ring_wraps() {
    let mut h = Nvm::new(2);
    for _ in 0..6 {
        h.submit(false, Nvm::command(0, 0, 0), true);
    }
    write(&mut h.device, nvme::REG_INTMS, 1);
    let original = h.device.checkpoint().unwrap();
    let r = h.restored();
    assert_eq!(r.device.checkpoint().unwrap(), original);
    assert!(!r.device.take_interrupt());
}
#[test]
fn nvme_readonly_media_stays_protected_after_detached_restore() {
    let image = ImageCheckpoint {
        bytes: vec![0x61; 4096],
        read_only: true,
    }
    .into_detached()
    .unwrap();
    let h = Nvm::image(4, image);
    let mut r = h.restored();
    r.memory.put(0x8000, &[0x92; 512]);
    assert_eq!(r.submit(false, Nvm::command(1, 0x8000, 0), true), 0x20);
    assert_eq!(r.device.disk(), vec![0x61; 4096]);
}
#[test]
fn nvme_every_truncated_control_and_trailing_byte_fail_atomically() {
    let source = Nvm::new(4).device.checkpoint().unwrap();
    let mut target = Nvm::new(2);
    let before = target.device.checkpoint().unwrap();
    for length in 0..source.state.len() {
        let mut bad = source.clone();
        bad.state.truncate(length);
        target.memory.clear();
        assert!(
            target.device.restore_checkpoint(bad).is_err(),
            "prefix{length}"
        );
        target.memory.untouched();
        assert_eq!(target.device.checkpoint().unwrap(), before);
    }
    let mut bad = source;
    bad.state.push(0);
    assert!(target.device.restore_checkpoint(bad).is_err());
    assert_eq!(target.device.checkpoint().unwrap(), before);
}
#[test]
fn nvme_corrupt_queue_profile_indices_booleans_and_media_are_rejected() {
    let source = Nvm::new(4).device.checkpoint().unwrap();
    let mut target = Nvm::new(2);
    let before = target.device.checkpoint().unwrap();
    for (offset, value) in [
        (0, 0),
        (24, 2),
        (57, 0),
        (59, 2),
        (68, 0),
        (72, 0xff),
        (153, 0xff),
        (155, 2),
        (348, 1),
        (352, 2),
    ] {
        let mut bad = source.clone();
        bad.state[offset] = value;
        target.memory.clear();
        assert!(
            target.device.restore_checkpoint(bad).is_err(),
            "byte{offset}"
        );
        target.memory.untouched();
        assert_eq!(target.device.checkpoint().unwrap(), before);
    }
    let mut bad = source;
    bad.media.bytes.pop();
    assert!(target.device.restore_checkpoint(bad).is_err());
    assert_eq!(target.device.checkpoint().unwrap(), before);
}
#[test]
fn ahci_control_wire_and_media_roundtrip_without_dma() {
    let h = Sata::new();
    let before = h.device.checkpoint().unwrap();
    assert_eq!(before.state.len(), 112);
    let r = h.restored();
    assert_eq!(r.device.checkpoint().unwrap(), before);
}
#[test]
fn ahci_fatal_slot_and_irq_remain_stopped_without_replay() {
    let mut h = Sata::new();
    h.command(31, 0xff, 0);
    h.issue(31);
    assert_eq!(h.device.port_ci(), 1 << 31);
    let mut r = h.restored();
    assert_eq!(r.device.port_ci(), 1 << 31);
    assert!(r.device.interrupt_pending());
    assert_eq!(
        (read(&mut r.device, ahci::PORT_BASE + ahci::PX_CMD) >> 8) & 31,
        31
    );
    r.memory.clear();
    r.issue(0);
    r.memory.untouched();
    assert_eq!(r.device.port_ci(), (1 << 31) | 1);
    assert_eq!(
        read(&mut r.device, ahci::PORT_BASE + ahci::PX_CMD) & ahci::PXCMD_CR,
        0
    );
}
#[test]
fn ahci_stopped_pending_command_executes_only_after_explicit_start() {
    let mut h = Sata::new();
    write(
        &mut h.device,
        ahci::PORT_BASE + ahci::PX_CMD,
        ahci::PXCMD_FRE,
    );
    h.command(0, 0x35, 0);
    h.memory.put(0x8000, &[0x27; 512]);
    h.issue(0);
    assert_eq!(h.device.port_ci(), 1);
    let mut r = h.restored();
    assert_eq!(r.device.disk(), vec![0xb9; 4096]);
    write(
        &mut r.device,
        ahci::PORT_BASE + ahci::PX_CMD,
        ahci::PXCMD_FRE | ahci::PXCMD_ST,
    );
    assert_eq!(r.device.port_ci(), 0);
    assert_eq!(&r.device.disk()[..512], &[0x27; 512]);
}
#[test]
fn ahci_completed_write_count_taskfile_and_sticky_interrupt_roundtrip() {
    let mut h = Sata::new();
    h.command(17, 0x35, 2);
    h.memory.put(0x8000, &[0x67; 512]);
    h.issue(17);
    let before = h.device.checkpoint().unwrap();
    let r = h.restored();
    assert_eq!(r.device.checkpoint().unwrap(), before);
    assert!(r.device.interrupt_pending());
    assert_eq!(r.memory.get(0x1000 + 17 * 32 + 4, 4), 512u32.to_le_bytes());
    assert_eq!(&r.device.disk()[1024..1536], &[0x67; 512]);
}
#[test]
fn ahci_readonly_media_stays_protected_after_detached_restore() {
    let image = ImageCheckpoint {
        bytes: vec![0x42; 4096],
        read_only: true,
    }
    .into_detached()
    .unwrap();
    let h = Sata::image(image);
    let mut r = h.restored();
    r.command(0, 0x35, 0);
    r.memory.put(0x8000, &[0x27; 512]);
    r.issue(0);
    assert_eq!(r.device.port_ci(), 1);
    assert_ne!(r.device.port_is() & ahci::PXIS_TFES, 0);
    assert_eq!(r.device.disk(), vec![0x42; 4096]);
}
#[test]
fn ahci_every_truncated_control_and_trailing_byte_fail_atomically() {
    let source = Sata::new().device.checkpoint().unwrap();
    let mut target = Sata::new();
    let before = target.device.checkpoint().unwrap();
    for length in 0..source.state.len() {
        let mut bad = source.clone();
        bad.state.truncate(length);
        target.memory.clear();
        assert!(
            target.device.restore_checkpoint(bad).is_err(),
            "prefix{length}"
        );
        target.memory.untouched();
        assert_eq!(target.device.checkpoint().unwrap(), before);
    }
    let mut bad = source;
    bad.state.push(0);
    assert!(target.device.restore_checkpoint(bad).is_err());
    assert_eq!(target.device.checkpoint().unwrap(), before);
}
#[test]
fn ahci_corrupt_profile_slots_boolean_alignment_and_media_fail_atomically() {
    let source = Sata::new().device.checkpoint().unwrap();
    let mut target = Sata::new();
    let before = target.device.checkpoint().unwrap();
    for (offset, value) in [
        (0, 0),
        (24, 2),
        (25, 4),
        (33, 0),
        (37, 2),
        (38, 1),
        (46, 1),
        (94, 2),
        (95, 2),
        (96, 32),
        (97, 32),
    ] {
        let mut bad = source.clone();
        bad.state[offset] = value;
        target.memory.clear();
        assert!(
            target.device.restore_checkpoint(bad).is_err(),
            "byte{offset}"
        );
        target.memory.untouched();
        assert_eq!(target.device.checkpoint().unwrap(), before);
    }
    let mut bad = source;
    bad.media.read_only = true;
    assert!(target.device.restore_checkpoint(bad).is_err());
    assert_eq!(target.device.checkpoint().unwrap(), before);
}
#[test]
fn empty_and_partial_sector_memory_media_preserve_legacy_capacity_bytes() {
    for bytes in [vec![], vec![0x71; 513]] {
        let memory = Memory::new();
        let n = nvme::NvmeController::new(BASE, memory.clone(), bytes.clone());
        let mut restored = nvme::NvmeController::new(0, memory.clone(), vec![]);
        restored
            .restore_checkpoint(n.checkpoint().unwrap())
            .unwrap();
        assert_eq!(restored.disk(), bytes);
        let a = ahci::AhciController::new(BASE, memory.clone(), bytes.clone());
        let mut restored = ahci::AhciController::new(0, memory, vec![]);
        restored
            .restore_checkpoint(a.checkpoint().unwrap())
            .unwrap();
        assert_eq!(restored.disk(), bytes);
    }
}
#[test]
fn media_checkpoint_detaches_file_and_preserves_readonly_without_host_effects() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rax-detached-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, vec![0x51; 4096]).unwrap();
    let source = BlockImage::open(&path, ImageMode::ReadWrite, 4096).unwrap();
    let mut restored = source.checkpoint().unwrap().into_detached().unwrap();
    assert!(restored.path().is_none());
    restored.write_bytes(0, &[0x92; 512]).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), vec![0x51; 4096]);
    drop(source);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn ahci_masked_sticky_status_survives_restore_and_late_global_enable() {
    let mut h = Sata::new();
    h.command(0, 0x25, 0);
    h.issue(0);
    assert!(h.device.interrupt_pending());
    write(&mut h.device, ahci::REG_GHC, ahci::GHC_AE);
    assert!(!h.device.interrupt_pending());
    let mut restored = h.restored();
    assert!(!restored.device.interrupt_pending());
    write(
        &mut restored.device,
        ahci::REG_GHC,
        ahci::GHC_AE | ahci::GHC_IE,
    );
    assert!(restored.device.interrupt_pending());
}

#[test]
fn nvme_admin_4096_entries_roundtrip_independently_of_io_mqes() {
    let memory = Memory(Arc::new(Mutex::new((vec![0; 1024 * 1024], vec![]))));
    let mut device = nvme::NvmeController::new(BASE, memory.clone(), vec![0x31; 4096]);
    for (r, v) in [
        (nvme::REG_AQA, 4095u32 | (4095 << 16)),
        (nvme::REG_ASQ, 0x1000),
        (nvme::REG_ACQ, 0x80000),
        (nvme::REG_CC, 0x00460001),
    ] {
        write(&mut device, r, v);
    }
    assert_eq!((device.cap() & 0xffff) + 1, 256);
    assert_eq!(
        read(&mut device, nvme::REG_CSTS) & nvme::CSTS_RDY,
        nvme::CSTS_RDY
    );
    let checkpoint = device.checkpoint().unwrap();
    let expected = checkpoint.clone();
    memory.clear();
    let mut restored = nvme::NvmeController::new(0, memory.clone(), vec![]);
    restored.restore_checkpoint(checkpoint).unwrap();
    memory.untouched();
    assert_eq!(restored.checkpoint().unwrap(), expected);
}
#[test]
fn nvme_io_queue_257_is_invalid_even_though_admin_can_use_4096() {
    let mut checkpoint = Nvm::new(4).device.checkpoint().unwrap();
    checkpoint.state[140..144].copy_from_slice(&257u32.to_le_bytes());
    let mut target = Nvm::new(2);
    let before = target.device.checkpoint().unwrap();
    target.memory.clear();
    assert!(target.device.restore_checkpoint(checkpoint).is_err());
    target.memory.untouched();
    assert_eq!(target.device.checkpoint().unwrap(), before);
}

/// Publish source/restored controls, media and RAM for an independent parser.
pub fn emit_reference(folder: &std::path::Path) {
    std::fs::create_dir_all(folder).unwrap();
    for index in 0..9 {
        let case = folder.join(format!("case-{index}"));
        std::fs::create_dir_all(&case).unwrap();
        if index < 5 {
            let mut h = if index == 3 {
                Nvm::image(
                    4,
                    ImageCheckpoint {
                        bytes: vec![0x61; 4096],
                        read_only: true,
                    }
                    .into_detached()
                    .unwrap(),
                )
            } else {
                Nvm::new(if index == 2 { 2 } else { 4 })
            };
            if index == 1 {
                h.submit(false, Nvm::command(0, 0, 0), false);
            }
            if index == 2 {
                h.memory.put(0x8000, &[0x27; 512]);
                h.submit(false, Nvm::command(1, 0x8000, 0), false);
                h.memory.put(0x8000, &[0x39; 512]);
                h.submit(false, Nvm::command(1, 0x8000, 1), false);
            }
            if index == 4 {
                write(&mut h.device, nvme::REG_CC, 0);
                write(&mut h.device, nvme::REG_AQA, 4095 | (4095 << 16));
                write(&mut h.device, nvme::REG_ASQ, 0x1000);
                write(&mut h.device, nvme::REG_ACQ, 0x80000);
                write(&mut h.device, nvme::REG_CC, 0x00460001);
            }
            let cp = h.device.checkpoint().unwrap();
            std::fs::write(case.join("control.bin"), &cp.state).unwrap();
            std::fs::write(case.join("media.raw"), &cp.media.bytes).unwrap();
            std::fs::write(case.join("ram.raw"), h.memory.get(0, 0x20000)).unwrap();
            let mut restored = h.restored();
            assert_eq!(restored.device.checkpoint().unwrap(), cp);
            if index == 2 {
                write(&mut restored.device, nvme::REG_DOORBELL_BASE + 12, 1);
            }
            let cp = restored.device.checkpoint().unwrap();
            std::fs::write(case.join("continued-control.bin"), &cp.state).unwrap();
            std::fs::write(case.join("continued-media.raw"), &cp.media.bytes).unwrap();
            std::fs::write(
                case.join("continued-ram.raw"),
                restored.memory.get(0, 0x20000),
            )
            .unwrap();
        } else {
            let mut h = if index == 8 {
                Sata::image(
                    ImageCheckpoint {
                        bytes: vec![0x42; 4096],
                        read_only: true,
                    }
                    .into_detached()
                    .unwrap(),
                )
            } else {
                Sata::new()
            };
            if index == 5 {
                h.command(17, 0x35, 2);
                h.memory.put(0x8000, &[0x67; 512]);
                h.issue(17);
            }
            if index == 6 {
                h.command(31, 0xff, 0);
                h.issue(31);
            }
            if index == 7 {
                write(
                    &mut h.device,
                    ahci::PORT_BASE + ahci::PX_CMD,
                    ahci::PXCMD_FRE,
                );
                h.command(0, 0x35, 0);
                h.memory.put(0x8000, &[0x27; 512]);
                h.issue(0);
            }
            let cp = h.device.checkpoint().unwrap();
            std::fs::write(case.join("control.bin"), &cp.state).unwrap();
            std::fs::write(case.join("media.raw"), &cp.media.bytes).unwrap();
            std::fs::write(case.join("ram.raw"), h.memory.get(0, 0x20000)).unwrap();
            let mut restored = h.restored();
            assert_eq!(restored.device.checkpoint().unwrap(), cp);
            if index == 6 {
                restored.issue(0);
            }
            if index == 7 {
                write(
                    &mut restored.device,
                    ahci::PORT_BASE + ahci::PX_CMD,
                    ahci::PXCMD_FRE | ahci::PXCMD_ST,
                );
            }
            let cp = restored.device.checkpoint().unwrap();
            std::fs::write(case.join("continued-control.bin"), &cp.state).unwrap();
            std::fs::write(case.join("continued-media.raw"), &cp.media.bytes).unwrap();
            std::fs::write(
                case.join("continued-ram.raw"),
                restored.memory.get(0, 0x20000),
            )
            .unwrap();
        }
    }
    println!("controller-checkpoint-fixtures=9");
}
