//! Public image/media APIs and actual device command paths against raw files.
use rax::devices::ahci;
use rax::devices::bus::MmioDevice;
use rax::devices::nvme;
use rax::devices::virtio::blk::*;
use rax::devices::virtio::block_image::{BlockImage, ImageMode, MAX_IMAGE_BYTES};
use rax::devices::virtio::{Descriptor, DescriptorChain, Mem, VecMem, VirtioDevice};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Image {
    directory: PathBuf,
    path: PathBuf,
    original: Vec<u8>,
}
impl Image {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-image-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("disk.raw");
        let original = (0..16384)
            .map(|i| ((i * 37) ^ (i >> 9)) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&path, &original).unwrap();
        Self {
            directory,
            path,
            original,
        }
    }
    fn open(&self, mode: ImageMode) -> BlockImage {
        BlockImage::open(&self.path, mode, 1024 * 1024).unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap()
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
#[test]
fn loading_all_modes_preserves_every_byte_and_records_canonical_path() {
    let i = Image::new();
    for mode in [
        ImageMode::ReadOnly,
        ImageMode::ReadWrite,
        ImageMode::CopyOnWrite,
    ] {
        let image = i.open(mode);
        assert_eq!(&*image, i.original);
        assert_eq!(image.mode(), mode);
        assert_eq!(image.path(), Some(i.path.canonicalize().unwrap().as_path()));
    }
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn readonly_write_and_zero_errors_preserve_cache_and_original() {
    let i = Image::new();
    let mut image = i.open(ImageMode::ReadOnly);
    assert_eq!(
        image.write_bytes(0, &[1; 512]).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(image.zero_bytes(0..512).is_err());
    image.flush().unwrap();
    assert_eq!(&*image, i.original);
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn cow_modifications_and_flush_never_change_source_or_other_instances() {
    let i = Image::new();
    let mut a = i.open(ImageMode::CopyOnWrite);
    let b = i.open(ImageMode::CopyOnWrite);
    a.write_bytes(4094, &[0x97; 1024]).unwrap();
    a.zero_bytes(100..600).unwrap();
    a.flush().unwrap();
    assert_eq!(&a[4094..5118], &[0x97; 1024]);
    assert_eq!(&a[100..600], &[0; 500]);
    assert_eq!(&*b, i.original);
    drop(a);
    assert_eq!(i.bytes(), i.original);
    assert_eq!(&*i.open(ImageMode::CopyOnWrite), i.original);
}
#[test]
fn persistent_writes_and_zeroes_are_visible_without_separate_flush() {
    let i = Image::new();
    let mut image = i.open(ImageMode::ReadWrite);
    image.write_bytes(4094, &[0x73; 1024]).unwrap();
    image.zero_bytes(8000..15000).unwrap();
    let mut expected = i.original.clone();
    expected[4094..5118].fill(0x73);
    expected[8000..15000].fill(0);
    assert_eq!(&*image, expected);
    assert_eq!(i.bytes(), expected);
    image.flush().unwrap();
    drop(image);
    assert_eq!(&*i.open(ImageMode::ReadOnly), expected);
}
#[test]
fn invalid_write_and_zero_extents_have_no_cache_or_host_effects() {
    let i = Image::new();
    let mut image = i.open(ImageMode::ReadWrite);
    assert!(image.write_bytes(usize::MAX, &[1, 2]).is_err());
    assert!(image.write_bytes(16383, &[1, 2]).is_err());
    assert!(image.zero_bytes(400..399).is_err());
    assert!(image.zero_bytes(0..16385).is_err());
    assert_eq!(&*image, i.original);
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn zero_length_at_capacity_is_noop_and_outside_capacity_is_error() {
    let i = Image::new();
    let mut image = i.open(ImageMode::ReadWrite);
    image.write_bytes(16384, &[]).unwrap();
    image.zero_bytes(16384..16384).unwrap();
    assert!(image.write_bytes(16385, &[]).is_err());
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn invalid_budget_capacity_and_nonregular_inputs_do_not_mutate_source() {
    let i = Image::new();
    for max in [0, MAX_IMAGE_BYTES + 1, 16383] {
        assert!(BlockImage::open(&i.path, ImageMode::ReadWrite, max).is_err());
    }
    assert!(BlockImage::open(&i.directory, ImageMode::ReadOnly, 1024).is_err());
    let absent = i.directory.join("missing");
    assert!(BlockImage::open(&absent, ImageMode::ReadWrite, 1024).is_err());
    assert!(!absent.exists());
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn empty_and_partial_sector_images_are_rejected_without_padding() {
    let i = Image::new();
    for length in [0, 1, 511, 513] {
        std::fs::write(&i.path, vec![0x87; length]).unwrap();
        assert!(BlockImage::open(&i.path, ImageMode::ReadWrite, 1024).is_err());
        assert_eq!(i.bytes(), vec![0x87; length]);
    }
}
#[test]
fn exclusive_attachment_rejects_conflicting_lock_and_releases_on_drop() {
    let i = Image::new();
    let a = i.open(ImageMode::ReadWrite);
    for mode in [
        ImageMode::ReadOnly,
        ImageMode::ReadWrite,
        ImageMode::CopyOnWrite,
    ] {
        assert!(BlockImage::open(&i.path, mode, 16384).is_err());
    }
    drop(a);
    let _a = i.open(ImageMode::ReadWrite);
}
#[test]
fn changed_host_capacity_fails_write_and_flush_without_claiming_success() {
    let i = Image::new();
    let mut image = i.open(ImageMode::ReadWrite);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&i.path)
        .unwrap()
        .set_len(512)
        .unwrap();
    assert!(image.write_bytes(0, &[0x92; 512]).is_err());
    assert!(image.flush().is_err());
    assert_eq!(&*image, i.original);
    assert_eq!(i.bytes(), i.original[..512]);
}
#[test]
fn cow_is_a_frozen_instance_when_source_changes_after_load() {
    let i = Image::new();
    let image = i.open(ImageMode::CopyOnWrite);
    std::fs::write(&i.path, vec![0x61; 16384]).unwrap();
    assert_eq!(&*image, i.original);
}
#[test]
fn memory_constructor_retains_empty_and_partial_sector_compatibility() {
    for bytes in [vec![], vec![1; 513]] {
        let mut image = BlockImage::from_bytes(bytes.clone());
        assert_eq!(&*image, bytes);
        assert!(image.path().is_none());
        image.flush().unwrap();
    }
}
#[cfg(unix)]
#[test]
fn canonical_symlink_and_hardlink_aliases_share_persistent_lock() {
    let i = Image::new();
    let symlink = i.directory.join("symbolic");
    let hardlink = i.directory.join("hard");
    std::os::unix::fs::symlink(&i.path, &symlink).unwrap();
    std::fs::hard_link(&i.path, &hardlink).unwrap();
    let image = BlockImage::open(&symlink, ImageMode::ReadWrite, 16384).unwrap();
    assert_eq!(image.path(), Some(i.path.canonicalize().unwrap().as_path()));
    assert!(BlockImage::open(&hardlink, ImageMode::ReadWrite, 16384).is_err());
}

#[derive(Clone)]
struct Memory(Arc<Mutex<Vec<u8>>>);
impl Memory {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(vec![0; 0x20000])))
    }
    fn put(&self, a: u64, b: &[u8]) {
        self.0.lock().unwrap()[a as usize..a as usize + b.len()].copy_from_slice(b);
    }
    fn get(&self, a: u64, n: usize) -> Vec<u8> {
        self.0.lock().unwrap()[a as usize..a as usize + n].to_vec()
    }
}
impl Mem for Memory {
    fn read(&self, a: u64, b: &mut [u8]) -> bool {
        let Ok(a) = usize::try_from(a) else {
            return false;
        };
        let s = self.0.lock().unwrap();
        let Some(end) = a.checked_add(b.len()).filter(|end| *end <= s.len()) else {
            return false;
        };
        b.copy_from_slice(&s[a..end]);
        true
    }
    fn write(&mut self, a: u64, b: &[u8]) -> bool {
        let Ok(a) = usize::try_from(a) else {
            return false;
        };
        let mut s = self.0.lock().unwrap();
        let Some(end) = a.checked_add(b.len()).filter(|end| *end <= s.len()) else {
            return false;
        };
        s[a..end].copy_from_slice(b);
        true
    }
}
struct Nvme {
    device: nvme::NvmeController<Memory>,
    memory: Memory,
    admin: u32,
    io: u32,
}
impl Nvme {
    fn new(image: BlockImage) -> Self {
        let memory = Memory::new();
        let mut h = Self {
            device: nvme::NvmeController::with_image(0, memory.clone(), image),
            memory,
            admin: 0,
            io: 0,
        };
        for (r, v) in [
            (nvme::REG_AQA, 63u32 | (63 << 16)),
            (nvme::REG_ASQ, 0x1000),
            (nvme::REG_ACQ, 0x2000),
            (nvme::REG_CC, 0x00460001),
        ] {
            h.device.write(r, &v.to_le_bytes());
        }
        for (op, base, flags) in [(5, 0x4000, 1u32), (1, 0x3000, 0x10001)] {
            let mut c = Self::command(op, base, 0);
            c[40..44].copy_from_slice(&0x003f0001u32.to_le_bytes());
            c[44..48].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(h.submit(true, c), 0);
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
    fn submit(&mut self, admin: bool, c: [u8; 64]) -> u16 {
        let slot = if admin { self.admin } else { self.io };
        let (sq, cq, doorbell) = if admin {
            (0x1000, 0x2000, 0x1000)
        } else {
            (0x3000, 0x4000, 0x1008)
        };
        self.memory.put(sq + u64::from(slot) * 64, &c);
        let next = (slot + 1) % 64;
        self.device.write(doorbell, &next.to_le_bytes());
        let r = self.memory.get(cq + u64::from(slot) * 16, 16);
        self.device.write(doorbell + 4, &next.to_le_bytes());
        if admin {
            self.admin = next
        } else {
            self.io = next
        };
        u16::from_le_bytes(r[14..16].try_into().unwrap()) >> 1
    }
}
#[test]
fn nvme_write_and_fua_update_file_before_completion_and_flush_succeeds() {
    let i = Image::new();
    let mut h = Nvme::new(i.open(ImageMode::ReadWrite));
    h.memory.put(0x8000, &[0x47; 512]);
    for (fua, lba) in [(false, 2), (true, 3)] {
        let mut c = Nvme::command(1, 0x8000, lba);
        if fua {
            c[48..52].copy_from_slice(&(1u32 << 30).to_le_bytes());
        }
        assert_eq!(h.submit(false, c), 0);
        assert_eq!(
            &i.bytes()[lba as usize * 512..lba as usize * 512 + 512],
            &[0x47; 512]
        );
    }
    assert_eq!(h.submit(false, Nvme::command(0, 0, 0)), 0);
}
#[test]
fn nvme_readonly_writes_zeroes_and_deallocation_fail_without_effects() {
    let i = Image::new();
    let mut h = Nvme::new(i.open(ImageMode::ReadOnly));
    assert_eq!(h.submit(false, Nvme::command(2, 0x8000, 2)), 0);
    assert_eq!(h.memory.get(0x8000, 512), i.original[1024..1536]);
    assert_eq!(h.submit(true, Nvme::command(6, 0xa000, 0)), 0);
    assert_eq!(h.memory.get(0xa000 + 99, 1), [1]);

    for op in [1, 8, 9] {
        let mut c = Nvme::command(op, u64::MAX, 0);
        if op == 9 {
            c[44..48].copy_from_slice(&4u32.to_le_bytes());
        }
        assert_eq!(h.submit(false, c), 0x20);
    }
    assert_eq!(h.device.disk(), i.original);
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn nvme_host_failure_reports_media_status_and_retains_cached_bytes() {
    let i = Image::new();
    let mut h = Nvme::new(i.open(ImageMode::ReadWrite));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&i.path)
        .unwrap()
        .set_len(512)
        .unwrap();
    h.memory.put(0x8000, &[0x72; 512]);
    assert_eq!(h.submit(false, Nvme::command(1, 0x8000, 0)), 0x280);
    assert_eq!(h.submit(false, Nvme::command(0, 0, 0)), 0x280);
    assert_eq!(h.device.disk(), i.original);
}
fn ahci_command(d: &mut ahci::AhciController<Memory>, memory: &Memory, op: u8, lba: u8) {
    let mut header = [0; 32];
    let flags = 5u32
        | if op == 0x35 { 1 << 6 } else { 0 }
        | if op == 0x25 || op == 0x35 { 1 << 16 } else { 0 };
    header[..4].copy_from_slice(&flags.to_le_bytes());
    header[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
    memory.put(0x1000, &header);
    let mut fis = [0; 20];
    fis[0] = 0x27;
    fis[1] = 0x80;
    fis[2] = op;
    fis[4] = lba;
    fis[7] = 0x40;
    fis[12] = 1;
    memory.put(0x3000, &fis);
    let mut prd = [0; 16];
    prd[..8].copy_from_slice(&0x8000u64.to_le_bytes());
    prd[12..16].copy_from_slice(&511u32.to_le_bytes());
    memory.put(0x3080, &prd);
    d.write(ahci::PORT_BASE + ahci::PX_CI, &1u32.to_le_bytes());
}
fn ahci_device(image: BlockImage) -> (ahci::AhciController<Memory>, Memory) {
    let m = Memory::new();
    let mut d = ahci::AhciController::with_image(0, m.clone(), image);
    for (r, v) in [
        (ahci::REG_GHC, 0x80000002u32),
        (ahci::PORT_BASE + ahci::PX_CLB, 0x1000),
        (ahci::PORT_BASE + ahci::PX_FB, 0x2000),
        (ahci::PORT_BASE + ahci::PX_CMD, 0x11),
    ] {
        d.write(r, &v.to_le_bytes());
    }
    (d, m)
}
#[test]
fn ahci_write_updates_persistent_file_and_flush_has_no_payload_dma() {
    let i = Image::new();
    let (mut d, m) = ahci_device(i.open(ImageMode::ReadWrite));
    m.put(0x8000, &[0x35; 512]);
    ahci_command(&mut d, &m, 0x35, 2);
    assert_eq!(d.port_ci(), 0);
    assert_eq!(&i.bytes()[1024..1536], &[0x35; 512]);
    for op in [0xe7, 0xea] {
        ahci_command(&mut d, &m, op, 0);
        assert_eq!(d.port_ci(), 0);
    }
}
#[test]
fn ahci_readonly_write_retains_failed_command_and_source_media() {
    let i = Image::new();
    let (mut d, m) = ahci_device(i.open(ImageMode::ReadOnly));
    ahci_command(&mut d, &m, 0x25, 2);
    assert_eq!(d.port_ci(), 0);
    assert_eq!(m.get(0x8000, 512), i.original[1024..1536]);
    m.put(0x8000, &[0x89; 512]);
    ahci_command(&mut d, &m, 0x35, 2);
    assert_eq!(d.port_ci(), 1);
    assert_ne!(d.port_is() & (1 << 30), 0);
    assert_eq!(d.disk(), i.original);
    assert_eq!(i.bytes(), i.original);
}
fn blk_request(d: &mut VirtioBlk, op: u32, sector: u64, data: &[u8]) -> u8 {
    let mut m = VecMem::new(0x4000);
    let mut header = [0; 16];
    header[..4].copy_from_slice(&op.to_le_bytes());
    header[8..].copy_from_slice(&sector.to_le_bytes());
    assert!(m.write(0x100, &header));
    assert!(m.write(0x200, data));
    let mut descriptors = vec![Descriptor {
        addr: 0x100,
        len: 16,
        flags: 1,
        next: 1,
    }];
    if !data.is_empty() {
        descriptors.push(Descriptor {
            addr: 0x200,
            len: data.len() as u32,
            flags: 1,
            next: 2,
        });
    }
    descriptors.push(Descriptor {
        addr: 0x3000,
        len: 1,
        flags: 2,
        next: 0,
    });
    d.handle_chain(
        &DescriptorChain {
            head: 0,
            descriptors,
        },
        &mut m,
    );
    let mut status = [0xff];
    assert!(m.read(0x3000, &mut status));
    status[0]
}
#[test]
fn virtio_persistent_write_zeroes_and_flush_use_image_backend() {
    let i = Image::new();
    let mut d = VirtioBlk::with_image(i.open(ImageMode::ReadWrite));
    assert_eq!(blk_request(&mut d, 1, 1, &[0x82; 512]), 0);
    assert_eq!(&i.bytes()[512..1024], &[0x82; 512]);
    let mut range = [0; 16];
    range[..8].copy_from_slice(&1u64.to_le_bytes());
    range[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(blk_request(&mut d, 13, 0, &range), 0);
    assert_eq!(&i.bytes()[512..1024], &[0; 512]);
    assert_eq!(blk_request(&mut d, 4, 0, &[]), 0);
}
#[test]
fn virtio_readonly_image_flag_and_write_protection_cannot_be_cleared_by_device_override() {
    let i = Image::new();
    let mut d = VirtioBlk::with_image(i.open(ImageMode::ReadOnly));
    d.set_read_only(false);
    assert_ne!(d.device_features() & VIRTIO_BLK_F_RO, 0);
    assert_eq!(blk_request(&mut d, 1, 0, &[0x53; 512]), 1);
    assert_eq!(i.bytes(), i.original);
}
#[test]
fn virtio_flush_host_failure_is_reported_as_ioerr() {
    let i = Image::new();
    let mut d = VirtioBlk::with_image(i.open(ImageMode::ReadWrite));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&i.path)
        .unwrap()
        .set_len(512)
        .unwrap();
    assert_eq!(blk_request(&mut d, 4, 0, &[]), 1);
}

#[test]
fn virtio_readonly_guest_read_returns_original_image_bytes() {
    let i = Image::new();
    let mut d = VirtioBlk::with_image(i.open(ImageMode::ReadOnly));
    let mut memory = VecMem::new(0x4000);
    let mut header = [0; 16];
    header[8..16].copy_from_slice(&1u64.to_le_bytes());
    assert!(memory.write(0x100, &header));
    let chain = DescriptorChain {
        head: 0,
        descriptors: vec![
            Descriptor {
                addr: 0x100,
                len: 16,
                flags: 1,
                next: 1,
            },
            Descriptor {
                addr: 0x200,
                len: 512,
                flags: 3,
                next: 2,
            },
            Descriptor {
                addr: 0x3000,
                len: 1,
                flags: 2,
                next: 0,
            },
        ],
    };
    d.handle_chain(&chain, &mut memory);
    let mut result = [0; 512];
    assert!(memory.read(0x200, &mut result));
    assert_eq!(result.as_slice(), &i.original[512..1024]);
    let mut status = [0xff];
    assert!(memory.read(0x3000, &mut status));
    assert_eq!(status, [0]);
}
#[test]
fn ahci_flush_host_failure_retains_command_and_reports_taskfile_error() {
    let i = Image::new();
    let (mut d, m) = ahci_device(i.open(ImageMode::ReadWrite));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&i.path)
        .unwrap()
        .set_len(512)
        .unwrap();
    ahci_command(&mut d, &m, 0xea, 0);
    assert_eq!(d.port_ci(), 1);
    assert_ne!(d.port_is() & (1 << 30), 0);
    assert_eq!(d.disk(), i.original);
}
#[test]
fn all_three_device_cow_writes_change_only_their_instance_media() {
    let i = Image::new();
    let mut n = Nvme::new(i.open(ImageMode::CopyOnWrite));
    n.memory.put(0x8000, &[0x29; 512]);
    assert_eq!(n.submit(false, Nvme::command(1, 0x8000, 0)), 0);
    assert_eq!(&n.device.disk()[..512], &[0x29; 512]);
    let (mut a, m) = ahci_device(i.open(ImageMode::CopyOnWrite));
    m.put(0x8000, &[0x31; 512]);
    ahci_command(&mut a, &m, 0x35, 0);
    assert_eq!(a.port_ci(), 0);
    assert_eq!(&a.disk()[..512], &[0x31; 512]);
    let mut v = VirtioBlk::with_image(i.open(ImageMode::CopyOnWrite));
    assert_eq!(blk_request(&mut v, 1, 0, &[0x47; 512]), 0);
    assert_eq!(&v.disk()[..512], &[0x47; 512]);
    assert_eq!(i.bytes(), i.original);
}
