//! virtio over MMIO transport (VIRTIO 1.x / spec v2).
//!
//! This module implements the *transport* half of a virtio device using the
//! MMIO register layout defined in the "Virtual I/O Device (VIRTIO) Version 1.x"
//! specification, section "Virtio Over MMIO". A concrete device (for example
//! [`blk::VirtioBlk`]) plugs into the transport by implementing the
//! [`VirtioDevice`] trait, which supplies the device id, feature bits, a
//! configuration space, and the per-queue request handling.
//!
//! # MMIO register layout
//!
//! The transport occupies a contiguous MMIO window. Offsets (from the window
//! base) of the registers we implement:
//!
//! | Offset | Name                | Dir | Notes                               |
//! |--------|---------------------|-----|-------------------------------------|
//! | 0x000  | MagicValue          | RO  | "virt" = `0x74726976`               |
//! | 0x004  | Version             | RO  | `2` (spec v2, non-legacy)           |
//! | 0x008  | DeviceID            | RO  | per-device (blk = 2)                |
//! | 0x00C  | VendorID            | RO  | "QEMU" = `0x554d4551`               |
//! | 0x010  | DeviceFeatures      | RO  | feature words, selected by 0x014    |
//! | 0x014  | DeviceFeaturesSel   | WO  | selects feature word (0 or 1)       |
//! | 0x020  | DriverFeatures      | WO  | feature words, selected by 0x024    |
//! | 0x024  | DriverFeaturesSel   | WO  | selects feature word (0 or 1)       |
//! | 0x030  | QueueSel            | WO  | selects the queue addressed below   |
//! | 0x034  | QueueNumMax         | RO  | max size of the selected queue      |
//! | 0x038  | QueueNum            | WO  | negotiated size of the queue        |
//! | 0x044  | QueueReady          | RW  | 1 = queue is live                   |
//! | 0x050  | QueueNotify         | WO  | driver kicks the written queue      |
//! | 0x060  | InterruptStatus     | RO  | bit0 = used buffer, bit1 = config   |
//! | 0x064  | InterruptACK        | WO  | write-1-to-clear of InterruptStatus |
//! | 0x070  | Status              | RW  | device status bits                  |
//! | 0x080  | QueueDescLow        | WO  | descriptor table GPA low 32 bits    |
//! | 0x084  | QueueDescHigh       | WO  | descriptor table GPA high 32 bits   |
//! | 0x090  | QueueDriverLow      | WO  | available ring GPA low 32 bits      |
//! | 0x094  | QueueDriverHigh     | WO  | available ring GPA high 32 bits     |
//! | 0x0A0  | QueueDeviceLow      | WO  | used ring GPA low 32 bits           |
//! | 0x0A4  | QueueDeviceHigh     | WO  | used ring GPA high 32 bits          |
//! | 0x0FC  | ConfigGeneration    | RO  | config-space generation counter     |
//! | 0x100+ | Config              | RW  | device-specific configuration space |
//!
//! All registers are accessed as little-endian 32-bit words except the
//! device-specific configuration space (>= 0x100), which is byte addressable.
//!
//! # What is deferred
//!
//! The transport exposes the negotiated queue addresses and a [`Mem`] trait for
//! reading/writing guest memory, and [`VirtQueue::process`] walks the split
//! virtqueue (descriptor table / available ring / used ring) far enough to hand
//! each chained request to the device and post completions to the used ring.
//! What is *partial / deferred*:
//!
//! * Negotiated indirect descriptors and checked split-ring publication are supported.
//! * Used/available event suppression (`VIRTIO_F_EVENT_IDX`) is not honoured.
//! * Interrupt delivery is surfaced via [`VirtioMmio::interrupt_status`] /
//!   [`VirtioMmio::take_interrupt`] for an orchestrator to inject; the transport
//!   does not itself raise a guest interrupt line.
//!
//! Hardware interrupt routing, concurrent DMA synchronization and complete
//! checkpoint integration remain separate platform requirements.

pub mod blk;

use super::bus::MmioDevice;

// ---- Identity registers ----------------------------------------------------

/// MagicValue register contents: ASCII "virt", little-endian.
pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
/// Version register: `2` selects the modern (non-legacy) MMIO interface.
pub const VIRTIO_MMIO_VERSION: u32 = 2;
/// VendorID register contents: ASCII "QEMU".
pub const VIRTIO_MMIO_VENDOR: u32 = 0x554d_4551;

// ---- Register offsets ------------------------------------------------------

pub const REG_MAGIC_VALUE: u64 = 0x000;
pub const REG_VERSION: u64 = 0x004;
pub const REG_DEVICE_ID: u64 = 0x008;
pub const REG_VENDOR_ID: u64 = 0x00c;
pub const REG_DEVICE_FEATURES: u64 = 0x010;
pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const REG_DRIVER_FEATURES: u64 = 0x020;
pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const REG_QUEUE_SEL: u64 = 0x030;
pub const REG_QUEUE_NUM_MAX: u64 = 0x034;
pub const REG_QUEUE_NUM: u64 = 0x038;
pub const REG_QUEUE_READY: u64 = 0x044;
pub const REG_QUEUE_NOTIFY: u64 = 0x050;
pub const REG_INTERRUPT_STATUS: u64 = 0x060;
pub const REG_INTERRUPT_ACK: u64 = 0x064;
pub const REG_STATUS: u64 = 0x070;
pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
pub const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
pub const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
pub const REG_QUEUE_DEVICE_LOW: u64 = 0x0a0;
pub const REG_QUEUE_DEVICE_HIGH: u64 = 0x0a4;
pub const REG_CONFIG_GENERATION: u64 = 0x0fc;
/// First byte of the device-specific configuration space.
pub const REG_CONFIG: u64 = 0x100;

// ---- Device status bits (spec 2.1) -----------------------------------------

pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u32 = 64;
pub const STATUS_FAILED: u32 = 128;

// ---- InterruptStatus bits --------------------------------------------------

/// A buffer has been used (added to the used ring).
pub const INT_USED_BUFFER: u32 = 1 << 0;
/// The device configuration changed.
pub const INT_CONFIG_CHANGE: u32 = 1 << 1;

// ---- Common (transport-level) feature bits ---------------------------------

/// `VIRTIO_F_VERSION_1`: the device operates in modern (1.x) mode. Required by
/// a v2 MMIO transport and always advertised.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Number of 32-bit feature words exposed (bits 0..63 => words 0 and 1).
const FEATURE_WORDS: usize = 2;
/// Negotiated split-ring indirect descriptor support.
pub const VIRTIO_F_INDIRECT_DESC: u64 = 1 << 28;

/// Maximum number of descriptors we allow per queue. Power of two as required
/// by the spec.
pub const QUEUE_SIZE_MAX: u32 = 256;

/// Abstraction over guest physical memory used by the ring-walking code.
///
/// The transport itself is memory-agnostic so the device and its virtqueue
/// logic can be unit-tested against a plain `Vec<u8>` backing store. A real VMM
/// implements this over its `GuestMemoryMmap`.
pub trait Mem {
    /// Read bytes starting at guest physical address `gpa` into `buf`.
    /// Returns false if the access is out of bounds (the caller treats this as
    /// a failed request).
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool;
    /// Write `buf` to guest physical address `gpa`. Returns false on an
    /// out-of-bounds access.
    fn write(&mut self, gpa: u64, buf: &[u8]) -> bool;
}

/// A flat little-endian byte buffer used as guest memory in tests. GPA 0 maps
/// to byte 0 of the buffer.
pub struct VecMem {
    pub bytes: Vec<u8>,
}

impl VecMem {
    pub fn new(size: usize) -> Self {
        VecMem {
            bytes: vec![0u8; size],
        }
    }
}

impl Mem for VecMem {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool {
        let start = gpa as usize;
        let end = match start.checked_add(buf.len()) {
            Some(e) => e,
            None => return false,
        };
        if end > self.bytes.len() {
            return false;
        }
        buf.copy_from_slice(&self.bytes[start..end]);
        true
    }

    fn write(&mut self, gpa: u64, buf: &[u8]) -> bool {
        let start = gpa as usize;
        let end = match start.checked_add(buf.len()) {
            Some(e) => e,
            None => return false,
        };
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[start..end].copy_from_slice(buf);
        true
    }
}

mod queue;
pub use queue::{
    Descriptor, DescriptorChain, QueueError, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE, VirtQueue,
};

/// Interface a concrete virtio device implements to be driven by the transport.
pub trait VirtioDevice: Send {
    /// The virtio device id reported in the DeviceID register.
    fn device_id(&self) -> u32;
    /// The device's offered feature bits (combined across all 64 bits). The
    /// transport always OR-s in [`VIRTIO_F_VERSION_1`].
    fn device_features(&self) -> u64;
    /// Number of virtqueues this device exposes.
    fn num_queues(&self) -> usize;
    /// Read one byte of the device-specific configuration space at `offset`.
    fn config_read(&self, offset: u64) -> u8;
    /// Write one byte of the device-specific configuration space. Most blk
    /// config is read-only; the default ignores writes.
    fn config_write(&mut self, _offset: u64, _value: u8) {}
    /// Called when the driver kicks `queue_idx` (QueueNotify). `queue` is the
    /// transport's per-queue state for that index, and `mem` is guest memory.
    /// Implementations typically call [`VirtQueue::process`].
    fn handle_queue(&mut self, queue_idx: usize, queue: &mut VirtQueue, mem: &mut dyn Mem);
    /// Feature-aware checked path. Existing device implementations retain their
    /// callback; devices offering indirect descriptors can override this method.
    fn handle_queue_with_features(
        &mut self,
        queue_idx: usize,
        queue: &mut VirtQueue,
        mem: &mut dyn Mem,
        _features: u64,
    ) -> Result<(), QueueError> {
        self.handle_queue(queue_idx, queue, mem);
        Ok(())
    }
}

/// The virtio MMIO transport wrapping a concrete [`VirtioDevice`].
///
/// `M` is the guest memory type; it is owned by the transport so that the
/// `MmioDevice::write` handler (which takes `&mut self` only) can perform the
/// ring DMA when the driver kicks a queue.
pub struct VirtioMmio<M: Mem> {
    base: u64,
    device: Box<dyn VirtioDevice>,
    mem: M,

    // Negotiation state.
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,

    // Per-queue state, indexed by queue selector.
    queue_sel: u32,
    queues: Vec<VirtQueue>,

    // Status / interrupt.
    status: u32,
    interrupt_status: u32,
    config_generation: u32,
}

impl<M: Mem> VirtioMmio<M> {
    /// Build a transport at MMIO window `base` wrapping `device`, using `mem`
    /// as the guest memory backing for ring DMA.
    pub fn new(base: u64, device: Box<dyn VirtioDevice>, mem: M) -> Self {
        let num_queues = device.num_queues();
        VirtioMmio {
            base,
            device,
            mem,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            queues: vec![VirtQueue::default(); num_queues],
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
        }
    }

    /// The full set of features the device offers (device bits plus the
    /// transport-mandated `VIRTIO_F_VERSION_1`).
    fn offered_features(&self) -> u64 {
        self.device.device_features() | VIRTIO_F_VERSION_1
    }

    /// Features that have actually been negotiated (driver bits masked by what
    /// the device offered).
    pub fn negotiated_features(&self) -> u64 {
        if self.status & STATUS_FEATURES_OK == 0 {
            return 0;
        }
        self.driver_features & self.offered_features()
    }

    /// Current device status register value.
    pub fn status(&self) -> u32 {
        self.status
    }

    /// Pending interrupt-status bits (un-acked).
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// True if an interrupt is pending and an orchestrator should inject one.
    pub fn take_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Borrow the guest memory backing (for orchestrators that need to inspect
    /// it, and for tests that verify DMA results after a notify).
    pub fn mem(&self) -> &M {
        &self.mem
    }

    fn selected_queue(&self) -> Option<&VirtQueue> {
        self.queues.get(self.queue_sel as usize)
    }
    fn selected_queue_mut(&mut self) -> Option<&mut VirtQueue> {
        self.queues.get_mut(self.queue_sel as usize)
    }
    fn needs_reset(&mut self) {
        self.status |= STATUS_DEVICE_NEEDS_RESET;
        if self.status & STATUS_DRIVER_OK != 0 {
            self.interrupt_status |= INT_CONFIG_CHANGE;
        }
    }

    /// Reset all transport/device negotiation state (Status write of 0).
    fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        for q in &mut self.queues {
            *q = VirtQueue::default();
        }
        self.status = 0;
        self.interrupt_status = 0;
    }

    /// Read a 32-bit register at window-relative `offset`.
    fn read_reg(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => self.device.device_id(),
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                let feats = self.offered_features();
                match self.device_features_sel {
                    0 => (feats & 0xffff_ffff) as u32,
                    1 => (feats >> 32) as u32,
                    _ => 0,
                }
            }
            REG_QUEUE_NUM_MAX => self.selected_queue().map_or(0, |_| QUEUE_SIZE_MAX),
            REG_QUEUE_READY => self
                .selected_queue()
                .map_or(0, |queue| u32::from(queue.ready)),
            REG_INTERRUPT_STATUS => self.interrupt_status,
            REG_STATUS => self.status,
            REG_CONFIG_GENERATION => self.config_generation,
            // QueueSel/Num/Notify, feature selectors, ACK, and address regs are
            // write-only; reads return 0 per the spec.
            _ => 0,
        }
    }

    /// Write a 32-bit `value` to the register at window-relative `offset`.
    fn write_reg(&mut self, offset: u64, value: u32) {
        match offset {
            REG_DEVICE_FEATURES_SEL => {
                self.device_features_sel = value;
            }
            REG_DRIVER_FEATURES => {
                if self.status & STATUS_FEATURES_OK == 0
                    && self.driver_features_sel < FEATURE_WORDS as u32
                {
                    let shift = u64::from(self.driver_features_sel) * 32;
                    let mask = 0xffff_ffffu64 << shift;
                    self.driver_features =
                        (self.driver_features & !mask) | (u64::from(value) << shift);
                }
            }
            REG_DRIVER_FEATURES_SEL => {
                self.driver_features_sel = value;
            }
            REG_QUEUE_SEL => {
                self.queue_sel = value;
            }
            REG_QUEUE_NUM => {
                if let Some(queue) = self.selected_queue_mut() {
                    if !queue.ready {
                        queue.size = if value.is_power_of_two() && value <= QUEUE_SIZE_MAX {
                            value
                        } else {
                            0
                        };
                    }
                }
            }
            REG_QUEUE_READY => {
                if let Some(queue) = self.selected_queue_mut() {
                    queue.ready = value & 1 != 0;
                    if queue.ready
                        && (queue.size == 0
                            || queue.desc_addr % 16 != 0
                            || queue.avail_addr % 2 != 0
                            || queue.used_addr % 4 != 0)
                    {
                        self.needs_reset();
                    }
                }
            }
            REG_QUEUE_NOTIFY => {
                self.notify(value as usize);
            }
            REG_INTERRUPT_ACK => {
                // Write-1-to-clear of the matching interrupt-status bits.
                self.interrupt_status &= !value;
            }
            REG_STATUS => {
                if value == 0 {
                    self.reset();
                } else {
                    let mut status = self.status | value;
                    if status & STATUS_FEATURES_OK != 0
                        && (self.driver_features & !self.offered_features() != 0
                            || self.driver_features & VIRTIO_F_VERSION_1 == 0)
                    {
                        status &= !STATUS_FEATURES_OK;
                    }
                    self.status = status;
                }
            }
            REG_QUEUE_DESC_LOW
            | REG_QUEUE_DESC_HIGH
            | REG_QUEUE_DRIVER_LOW
            | REG_QUEUE_DRIVER_HIGH
            | REG_QUEUE_DEVICE_LOW
            | REG_QUEUE_DEVICE_HIGH => {
                if let Some(queue) = self.selected_queue_mut() {
                    if !queue.ready {
                        let address = match offset {
                            REG_QUEUE_DESC_LOW | REG_QUEUE_DESC_HIGH => &mut queue.desc_addr,
                            REG_QUEUE_DRIVER_LOW | REG_QUEUE_DRIVER_HIGH => &mut queue.avail_addr,
                            _ => &mut queue.used_addr,
                        };
                        if matches!(
                            offset,
                            REG_QUEUE_DESC_HIGH | REG_QUEUE_DRIVER_HIGH | REG_QUEUE_DEVICE_HIGH
                        ) {
                            *address = (*address & 0xffff_ffff) | (u64::from(value) << 32);
                        } else {
                            *address = (*address & !0xffff_ffff) | u64::from(value);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle a QueueNotify: drive the device's queue handler and raise the
    /// used-buffer interrupt if it consumed anything.
    fn notify(&mut self, queue_idx: usize) {
        let required = STATUS_FEATURES_OK | STATUS_DRIVER_OK;
        if queue_idx >= self.queues.len()
            || self.status & required != required
            || self.status & (STATUS_FAILED | STATUS_DEVICE_NEEDS_RESET) != 0
        {
            return;
        }
        let features = self.negotiated_features();
        let mut queue = std::mem::take(&mut self.queues[queue_idx]);
        let before = queue.last_avail_idx;
        let result =
            self.device
                .handle_queue_with_features(queue_idx, &mut queue, &mut self.mem, features);
        let advanced = queue.last_avail_idx != before;
        if advanced {
            let mut flags = [0; 2];
            if self.mem.read(queue.avail_addr, &mut flags) {
                if u16::from_le_bytes(flags) & 1 == 0 {
                    self.interrupt_status |= INT_USED_BUFFER;
                }
            } else {
                self.needs_reset();
            }
        }
        self.queues[queue_idx] = queue;
        if result.is_err() {
            self.needs_reset();
        }
    }
}

impl<M: Mem + Send> MmioDevice for VirtioMmio<M> {
    fn read(&mut self, addr: u64, data: &mut [u8]) {
        let offset = addr.wrapping_sub(self.base);
        if offset >= REG_CONFIG {
            // Device-specific configuration space is byte addressable.
            let cfg_off = offset - REG_CONFIG;
            for (i, out) in data.iter_mut().enumerate() {
                *out = self.device.config_read(cfg_off + i as u64);
            }
            return;
        }
        // All control registers are 32-bit little-endian; service partial /
        // byte-wise accesses by extracting the requested bytes of the word.
        let aligned = offset & !0x3;
        let byte_in_reg = (offset & 0x3) as usize;
        let bytes = self.read_reg(aligned).to_le_bytes();
        for (i, out) in data.iter_mut().enumerate() {
            let pos = byte_in_reg + i;
            *out = if pos < 4 { bytes[pos] } else { 0 };
        }
    }

    fn write(&mut self, addr: u64, data: &[u8]) {
        let offset = addr.wrapping_sub(self.base);
        if offset >= REG_CONFIG {
            let cfg_off = offset - REG_CONFIG;
            for (i, byte) in data.iter().enumerate() {
                self.device.config_write(cfg_off + i as u64, *byte);
            }
            return;
        }
        // Read-modify-write so a sub-word access preserves the other bytes.
        let aligned = offset & !0x3;
        let byte_in_reg = (offset & 0x3) as usize;
        let mut bytes = self.read_reg(aligned).to_le_bytes();
        for (i, byte) in data.iter().enumerate() {
            let pos = byte_in_reg + i;
            if pos < 4 {
                bytes[pos] = *byte;
            }
        }
        self.write_reg(aligned, u32::from_le_bytes(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::MmioDevice;

    /// A minimal device for exercising the transport in isolation.
    struct DummyDevice;
    impl VirtioDevice for DummyDevice {
        fn device_id(&self) -> u32 {
            0x1234
        }
        fn device_features(&self) -> u64 {
            // Offer an arbitrary low bit and a high (word 1) bit to exercise
            // the feature-word selector.
            (1 << 5) | (1 << 40)
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn config_read(&self, _offset: u64) -> u8 {
            0
        }
        fn handle_queue(&mut self, _idx: usize, _q: &mut VirtQueue, _mem: &mut dyn Mem) {}
    }

    const BASE: u64 = 0xd000_0000;

    fn dev() -> VirtioMmio<VecMem> {
        VirtioMmio::new(BASE, Box::new(DummyDevice), VecMem::new(0))
    }

    fn read32(d: &mut VirtioMmio<VecMem>, off: u64) -> u32 {
        let mut buf = [0u8; 4];
        d.read(BASE + off, &mut buf);
        u32::from_le_bytes(buf)
    }

    fn write32(d: &mut VirtioMmio<VecMem>, off: u64, value: u32) {
        d.write(BASE + off, &value.to_le_bytes());
    }

    #[test]
    fn magic_version_vendor() {
        let mut d = dev();
        assert_eq!(read32(&mut d, REG_MAGIC_VALUE), VIRTIO_MMIO_MAGIC);
        assert_eq!(read32(&mut d, REG_MAGIC_VALUE), 0x7472_6976); // "virt"
        assert_eq!(read32(&mut d, REG_VERSION), 2);
        assert_eq!(read32(&mut d, REG_VENDOR_ID), VIRTIO_MMIO_VENDOR);
        assert_eq!(read32(&mut d, REG_VENDOR_ID), 0x554d_4551); // "QEMU"
    }

    #[test]
    fn device_id_reports_device() {
        let mut d = dev();
        assert_eq!(read32(&mut d, REG_DEVICE_ID), 0x1234);
    }

    #[test]
    fn device_features_word_select() {
        let mut d = dev();
        // Word 0: device bit 5, no VERSION_1 (that lives in word 1).
        write32(&mut d, REG_DEVICE_FEATURES_SEL, 0);
        assert_eq!(read32(&mut d, REG_DEVICE_FEATURES), 1 << 5);
        // Word 1: device bit 40 (=> bit 8 of word 1) plus VERSION_1 (bit 32 =>
        // bit 0 of word 1).
        write32(&mut d, REG_DEVICE_FEATURES_SEL, 1);
        assert_eq!(read32(&mut d, REG_DEVICE_FEATURES), (1 << 8) | 1);
    }

    #[test]
    fn feature_negotiation_round_trips() {
        let mut d = dev();
        // Driver accepts bit 5 (word 0) and VERSION_1 (word 1, bit 0).
        write32(&mut d, REG_DRIVER_FEATURES_SEL, 0);
        write32(&mut d, REG_DRIVER_FEATURES, 1 << 5);
        write32(&mut d, REG_DRIVER_FEATURES_SEL, 1);
        write32(&mut d, REG_DRIVER_FEATURES, 1);
        write32(
            &mut d,
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        assert_eq!(d.negotiated_features(), (1 << 5) | VIRTIO_F_VERSION_1);
    }

    #[test]
    fn feature_negotiation_masks_unoffered() {
        let mut d = dev();
        // Driver tries to accept bit 6 (word 0), which the device never offered.
        write32(&mut d, REG_DRIVER_FEATURES_SEL, 0);
        write32(&mut d, REG_DRIVER_FEATURES, 1 << 6);
        assert_eq!(d.negotiated_features() & (1 << 6), 0);
    }

    #[test]
    fn status_bits_accumulate_and_reset() {
        let mut d = dev();
        write32(&mut d, REG_DRIVER_FEATURES_SEL, 1);
        write32(&mut d, REG_DRIVER_FEATURES, 1);
        write32(&mut d, REG_STATUS, STATUS_ACKNOWLEDGE);
        write32(&mut d, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        write32(
            &mut d,
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        assert_eq!(
            read32(&mut d, REG_STATUS),
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
        );
        // Writing 0 triggers a full reset.
        write32(&mut d, REG_STATUS, 0);
        assert_eq!(read32(&mut d, REG_STATUS), 0);
    }

    #[test]
    fn queue_selection_num_max_and_ready() {
        let mut d = dev();
        // Select queue 0 and check the advertised max.
        write32(&mut d, REG_QUEUE_SEL, 0);
        assert_eq!(read32(&mut d, REG_QUEUE_NUM_MAX), QUEUE_SIZE_MAX);

        // Program a valid (power-of-two) size and mark the queue ready.
        write32(&mut d, REG_QUEUE_NUM, 64);
        write32(&mut d, REG_QUEUE_READY, 1);
        assert_eq!(read32(&mut d, REG_QUEUE_READY), 1);
        assert_eq!(d.selected_queue().unwrap().size, 64);
        assert!(d.selected_queue().unwrap().ready);

        // A non-power-of-two size is rejected (stays at the prior value? no —
        // we set it to 0 to keep the queue inert).
        write32(&mut d, REG_QUEUE_READY, 0);
        write32(&mut d, REG_QUEUE_NUM, 100);
        assert_eq!(d.selected_queue().unwrap().size, 0);
    }

    #[test]
    fn queue_address_registers_assemble_64bit() {
        let mut d = dev();
        write32(&mut d, REG_QUEUE_SEL, 0);
        write32(&mut d, REG_QUEUE_DESC_LOW, 0x1111_2222);
        write32(&mut d, REG_QUEUE_DESC_HIGH, 0x3333_4444);
        write32(&mut d, REG_QUEUE_DRIVER_LOW, 0xaaaa_bbbb);
        write32(&mut d, REG_QUEUE_DRIVER_HIGH, 0xcccc_dddd);
        write32(&mut d, REG_QUEUE_DEVICE_LOW, 0x0102_0304);
        write32(&mut d, REG_QUEUE_DEVICE_HIGH, 0x0506_0708);
        let q = d.selected_queue().unwrap();
        assert_eq!(q.desc_addr, 0x3333_4444_1111_2222);
        assert_eq!(q.avail_addr, 0xcccc_dddd_aaaa_bbbb);
        assert_eq!(q.used_addr, 0x0506_0708_0102_0304);
    }

    #[test]
    fn interrupt_ack_write_one_to_clear() {
        let mut d = dev();
        // Force a pending interrupt then ack it.
        d.interrupt_status = INT_USED_BUFFER | INT_CONFIG_CHANGE;
        assert_eq!(read32(&mut d, REG_INTERRUPT_STATUS), 0b11);
        write32(&mut d, REG_INTERRUPT_ACK, INT_USED_BUFFER);
        assert_eq!(read32(&mut d, REG_INTERRUPT_STATUS), INT_CONFIG_CHANGE);
        write32(&mut d, REG_INTERRUPT_ACK, INT_CONFIG_CHANGE);
        assert_eq!(read32(&mut d, REG_INTERRUPT_STATUS), 0);
    }

    #[test]
    fn write_only_registers_read_zero() {
        let mut d = dev();
        write32(&mut d, REG_QUEUE_SEL, 7);
        // QueueSel is write-only: a read returns 0, not the written value.
        assert_eq!(read32(&mut d, REG_QUEUE_SEL), 0);
    }

    #[test]
    fn byte_wise_register_access_reassembles() {
        let mut d = dev();
        // Read MagicValue one byte at a time; should reassemble to "virt".
        let mut assembled = [0u8; 4];
        for (i, b) in assembled.iter_mut().enumerate() {
            let mut one = [0u8; 1];
            d.read(BASE + REG_MAGIC_VALUE + i as u64, &mut one);
            *b = one[0];
        }
        assert_eq!(u32::from_le_bytes(assembled), VIRTIO_MMIO_MAGIC);
    }
}
