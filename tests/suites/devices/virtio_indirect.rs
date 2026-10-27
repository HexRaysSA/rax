//! Exercise the owning split-ring and block transport implementation.
pub use rax::devices::bus;
#[path = "../../../src/devices/virtio/mod.rs"]
pub mod virtio;
pub mod devices {
    pub use super::{bus, virtio};
}

use bus::MmioDevice;
use std::sync::{Arc, Mutex};
use virtio::blk::*;
use virtio::*;
const BASE: u64 = 0x1000_0000;
const INDIRECT: u64 = 1 << 28;
const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const HEADER: u64 = 0x4000;
const DATA: u64 = 0x5000;
const STATUS: u64 = 0x7000;
const TABLE: u64 = 0x8003;
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    fault: Option<(bool, u64)>,
    trace: Vec<(bool, u64, usize)>,
}
#[derive(Clone)]
struct Memory(Arc<Mutex<State>>);
impl Memory {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            bytes: vec![0; 0x20000],
            ..State::default()
        })))
    }
    fn put(&self, address: u64, bytes: &[u8]) {
        let mut state = self.0.lock().unwrap();
        state.bytes[address as usize..address as usize + bytes.len()].copy_from_slice(bytes);
    }
    fn get(&self, address: u64, length: usize) -> Vec<u8> {
        self.0.lock().unwrap().bytes[address as usize..address as usize + length].to_vec()
    }
    fn u16(&self, address: u64) -> u16 {
        u16::from_le_bytes(self.get(address, 2).try_into().unwrap())
    }
    fn u32(&self, address: u64) -> u32 {
        u32::from_le_bytes(self.get(address, 4).try_into().unwrap())
    }
    fn trace(&self) -> Vec<(bool, u64, usize)> {
        self.0.lock().unwrap().trace.clone()
    }
    fn clear_trace(&self) {
        self.0.lock().unwrap().trace.clear();
    }
    fn fail(&self, write: bool, address: u64) {
        self.0.lock().unwrap().fault = Some((write, address));
    }
    fn clear_fault(&self) {
        self.0.lock().unwrap().fault = None;
    }
    fn access(&self, address: u64, bytes: &mut [u8], write: bool) -> bool {
        let mut state = self.0.lock().unwrap();
        state.trace.push((write, address, bytes.len()));
        if state.fault == Some((write, address)) {
            return false;
        }
        let Ok(start) = usize::try_from(address) else {
            return false;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        if end > state.bytes.len() {
            return false;
        }
        if write {
            state.bytes[start..end].copy_from_slice(bytes);
        } else {
            bytes.copy_from_slice(&state.bytes[start..end]);
        }
        true
    }
}
impl Mem for Memory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        self.access(address, bytes, false)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        self.access(address, &mut bytes.to_vec(), true)
    }
}
struct Host {
    memory: Memory,
    transport: VirtioMmio<Memory>,
    submitted: u16,
}
impl Host {
    fn new(features: u64) -> Self {
        let memory = Memory::new();
        let disk = (0..4096).map(|n| (n as u8).wrapping_mul(37)).collect();
        let transport = VirtioMmio::new(BASE, Box::new(VirtioBlk::new(disk)), memory.clone());
        let mut host = Self {
            memory,
            transport,
            submitted: 0,
        };
        host.configure(features);
        host
    }
    fn write(&mut self, offset: u64, value: u32) {
        self.transport.write(BASE + offset, &value.to_le_bytes());
    }
    fn read(&mut self, offset: u64) -> u32 {
        let mut b = [0; 4];
        self.transport.read(BASE + offset, &mut b);
        u32::from_le_bytes(b)
    }
    fn configure(&mut self, features: u64) {
        self.write(REG_STATUS, 0);
        self.write(REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        self.write(REG_DRIVER_FEATURES_SEL, 0);
        self.write(REG_DRIVER_FEATURES, features as u32);
        self.write(REG_DRIVER_FEATURES_SEL, 1);
        self.write(REG_DRIVER_FEATURES, 1);
        self.write(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        assert_ne!(self.read(REG_STATUS) & STATUS_FEATURES_OK, 0);
        self.write(REG_QUEUE_SEL, 0);
        self.write(REG_QUEUE_NUM, 16);
        self.write(REG_QUEUE_DESC_LOW, DESC as u32);
        self.write(REG_QUEUE_DRIVER_LOW, AVAIL as u32);
        self.write(REG_QUEUE_DEVICE_LOW, USED as u32);
        self.write(REG_QUEUE_READY, 1);
        self.write(
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        self.memory.put(AVAIL, &[0; 38]);
        self.memory.put(USED, &[0; 134]);
        self.submitted = 0;
    }
    fn header(&self, kind: u32, sector: u64) {
        let mut h = [0; 16];
        h[..4].copy_from_slice(&kind.to_le_bytes());
        h[8..].copy_from_slice(&sector.to_le_bytes());
        self.memory.put(HEADER, &h);
        self.memory.put(STATUS, &[0xff]);
    }
    fn descriptor(&self, table: u64, index: u16, address: u64, length: u32, flags: u16, next: u16) {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&address.to_le_bytes());
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..].copy_from_slice(&next.to_le_bytes());
        self.memory.put(table + u64::from(index) * 16, &bytes);
    }
    fn direct(&self, kind: u32, sector: u64) {
        self.header(kind, sector);
        self.descriptor(DESC, 0, HEADER, 16, 1, 1);
        self.descriptor(DESC, 1, DATA, 512, if kind == 0 { 3 } else { 1 }, 2);
        self.descriptor(DESC, 2, STATUS, 1, 2, 0);
    }
    fn indirect(&self, kind: u32, mixed: bool, wrapper_write: bool) {
        self.header(kind, 0);
        if mixed {
            self.descriptor(DESC, 0, HEADER, 16, 1, 1);
            self.descriptor(DESC, 1, TABLE, 32, 4 | if wrapper_write { 2 } else { 0 }, 0);
            self.descriptor(TABLE, 0, DATA, 512, if kind == 0 { 3 } else { 1 }, 1);
            self.descriptor(TABLE, 1, STATUS, 1, 2, 0);
        } else {
            self.descriptor(DESC, 0, TABLE, 48, 4 | if wrapper_write { 2 } else { 0 }, 0);
            self.descriptor(TABLE, 0, HEADER, 16, 1, 1);
            self.descriptor(TABLE, 1, DATA, 512, if kind == 0 { 3 } else { 1 }, 2);
            self.descriptor(TABLE, 2, STATUS, 1, 2, 0);
        }
    }
    fn enqueue(&mut self, head: u16) {
        self.memory.put(
            AVAIL + 4 + u64::from(self.submitted % 16) * 2,
            &head.to_le_bytes(),
        );
        self.submitted = self.submitted.wrapping_add(1);
        self.memory.put(AVAIL + 2, &self.submitted.to_le_bytes());
    }
    fn kick(&mut self) {
        self.write(REG_QUEUE_NOTIFY, 0);
    }
    fn submit(&mut self) {
        self.enqueue(0);
        self.kick();
    }
    fn assert_ok(&mut self, used: u16, length: u32) {
        assert_eq!(self.memory.u16(USED + 2), used);
        assert_eq!(
            self.memory.u32(USED + 4 + u64::from((used - 1) % 16) * 8),
            0
        );
        assert_eq!(
            self.memory.u32(USED + 8 + u64::from((used - 1) % 16) * 8),
            length
        );
        assert_eq!(self.memory.get(STATUS, 1), [0]);
        assert_eq!(self.read(REG_STATUS) & STATUS_DEVICE_NEEDS_RESET, 0);
    }
    fn assert_reset(&mut self) {
        assert_ne!(self.read(REG_STATUS) & STATUS_DEVICE_NEEDS_RESET, 0);
        assert_ne!(self.read(REG_INTERRUPT_STATUS) & INT_CONFIG_CHANGE, 0);
        assert_eq!(self.read(REG_QUEUE_READY), 1);
        let trace = self.memory.trace();
        self.kick();
        assert_eq!(
            self.memory.trace(),
            trace,
            "fatal request must not be replayed"
        );
    }
}
#[test]
fn indirect_read_and_direct_prefix_accept_unaligned_table_and_ignore_wrapper_write() {
    for mixed in [false, true] {
        for write in [false, true] {
            let mut h = Host::new(INDIRECT);
            h.indirect(0, mixed, write);
            h.submit();
            h.assert_ok(1, 513);
            assert_eq!(
                h.memory.get(DATA, 512),
                (0..512)
                    .map(|n| (n as u8).wrapping_mul(37))
                    .collect::<Vec<_>>()
            );
        }
    }
}
#[test]
fn indirect_write_changes_only_selected_sector_and_reads_back_through_device() {
    let mut h = Host::new(INDIRECT);
    h.indirect(1, false, false);
    h.memory.put(DATA, &[0xab; 512]);
    h.submit();
    h.assert_ok(1, 1);
    h.direct(0, 0);
    h.submit();
    h.assert_ok(2, 513);
    assert_eq!(h.memory.get(DATA, 512), [0xab; 512]);
    h.direct(0, 1);
    h.submit();
    h.assert_ok(3, 513);
    assert_eq!(
        h.memory.get(DATA, 512),
        (0..512)
            .map(|n| (n as u8).wrapping_mul(37))
            .collect::<Vec<_>>()
    );
}
#[test]
fn fragmented_header_data_and_status_use_logical_stream_boundaries() {
    for kind in [0, 1] {
        for split in [1u32, 4, 7, 15] {
            let mut h = Host::new(INDIRECT);
            h.header(kind, 0);
            let header = h.memory.get(HEADER, 16);
            h.memory.put(0x9000, &header[..split as usize]);
            let mut suffix = header[split as usize..].to_vec();
            if kind == 1 {
                suffix.extend([0x6c; 512]);
            }
            h.memory.put(0xa000, &suffix);
            h.descriptor(DESC, 0, TABLE, 48, 4, 0);
            h.descriptor(TABLE, 0, 0x9000, split, 1, 1);
            h.descriptor(TABLE, 1, 0xa000, suffix.len() as u32, 1, 2);
            if kind == 0 {
                h.descriptor(TABLE, 2, DATA, 513, 2, 0);
            } else {
                h.descriptor(TABLE, 2, STATUS, 1, 2, 0);
            }
            h.submit();
            assert_eq!(h.memory.u16(USED + 2), 1);
            assert_eq!(
                h.memory.get(if kind == 0 { DATA + 512 } else { STATUS }, 1),
                [0]
            );
            assert_eq!(h.memory.u32(USED + 8), if kind == 0 { 513 } else { 1 });
            if kind == 0 {
                assert_eq!(
                    h.memory.get(DATA, 512),
                    (0..512)
                        .map(|n| (n as u8).wrapping_mul(37))
                        .collect::<Vec<_>>()
                );
            } else {
                h.direct(0, 0);
                h.submit();
                h.assert_ok(2, 513);
                assert_eq!(h.memory.get(DATA, 512), [0x6c; 512]);
            }
        }
    }
}
#[test]
fn unnegotiated_indirect_never_reaches_payload_or_publishes_used() {
    let mut h = Host::new(0);
    h.indirect(1, false, false);
    h.memory.clear_trace();
    h.submit();
    h.assert_reset();
    assert_eq!(h.memory.u16(USED + 2), 0);
    assert!(
        !h.memory
            .trace()
            .iter()
            .any(|(_, a, _)| *a == HEADER || *a == DATA || *a == TABLE)
    );
}
#[test]
fn malformed_indirect_metadata_is_validated_before_any_payload() {
    for bad in 0..8 {
        let mut h = Host::new(INDIRECT);
        h.indirect(1, false, false);
        match bad {
            0 => h.descriptor(DESC, 0, TABLE, 48, 5, 1),
            1 => h.descriptor(DESC, 0, TABLE, 0, 4, 0),
            2 => h.descriptor(DESC, 0, TABLE, 47, 4, 0),
            3 => h.descriptor(TABLE, 1, TABLE, 16, 4, 0),
            4 => h.descriptor(TABLE, 1, DATA, 512, 1, 1),
            5 => h.descriptor(TABLE, 1, DATA, 512, 1, 3),
            6 => {
                h.descriptor(TABLE, 0, HEADER, 16, 3, 1);
                h.descriptor(TABLE, 1, DATA, 512, 1, 2);
            }
            _ => h.descriptor(DESC, 0, u64::MAX - 15, 32, 4, 0),
        }
        h.memory.clear_trace();
        h.submit();
        h.assert_reset();
        assert_eq!(h.memory.u16(USED + 2), 0);
        assert!(
            !h.memory
                .trace()
                .iter()
                .any(|(_, a, _)| *a == HEADER || *a == DATA || *a == STATUS)
        );
    }
}
#[test]
fn direct_bad_index_cycle_and_dma_fault_do_not_invoke_block_request() {
    for bad in 0..4 {
        let mut h = Host::new(0);
        h.direct(1, 0);
        match bad {
            0 => h.descriptor(DESC, 1, DATA, 512, 1, 16),
            1 => h.descriptor(DESC, 1, DATA, 512, 1, 0),
            2 => h.memory.fail(false, DESC + 16),
            _ => h.memory.put(AVAIL + 2, &17u16.to_le_bytes()),
        }
        h.memory.clear_trace();
        if bad == 3 {
            h.kick()
        } else {
            h.submit()
        };
        h.assert_reset();
        assert_eq!(h.memory.u16(USED + 2), 0);
        assert!(
            !h.memory
                .trace()
                .iter()
                .any(|(_, a, _)| *a == HEADER || *a == DATA || *a == STATUS)
        );
    }
}
#[test]
fn oversized_unused_indirect_entries_do_not_bound_reachable_chain() {
    let mut h = Host::new(INDIRECT);
    h.indirect(0, false, false);
    h.descriptor(DESC, 0, TABLE, 32 * 16, 4, 0);
    h.memory.fail(false, TABLE + 48);
    h.submit();
    h.assert_ok(1, 513);
}
#[test]
fn complete_request_is_not_replayed_after_status_entry_or_index_dma_failure() {
    for address in [STATUS, USED + 4, USED + 2] {
        let mut h = Host::new(0);
        h.direct(1, 0);
        h.memory.put(DATA, &[0x7d; 512]);
        h.memory.fail(true, address);
        h.submit();
        h.assert_reset();
        assert_eq!(h.memory.u16(USED + 2), 0);
        h.memory.clear_fault();
        h.configure(0);
        h.direct(0, 0);
        h.submit();
        h.assert_ok(1, 513);
        assert_eq!(h.memory.get(DATA, 512), [0x7d; 512]);
    }
}
#[test]
fn late_write_source_fault_preserves_all_media_and_completes_ioerr() {
    let mut h = Host::new(0);
    h.header(1, 0);
    h.descriptor(DESC, 0, HEADER, 16, 1, 1);
    h.descriptor(DESC, 1, DATA, 256, 1, 2);
    h.descriptor(DESC, 2, DATA + 256, 256, 1, 3);
    h.descriptor(DESC, 3, STATUS, 1, 2, 0);
    h.memory.put(DATA, &[0x99; 512]);
    h.memory.fail(false, DATA + 256);
    h.submit();
    assert_eq!(h.memory.get(STATUS, 1), [1]);
    assert_eq!(h.memory.u16(USED + 2), 1);
    assert_eq!(h.read(REG_STATUS) & STATUS_DEVICE_NEEDS_RESET, 0);
    h.memory.clear_fault();
    h.direct(0, 0);
    h.submit();
    h.assert_ok(2, 513);
    assert_eq!(
        h.memory.get(DATA, 512),
        (0..512)
            .map(|n| (n as u8).wrapping_mul(37))
            .collect::<Vec<_>>()
    );
}
#[test]
fn late_read_destination_fault_reports_reset_without_false_completion() {
    let mut h = Host::new(0);
    h.header(0, 0);
    h.descriptor(DESC, 0, HEADER, 16, 1, 1);
    h.descriptor(DESC, 1, DATA, 256, 3, 2);
    h.descriptor(DESC, 2, DATA + 256, 256, 3, 3);
    h.descriptor(DESC, 3, STATUS, 1, 2, 0);
    h.memory.put(DATA, &[0xee; 512]);
    h.memory.fail(true, DATA + 256);
    h.submit();
    h.assert_reset();
    assert_eq!(h.memory.u16(USED + 2), 0);
    assert_eq!(h.memory.get(STATUS, 1), [0xff]);
    assert_eq!(
        h.memory.get(DATA, 256),
        (0..256)
            .map(|n| (n as u8).wrapping_mul(37))
            .collect::<Vec<_>>()
    );
    assert_eq!(h.memory.get(DATA + 256, 256), [0xee; 256]);
}
#[test]
fn payload_and_status_precede_used_entry_and_final_index_publication() {
    let mut h = Host::new(0);
    h.direct(0, 0);
    h.memory.clear_trace();
    h.submit();
    h.assert_ok(1, 513);
    let writes = h
        .memory
        .trace()
        .into_iter()
        .filter(|(w, _, _)| *w)
        .collect::<Vec<_>>();
    assert_eq!(
        writes,
        [
            (true, DATA, 512),
            (true, STATUS, 1),
            (true, USED + 4, 8),
            (true, USED + 2, 2)
        ]
    );
}
#[test]
fn negotiated_features_are_immutable_and_invalid_selector_does_not_alias_high_word() {
    let mut h = Host::new(INDIRECT);
    h.write(REG_DRIVER_FEATURES_SEL, 0);
    h.write(REG_DRIVER_FEATURES, 0);
    h.indirect(0, false, false);
    h.submit();
    h.assert_ok(1, 513);
    h.write(REG_STATUS, 0);
    h.write(REG_DRIVER_FEATURES_SEL, 2);
    h.write(REG_DRIVER_FEATURES, 1);
    h.write(
        REG_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
    );
    assert_eq!(h.read(REG_STATUS) & STATUS_FEATURES_OK, 0);
}
#[test]
fn unsupported_features_clear_features_ok_and_notify_has_no_dma() {
    for feature in [1u32, 1 << 27, 1 << 31] {
        let mut h = Host::new(0);
        h.write(REG_STATUS, 0);
        h.write(REG_DRIVER_FEATURES_SEL, 0);
        h.write(REG_DRIVER_FEATURES, feature);
        h.write(REG_DRIVER_FEATURES_SEL, 1);
        h.write(REG_DRIVER_FEATURES, 1);
        h.write(REG_STATUS, 15);
        assert_eq!(h.read(REG_STATUS) & STATUS_FEATURES_OK, 0);
        h.memory.clear_trace();
        h.kick();
        assert!(h.memory.trace().is_empty());
    }
}
#[test]
fn no_dma_before_driver_ok_ready_or_after_failed_and_reset_clears_transport() {
    for blocked in 0..4 {
        let mut h = Host::new(INDIRECT);
        h.direct(0, 0);
        h.enqueue(0);
        match blocked {
            0 => {
                h.write(REG_STATUS, 0);
                h.write(REG_STATUS, 3);
            }
            1 => h.write(REG_QUEUE_READY, 0),
            2 => h.write(REG_STATUS, STATUS_FAILED),
            _ => h.write(REG_STATUS, 0),
        }
        h.memory.clear_trace();
        h.kick();
        assert!(h.memory.trace().is_empty());
        assert_eq!(h.memory.u16(USED + 2), 0);
        h.write(REG_STATUS, 0);
        assert_eq!(h.read(REG_STATUS), 0);
        assert_eq!(h.read(REG_QUEUE_READY), 0);
        assert_eq!(h.read(REG_INTERRUPT_STATUS), 0);
        assert_eq!(h.transport.negotiated_features(), 0);
    }
}
#[test]
fn invalid_queue_selection_does_not_mutate_queue_zero_and_live_fields_are_immutable() {
    let mut h = Host::new(0);
    h.write(REG_QUEUE_SEL, u32::MAX);
    assert_eq!(h.read(REG_QUEUE_NUM_MAX), 0);
    assert_eq!(h.read(REG_QUEUE_READY), 0);
    h.write(REG_QUEUE_NUM, 0);
    h.write(REG_QUEUE_READY, 1);
    h.write(REG_QUEUE_DESC_LOW, 0);
    h.write(REG_QUEUE_SEL, 0);
    assert_eq!(h.read(REG_QUEUE_READY), 1);
    h.write(REG_QUEUE_NUM, 3);
    h.write(REG_QUEUE_DESC_LOW, 1);
    h.write(REG_QUEUE_DRIVER_LOW, 1);
    h.write(REG_QUEUE_DEVICE_LOW, 1);
    h.direct(0, 0);
    h.submit();
    h.assert_ok(1, 513);
}
#[test]
fn suppressed_used_interrupt_and_ack_preserve_exact_pending_bits() {
    let mut h = Host::new(0);
    h.direct(0, 0);
    h.memory.put(AVAIL, &1u16.to_le_bytes());
    h.submit();
    h.assert_ok(1, 513);
    assert_eq!(h.read(REG_INTERRUPT_STATUS), 0);
    h.memory.put(AVAIL, &0u16.to_le_bytes());
    h.submit();
    assert_eq!(h.read(REG_INTERRUPT_STATUS), INT_USED_BUFFER);
    h.write(REG_INTERRUPT_ACK, INT_CONFIG_CHANGE);
    assert_eq!(h.read(REG_INTERRUPT_STATUS), INT_USED_BUFFER);
    h.write(REG_INTERRUPT_ACK, INT_USED_BUFFER);
    assert_eq!(h.read(REG_INTERRUPT_STATUS), 0);
}
#[test]
fn block_id_can_span_writable_descriptors_and_shared_final_status_buffer() {
    let mut h = Host::new(INDIRECT);
    h.header(8, 0);
    h.descriptor(DESC, 0, HEADER, 16, 1, 1);
    h.descriptor(DESC, 1, DATA, 7, 3, 2);
    h.descriptor(DESC, 2, DATA + 7, 14, 2, 0);
    h.submit();
    assert_eq!(h.memory.u16(USED + 2), 1);
    assert_eq!(h.memory.u32(USED + 8), 21);
    assert_eq!(
        h.memory.get(DATA, 20),
        b"rax-virtio-blk\0\0\0\0\0\0".to_vec()
    );
    assert_eq!(h.memory.get(DATA + 20, 1), [0]);
}
#[test]
fn sector_overflow_nonsector_data_and_read_only_requests_return_ioerr() {
    for (sector, length) in [(u64::MAX, 512), (0, 511), (8, 512)] {
        let mut h = Host::new(0);
        h.direct(0, sector);
        h.descriptor(DESC, 1, DATA, length, 3, 2);
        h.submit();
        assert_eq!(h.memory.get(STATUS, 1), [1]);
        assert_eq!(h.memory.u32(USED + 8), 1);
    }
    let mut disk = VirtioBlk::with_sectors(1);
    disk.set_read_only(true);
    let mut mem = VecMem::new(1024);
    mem.bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    mem.bytes[16..528].fill(0xab);
    let chain = DescriptorChain {
        head: 0,
        descriptors: vec![
            Descriptor {
                addr: 0,
                len: 528,
                flags: 0,
                next: 0,
            },
            Descriptor {
                addr: 600,
                len: 1,
                flags: 2,
                next: 0,
            },
        ],
    };
    assert_eq!(disk.handle_chain(&chain, &mut mem), 1);
    assert_eq!(mem.bytes[600], 1);
    assert_eq!(disk.disk(), [0; 512]);
}

#[test]
fn queue_byte_limit_accepts_exactly_four_gibibytes_and_rejects_overflow() {
    for extra in [1u32, 2] {
        let h = Host::new(0);
        h.descriptor(DESC, 0, 0, u32::MAX, 1, 1);
        h.descriptor(DESC, 1, 0, extra, 0, 0);
        h.memory.put(AVAIL + 2, &1u16.to_le_bytes());
        let mut queue = VirtQueue {
            size: 16,
            ready: true,
            desc_addr: DESC,
            avail_addr: AVAIL,
            used_addr: USED,
            last_avail_idx: 0,
        };
        let mut memory = h.memory.clone();
        let mut invoked = 0;
        let completed = queue.process(&mut memory, |chain, _| {
            invoked += 1;
            assert_eq!(
                chain
                    .descriptors
                    .iter()
                    .map(|d| u64::from(d.len))
                    .sum::<u64>(),
                1u64 << 32
            );
            0
        });
        assert_eq!(invoked, if extra == 1 { 1 } else { 0 });
        assert_eq!(completed, invoked);
        assert_eq!(queue.ready, extra == 1);
    }
}
#[test]
fn overlong_reachable_indirect_chain_is_rejected_even_with_zero_byte_buffers() {
    let mut h = Host::new(INDIRECT);
    h.header(0, 0);
    h.descriptor(DESC, 0, TABLE, 17 * 16, 4, 0);
    for i in 0..17 {
        h.descriptor(TABLE, i, 0, 0, if i == 16 { 0 } else { 1 }, i + 1);
    }
    h.memory.clear_trace();
    h.submit();
    h.assert_reset();
    assert_eq!(h.memory.u16(USED + 2), 0);
    assert!(!h.memory.trace().iter().any(|(w, _, _)| *w));
}
#[test]
fn queue_indices_wrap_without_trusting_guest_used_index() {
    let mut h = Host::new(0);
    h.header(4, 0);
    h.descriptor(DESC, 0, HEADER, 16, 1, 1);
    h.descriptor(DESC, 1, STATUS, 1, 2, 0);
    h.memory.put(USED + 2, &0x1234u16.to_le_bytes());
    for i in 1..=65538u32 {
        h.memory.clear_trace();
        h.submit();
        assert_eq!(h.memory.u16(USED + 2), i as u16);
        assert_eq!(h.memory.get(STATUS, 1), [0]);
    }
    assert_eq!(h.read(REG_STATUS) & STATUS_DEVICE_NEEDS_RESET, 0);
}

/// Independent guest records are replayed through the owning source modules.
#[derive(Default)]
pub struct ReferenceReport {
    pub cases: usize,
    pub requests: usize,
    pub frame_bytes: usize,
    pub payload_bytes: usize,
    pub media_bytes: usize,
    pub capability_differences: usize,
    pub reference_difference_cases: usize,
    pub shared_exact_cases: usize,
    pub shared_requests: usize,
    pub shared_payload_bytes: usize,
    pub shared_media_bytes: usize,
    pub failed: usize,
}
struct Wire<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Wire<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self.offset.checked_add(length).unwrap();
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        bytes
    }
    fn word(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
}
#[derive(Clone)]
struct PhysicalMemory(Memory);
impl Mem for PhysicalMemory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        address
            .checked_sub(0x4010_0000)
            .is_some_and(|offset| self.0.read(offset, bytes))
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        address
            .checked_sub(0x4010_0000)
            .is_some_and(|offset| self.0.write(offset, bytes))
    }
}
fn wire_write(transport: &mut VirtioMmio<PhysicalMemory>, offset: u64, value: u32) {
    transport.write(BASE + offset, &value.to_le_bytes());
}
fn wire_read(transport: &mut VirtioMmio<PhysicalMemory>, offset: u64) -> u32 {
    let mut bytes = [0; 4];
    transport.read(BASE + offset, &mut bytes);
    u32::from_le_bytes(bytes)
}
pub fn compare_reference(folder: &std::path::Path) -> ReferenceReport {
    let mut report = ReferenceReport::default();
    for index in 0..16 {
        let result = std::panic::catch_unwind(|| {
            let case = folder.join(format!("case-{index:02}"));
            let input = std::fs::read(case.join("input.bin")).unwrap();
            let expected = std::fs::read(case.join("expected.bin")).unwrap();
            let records = std::fs::read(case.join("records.bin")).unwrap();
            let media = std::fs::read(case.join("disk.raw")).unwrap();
            let mut wire = Wire {
                bytes: &input,
                offset: 0,
            };
            assert_eq!(wire.take(8), b"VIOIN001");
            let features = wire.word();
            let count = wire.word();
            let mut reference = Wire {
                bytes: &records,
                offset: 0,
            };
            assert_eq!(reference.take(8), b"RAXVIOI1");
            assert_eq!(reference.word(), count);
            let ref_features = u64::from(reference.word()) | u64::from(reference.word()) << 32;
            let ref_max = reference.word();
            let required = u64::from(features) | (1 << 32);
            assert_eq!(ref_features & required, required);
            assert!(ref_max >= 16);
            let reference_difference = [2, 4, 12, 14].contains(&index);
            if [2, 4, 14].contains(&index) {
                assert_eq!(&records[24..], b"VIOFAIL!");
                assert_eq!(
                    media,
                    (0..4096)
                        .map(|n| (n as u8).wrapping_mul(37))
                        .collect::<Vec<_>>()
                );
            } else if index == 12 {
                let mut observed = expected.clone();
                let end = observed.len();
                observed[end - 5..].fill(0xee);
                assert_eq!(&records[24..], observed);
            } else {
                assert_eq!(&records[24..], expected);
            }
            // The four recorded differences use the primary contract for the
            // product, while every remaining case requires byte-exact QEMU data.
            let canonical = [&records[..24], &expected].concat();
            let mut reference = Wire {
                bytes: if reference_difference {
                    &canonical
                } else {
                    &records
                },
                offset: 24,
            };
            let memory = Memory::new();
            let disk = (0..4096).map(|n| (n as u8).wrapping_mul(37)).collect();
            let mut transport = VirtioMmio::new(
                BASE,
                Box::new(VirtioBlk::new(disk)),
                PhysicalMemory(memory.clone()),
            );
            wire_write(&mut transport, REG_DEVICE_FEATURES_SEL, 0);
            let low = wire_read(&mut transport, REG_DEVICE_FEATURES);
            wire_write(&mut transport, REG_DEVICE_FEATURES_SEL, 1);
            let high = wire_read(&mut transport, REG_DEVICE_FEATURES);
            let product_features = u64::from(low) | u64::from(high) << 32;
            assert_eq!(product_features & required, required);
            let product_max = wire_read(&mut transport, REG_QUEUE_NUM_MAX);
            assert!(product_max >= 16);
            let capability_difference =
                usize::from(ref_features != product_features || ref_max != product_max);
            for (register, value) in [
                (REG_STATUS, 3),
                (REG_DRIVER_FEATURES_SEL, 0),
                (REG_DRIVER_FEATURES, features),
                (REG_DRIVER_FEATURES_SEL, 1),
                (REG_DRIVER_FEATURES, 1),
                (REG_STATUS, 11),
                (REG_QUEUE_NUM, 16),
                (REG_QUEUE_DESC_LOW, 0x40100000),
                (REG_QUEUE_DRIVER_LOW, 0x40101000),
                (REG_QUEUE_DEVICE_LOW, 0x40102000),
                (REG_QUEUE_READY, 1),
                (REG_STATUS, 15),
            ] {
                wire_write(&mut transport, register, value);
            }
            let mut compared = 0;
            for i in 0..count {
                let writes = wire.word();
                for _ in 0..writes {
                    let offset = wire.word();
                    let length = wire.word() as usize;
                    memory.put(u64::from(offset), wire.take(length));
                    wire.take((4 - length % 4) % 4);
                }
                let head = wire.word() as u16;
                let output_count = wire.word();
                let outputs = (0..output_count)
                    .map(|_| (wire.word(), wire.word()))
                    .collect::<Vec<_>>();
                memory.put(0x1004 + u64::from(i % 16) * 2, &head.to_le_bytes());
                memory.put(0x1002, &((i + 1) as u16).to_le_bytes());
                wire_write(&mut transport, REG_QUEUE_NOTIFY, 0);
                let mut actual = memory.get(0x2004 + u64::from(i % 16) * 8, 8);
                actual.extend(u32::from(memory.u16(0x2002)).to_le_bytes());
                actual.extend(wire_read(&mut transport, REG_INTERRUPT_STATUS).to_le_bytes());
                actual.extend(wire_read(&mut transport, REG_STATUS).to_le_bytes());
                assert_eq!(
                    actual,
                    reference.take(20),
                    "case{index},request{i}: completion"
                );
                for (offset, length) in outputs {
                    let actual = memory.get(u64::from(offset), length as usize);
                    assert_eq!(
                        actual,
                        reference.take(length as usize),
                        "case{index},request{i}: output"
                    );
                    compared += length as usize;
                }
                wire_write(&mut transport, REG_INTERRUPT_ACK, 3);
            }
            assert_eq!(wire.offset, input.len());
            assert_eq!(reference.offset, reference.bytes.len());
            // Read all media through the public device, independently of the
            // requested output buffers and the retained QEMU raw image.
            let mut header = [0; 16];
            header[..4].copy_from_slice(&0u32.to_le_bytes());
            memory.put(0x3000, &header);
            for (i, address, length, flags, next) in [
                (0, 0x40103000u64, 16u32, 1u16, 1u16),
                (1, 0x40110000, 4096, 3, 2),
                (2, 0x40106000, 1, 2, 0),
            ] {
                let mut d = address.to_le_bytes().to_vec();
                d.extend(length.to_le_bytes());
                d.extend(flags.to_le_bytes());
                d.extend(next.to_le_bytes());
                memory.put(i * 16, &d);
            }
            memory.put(0x1004 + u64::from(count % 16) * 2, &0u16.to_le_bytes());
            memory.put(0x1002, &((count + 1) as u16).to_le_bytes());
            wire_write(&mut transport, REG_QUEUE_NOTIFY, 0);
            assert_eq!(memory.u16(0x2002), (count + 1) as u16);
            assert_eq!(memory.get(0x6000, 1), [0]);
            let primary_media = std::fs::read(case.join("expected-media.bin")).unwrap();
            assert_eq!(
                memory.get(0x10000, 4096),
                primary_media,
                "case{index}: media"
            );
            if index != 4 {
                assert_eq!(media, primary_media);
            }
            (
                count as usize,
                records.len(),
                compared,
                media.len(),
                capability_difference,
                reference_difference,
            )
        });
        report.cases += 1;
        match result {
            Ok((
                requests,
                frame_bytes,
                payload_bytes,
                media_bytes,
                capabilities,
                reference_difference,
            )) => {
                report.requests += requests;
                report.frame_bytes += frame_bytes;
                report.payload_bytes += payload_bytes;
                report.media_bytes += media_bytes;
                report.capability_differences += capabilities;
                report.reference_difference_cases += usize::from(reference_difference);
                report.shared_exact_cases += usize::from(!reference_difference);
                if !reference_difference {
                    report.shared_requests += requests;
                    report.shared_payload_bytes += payload_bytes;
                    report.shared_media_bytes += media_bytes;
                }
            }
            Err(_) => report.failed += 1,
        }
    }
    report
}

#[test]
fn queue_area_overflow_fails_before_request_side_effects() {
    for register in [
        REG_QUEUE_DESC_LOW,
        REG_QUEUE_DRIVER_LOW,
        REG_QUEUE_DEVICE_LOW,
    ] {
        let mut h = Host::new(0);
        h.direct(1, 0);
        h.enqueue(0);
        h.write(REG_QUEUE_READY, 0);
        h.write(register, 0xffff_fff0);
        h.write(register + 4, u32::MAX);
        h.write(REG_QUEUE_READY, 1);
        h.memory.clear_trace();
        h.kick();
        h.assert_reset();
        assert_eq!(h.memory.u16(USED + 2), 0);
        assert!(
            !h.memory
                .trace()
                .iter()
                .any(|(_, address, _)| *address == HEADER || *address == DATA)
        );
    }
}
