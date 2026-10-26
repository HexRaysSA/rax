//! Execute the production NVMe device through MMIO queues and traced guest DMA.
mod devices {
    pub use rax::devices::{bus, virtio};
}
use devices::{bus, virtio};
#[allow(dead_code)]
#[path = "../../../src/devices/nvme.rs"]
pub(crate) mod nvme;
use bus::MmioDevice;
use nvme::*;
use std::ops::Range;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct Memory(pub(crate) Arc<Mutex<MemoryState>>);
pub(crate) struct MemoryState {
    pub(crate) bytes: Vec<u8>,
    pub(crate) calls: Vec<(bool, u64, usize)>,
    pub(crate) fail_read: Option<Range<u64>>,
    pub(crate) fail_write: Option<Range<u64>>,
}
impl Memory {
    pub(crate) fn new(size: usize) -> Self {
        Self(Arc::new(Mutex::new(MemoryState {
            bytes: vec![0; size],
            calls: vec![],
            fail_read: None,
            fail_write: None,
        })))
    }
    pub(crate) fn put(&self, address: u64, bytes: &[u8]) {
        self.0.lock().unwrap().bytes[address as usize..address as usize + bytes.len()]
            .copy_from_slice(bytes);
    }
    pub(crate) fn get(&self, address: u64, length: usize) -> Vec<u8> {
        self.0.lock().unwrap().bytes[address as usize..address as usize + length].to_vec()
    }
    pub(crate) fn clear_calls(&self) {
        self.0.lock().unwrap().calls.clear();
    }
}
impl Mem for Memory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        let mut state = self.0.lock().unwrap();
        state.calls.push((false, address, bytes.len()));
        let Some(end) = address.checked_add(bytes.len() as u64) else {
            return false;
        };
        if end > state.bytes.len() as u64
            || state
                .fail_read
                .as_ref()
                .is_some_and(|r| address < r.end && end > r.start)
        {
            return false;
        }
        bytes.copy_from_slice(&state.bytes[address as usize..end as usize]);
        true
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        let mut state = self.0.lock().unwrap();
        state.calls.push((true, address, bytes.len()));
        let Some(end) = address.checked_add(bytes.len() as u64) else {
            return false;
        };
        if end > state.bytes.len() as u64
            || state
                .fail_write
                .as_ref()
                .is_some_and(|r| address < r.end && end > r.start)
        {
            return false;
        }
        state.bytes[address as usize..end as usize].copy_from_slice(bytes);
        true
    }
}
const BASE: u64 = 0xfeb0_0000;
pub(crate) struct Host {
    pub(crate) device: NvmeController<Memory>,
    pub(crate) memory: Memory,
    pub(crate) admin: u32,
    pub(crate) io: u32,
}
pub(crate) fn sqe(op: u8, first: u64, second: u64, blocks: u32) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[0] = op;
    bytes[2..4].copy_from_slice(&0x73a5u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&first.to_le_bytes());
    bytes[32..40].copy_from_slice(&second.to_le_bytes());
    bytes[48..52].copy_from_slice(&(blocks - 1).to_le_bytes());
    bytes
}
impl Host {
    pub(crate) fn new(blocks: usize, memory: usize) -> Self {
        let memory = Memory::new(memory);
        let disk = (0..blocks * 512)
            .map(|i| (i.wrapping_mul(17) ^ (i >> 9)) as u8)
            .collect();
        let mut host = Self {
            device: NvmeController::new(BASE, memory.clone(), disk),
            memory,
            admin: 0,
            io: 0,
        };
        host.write(REG_AQA, 63 | (63 << 16));
        host.write(REG_ASQ, 0x1000);
        host.write(REG_ACQ, 0x2000);
        host.write(REG_CC, CC_EN);
        for (op, base, flags) in [
            (ADMIN_CREATE_IO_CQ, 0x4000, 1u32),
            (ADMIN_CREATE_IO_SQ, 0x3000, 1 | (1 << 16)),
        ] {
            let mut command = sqe(op, base, 0, 1);
            command[40..44].copy_from_slice(&(1u32 | (63 << 16)).to_le_bytes());
            command[44..48].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(host.submit(true, command), SC_SUCCESS);
        }
        host.memory.clear_calls();
        host
    }
    pub(crate) fn write(&mut self, offset: u64, value: u32) {
        self.device.write(BASE + offset, &value.to_le_bytes());
    }
    pub(crate) fn submit(&mut self, admin: bool, command: [u8; 64]) -> u16 {
        let slot = if admin { self.admin } else { self.io };
        let queue = if admin { 0x1000 } else { 0x3000 };
        let cq = if admin { 0x2000 } else { 0x4000 };
        self.memory.put(queue + u64::from(slot) * 64, &command);
        let next = (slot + 1) % 64;
        self.write(REG_DOORBELL_BASE + if admin { 0 } else { 8 }, next);
        let completion = self.memory.get(cq + u64::from(slot) * 16, 16);
        assert_eq!(
            &completion[12..14],
            &command[2..4],
            "CID must echo even on faults"
        );
        let status = u16::from_le_bytes(completion[14..16].try_into().unwrap()) >> 1;
        self.write(REG_DOORBELL_BASE + if admin { 4 } else { 12 }, next);
        if admin {
            self.admin = next
        } else {
            self.io = next
        };
        status
    }
}
/// Build a specification-shaped list independently of the device walker.
/// Later pages are deliberately noncontiguous;the last slot becomes a link
/// only when the remaining data-page count exceeds that list's capacity.
fn layout(
    memory: &Memory,
    total: usize,
    first_offset: u64,
    list_offset: u64,
) -> (u64, u64, Vec<(u64, usize)>) {
    let first = 0x40000 + first_offset;
    let length = total.min(4096 - first_offset as usize);
    let mut data = vec![(first, length)];
    let mut left = total - length;
    let mut index = 1u64;
    while left != 0 {
        let n = left.min(4096);
        data.push((0x40000 + index * 8192, n));
        left -= n;
        index += 1;
    }
    if data.len() == 1 {
        return (first, 0, data);
    }
    if data.len() == 2 {
        return (first, data[1].0, data);
    }
    let list = 0x8000 + list_offset;
    let mut pointer = list;
    let mut next_list = 0x10000u64;
    let mut at = 1;
    while at < data.len() {
        let slots = ((4096 - pointer % 4096) / 8) as usize;
        let chain = data.len() - at > slots;
        let entries = if chain { slots - 1 } else { data.len() - at };
        for n in 0..entries {
            memory.put(pointer + n as u64 * 8, &data[at + n].0.to_le_bytes());
        }
        at += entries;
        if chain {
            memory.put(pointer + entries as u64 * 8, &next_list.to_le_bytes());
            pointer = next_list;
            next_list += 4096;
        }
    }
    (first, list, data)
}
pub(crate) fn collect(memory: &Memory, segments: &[(u64, usize)]) -> Vec<u8> {
    segments
        .iter()
        .flat_map(|(address, length)| memory.get(*address, *length))
        .collect()
}
#[test]
fn scattered_prp_lists_round_trip_at_page_and_list_boundaries() {
    for blocks in [1, 8, 9, 16, 17, 24, 4096, 4104, 4112, 8192] {
        for first in [0, 4, 512, 4092] {
            for list in [0, 8, 4080, 4088] {
                let bytes = blocks * 512;
                let mut h = Host::new(blocks, 10 << 20);
                let (p1, p2, segments) = layout(&h.memory, bytes, first, list);
                assert_eq!(
                    h.submit(false, sqe(NVM_READ, p1, p2, blocks as u32)),
                    SC_SUCCESS,
                    "blocks{blocks}first{first}list{list}"
                );
                assert_eq!(collect(&h.memory, &segments), h.device.disk());
                let replacement: Vec<u8> = (0..bytes)
                    .map(|i| (i.wrapping_mul(29) ^ 0xa7) as u8)
                    .collect();
                let mut offset = 0;
                for (address, length) in &segments {
                    h.memory
                        .put(*address, &replacement[offset..offset + length]);
                    offset += length;
                }
                assert_eq!(
                    h.submit(false, sqe(NVM_WRITE, p1, p2, blocks as u32)),
                    SC_SUCCESS
                );
                assert_eq!(h.device.disk(), replacement);
            }
        }
    }
}
#[test]
fn every_dword_first_page_offset_is_admitted() {
    let mut h = Host::new(17, 1 << 20);
    for offset in (0..4096).step_by(4) {
        let (p1, p2, segments) = layout(&h.memory, 17 * 512, offset, 4088);
        assert_eq!(
            h.submit(false, sqe(NVM_READ, p1, p2, 17)),
            SC_SUCCESS,
            "offset{offset}"
        );
        assert_eq!(collect(&h.memory, &segments), h.device.disk());
    }
}
#[test]
fn maximum_nlb_uses_finite_chains_and_every_byte() {
    let mut h = Host::new(65536, 70 << 20);
    let (p1, p2, segments) = layout(&h.memory, 65536 * 512, 4092, 4088);
    assert_eq!(segments.len(), 8193);
    assert_eq!(h.submit(false, sqe(NVM_READ, p1, p2, 65536)), SC_SUCCESS);
    assert_eq!(collect(&h.memory, &segments), h.device.disk());
    let calls = &h.memory.0.lock().unwrap().calls;
    assert!(calls.len() < 17000, "bounded8193data+listDMA");
}
#[test]
fn physical_page_zero_is_valid_for_first_and_second_data_pages() {
    let mut h = Host::new(9, 1 << 20);
    assert_eq!(h.submit(false, sqe(NVM_READ, 0, 0x8000, 9)), SC_SUCCESS);
    assert_eq!(h.memory.get(0, 4096), &h.device.disk()[..4096]);
    assert_eq!(h.submit(false, sqe(NVM_READ, 0x9000, 0, 9)), SC_SUCCESS);
    assert_eq!(h.memory.get(0, 512), &h.device.disk()[4096..]);
}
#[test]
fn malformed_first_and_second_offsets_return_specific_status_without_payload_dma() {
    for (p1, p2, blocks) in [
        (0x40001, 0, 1),
        (0x40002, 0, 1),
        (0x40003, 0, 1),
        (0x40000, 0x8004, 9),
        (0x40000, 0x8004, 17),
    ] {
        let mut h = Host::new(blocks, 1 << 20);
        let disk = h.device.disk().to_vec();
        assert_eq!(h.submit(false, sqe(NVM_READ, p1, p2, blocks as u32)), 0x13);
        assert_eq!(h.device.disk(), disk);
        assert!(
            h.memory
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .all(|(write, address, _)| !*write || *address < 0x5000)
        );
    }
}
#[test]
fn malformed_later_entry_or_link_has_no_earlier_payload_effects() {
    for link in [false, true] {
        for write in [false, true] {
            let blocks = if link { 4112 } else { 24 };
            let mut h = Host::new(blocks, 10 << 20);
            let (p1, p2, segments) = layout(&h.memory, blocks * 512, 0, 0);
            let bad = if link { p2 + 511 * 8 } else { p2 + 8 };
            h.memory.put(bad, &0x70001u64.to_le_bytes());
            let before = collect(&h.memory, &segments);
            let disk = h.device.disk().to_vec();
            assert_eq!(
                h.submit(
                    false,
                    sqe(
                        if write { NVM_WRITE } else { NVM_READ },
                        p1,
                        p2,
                        blocks as u32
                    )
                ),
                0x13
            );
            assert_eq!(collect(&h.memory, &segments), before);
            assert_eq!(h.device.disk(), disk);
        }
    }
}
#[test]
fn unreadable_prp_list_fails_before_any_payload_dma() {
    let mut h = Host::new(24, 1 << 20);
    let (p1, p2, segments) = layout(&h.memory, 24 * 512, 0, 0);
    h.memory.0.lock().unwrap().fail_read = Some(p2 + 8..p2 + 16);
    assert_eq!(
        h.submit(false, sqe(NVM_READ, p1, p2, 24)),
        SC_DATA_XFER_ERROR
    );
    assert!(collect(&h.memory, &segments).iter().all(|b| *b == 0));
}
#[test]
fn late_source_dma_error_preserves_the_entire_namespace() {
    let mut h = Host::new(9, 1 << 20);
    let (p1, p2, segments) = layout(&h.memory, 9 * 512, 0, 0);
    let disk = h.device.disk().to_vec();
    h.memory.0.lock().unwrap().fail_read = Some(segments[1].0..segments[1].0 + 1);
    assert_eq!(
        h.submit(false, sqe(NVM_WRITE, p1, p2, 9)),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(h.device.disk(), disk);
}
#[test]
fn late_destination_dma_error_retains_only_prior_successful_writes() {
    let mut h = Host::new(24, 1 << 20);
    let (p1, p2, segments) = layout(&h.memory, 24 * 512, 0, 0);
    h.memory.0.lock().unwrap().fail_write = Some(segments[1].0..segments[1].0 + 1);
    assert_eq!(
        h.submit(false, sqe(NVM_READ, p1, p2, 24)),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(h.memory.get(p1, 4096), h.device.disk()[..4096]);
    assert!(h.memory.get(segments[1].0, 4096).iter().all(|b| *b == 0));
    assert!(h.memory.get(segments[2].0, 4096).iter().all(|b| *b == 0));
}
#[test]
fn identify_uses_split_prps_and_preserves_the_gap() {
    let mut h = Host::new(24, 1 << 20);
    let mut command = sqe(ADMIN_IDENTIFY, 0x40e00, 0x80000, 1);
    command[40..44].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(h.submit(true, command), SC_SUCCESS);
    assert_eq!(
        h.memory.get(0x40e00 + 0x80, 4),
        NVME_VERSION_1_4.to_le_bytes()
    );
    assert_eq!(h.memory.get(0x80000 + 0x204 - 512, 4), 1u32.to_le_bytes());
    assert!(h.memory.get(0x41000, 4096).iter().all(|b| *b == 0));
}
#[test]
fn reserved_data_pointer_format_fails_before_transfer() {
    for psdt in [3] {
        let mut h = Host::new(24, 1 << 20);
        let mut command = sqe(NVM_READ, 0x40000, 0x8000, 24);
        command[1] = psdt << 6;
        assert_eq!(h.submit(false, command), SC_INVALID_FIELD);
        assert!(h.memory.get(0x40000, 4096).iter().all(|b| *b == 0));
    }
}
#[test]
fn unsupported_memory_page_size_never_arms_queues() {
    for mps in 1..=15 {
        let mut h = Host::new(24, 1 << 20);
        h.write(REG_CC, 0);
        h.write(REG_CC, CC_EN | (mps << CC_MPS_SHIFT));
        assert_eq!(h.device.csts() & (CSTS_RDY | CSTS_CFS), CSTS_CFS);
        assert!(!h.device.admin_sq().active);
        assert!(!h.device.admin_cq().active);
    }
}

#[test]
fn every_io_completion_reports_the_consumed_head_through_ring_wrap() {
    let mut host = Host::new(1, 1 << 20);
    for index in 0..130 {
        assert_eq!(host.submit(false, sqe(NVM_READ, 0x8000, 0, 1)), SC_SUCCESS);
        let slot = index % 64;
        let completion = host.memory.get(0x4000 + slot * 16, 16);
        assert_eq!(
            u16::from_le_bytes(completion[8..10].try_into().unwrap()),
            ((slot + 1) % 64) as u16
        );
        assert_eq!(
            u16::from_le_bytes(completion[10..12].try_into().unwrap()),
            1
        );
    }
}
#[test]
fn shared_completion_queue_preserves_the_actual_submitting_queue_id() {
    let mut host = Host::new(1, 1 << 20);
    let mut create = sqe(ADMIN_CREATE_IO_SQ, 0x5000, 0, 1);
    create[40..44].copy_from_slice(&(2u32 | (63 << 16)).to_le_bytes());
    create[44..48].copy_from_slice(&(1u32 | (1 << 16)).to_le_bytes());
    assert_eq!(host.submit(true, create), SC_SUCCESS);
    host.memory.put(0x5000, &sqe(NVM_READ, 0x8000, 0, 1));
    host.write(REG_DOORBELL_BASE + 16, 1);
    let completion = host.memory.get(0x4000, 16);
    assert_eq!(
        u16::from_le_bytes(completion[10..12].try_into().unwrap()),
        2
    );
    assert_eq!(u16::from_le_bytes(completion[8..10].try_into().unwrap()), 1);
}

/// Replay actual independent guest bytes through this same production device.
/// Invoked by tools/nvme-diff/prp_compare.rs;ordinary tests need no external files.
#[allow(dead_code)]
pub fn compare_reference(directory: &std::path::Path) -> (usize, usize, usize) {
    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }
    let mut failed = 0;
    let mut compared = 0;
    for index in 0..6 {
        let case = directory.join(format!("case-{index}"));
        let input = std::fs::read(case.join("input.bin")).unwrap();
        let records = std::fs::read(case.join("records.bin")).unwrap();
        let total = word(&input, 0) as usize;
        let first = u64::from(word(&input, 4));
        let second = u64::from(word(&input, 8));
        let count = word(&input, 12) as usize;
        let entries = word(&input, 16) as usize;
        assert_eq!(input.len(), 20 + 8 * (count + entries));
        assert_eq!(records.len(), 84 + 2 * total);
        assert_eq!(&records[..8], b"RAXNVPR1");
        assert_eq!(&records[8..28], &input[..20]);
        assert_eq!(&records[records.len() - 8..], b"NVPRDONE");
        let segments: Vec<_> = (0..count)
            .map(|n| {
                (
                    u64::from(word(&input, 20 + n * 8)),
                    word(&input, 24 + n * 8) as usize,
                )
            })
            .collect();
        assert_eq!(segments.iter().map(|x| x.1).sum::<usize>(), total);
        let mut host = Host::new(total / 512, 128 << 20);
        for n in 0..entries {
            let at = 20 + 8 * (count + n);
            host.memory.put(
                u64::from(word(&input, at)),
                &u64::from(word(&input, at + 4)).to_le_bytes(),
            );
        }
        let mut at = 28;
        let mut passed = true;
        for (slot, operation) in [NVM_READ, NVM_WRITE, NVM_READ].into_iter().enumerate() {
            if slot != 0 {
                for (address, length) in &segments {
                    host.memory
                        .put(*address, &vec![if slot == 1 { 0x5a } else { 0 }; *length]);
                }
            }
            let status = host.submit(false, sqe(operation, first, second, (total / 512) as u32));
            passed &= status == SC_SUCCESS;
            passed &= host.memory.get(0x4000 + slot as u64 * 16, 16) == records[at..at + 16];
            at += 16;
            if slot != 1 {
                passed &= collect(&host.memory, &segments) == records[at..at + total];
                at += total;
                compared += total;
            }
        }
        passed &= host.device.disk().iter().all(|byte| *byte == 0x5a);
        assert_eq!(at, records.len() - 8);
        if !passed {
            failed += 1;
            eprintln!(
                "NVMe independent case{index} differs:total{total} first{first:#x} second{second:#x}"
            );
        }
    }
    (6, compared, failed)
}

#[test]
fn repeated_list_page_is_bounded_by_the_finite_command_and_planned_before_dma() {
    let mut host = Host::new(8192, 5 << 20);
    for entry in 0..511 {
        host.memory
            .put(0x8000 + entry * 8, &0x80000u64.to_le_bytes());
    }
    host.memory.put(0x8000 + 511 * 8, &0x8000u64.to_le_bytes());
    assert_eq!(
        host.submit(false, sqe(NVM_READ, 0x40000, 0x8000, 8192)),
        SC_SUCCESS
    );
    assert_eq!(host.memory.get(0x40000, 4096), host.device.disk()[..4096]);
    assert_eq!(
        host.memory.get(0x80000, 4096),
        host.device.disk()[1022 * 4096..1023 * 4096]
    );
    assert_eq!(
        host.memory.get(0x8000, 4096),
        host.device.disk()[1023 * 4096..]
    );
    assert!(host.memory.0.lock().unwrap().calls.len() < 3000);
}
