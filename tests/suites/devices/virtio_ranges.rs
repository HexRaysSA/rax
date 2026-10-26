//! Range-command contracts through the owning modern virtio block implementation.
#[allow(dead_code, unused_imports)]
#[path = "virtio_indirect.rs"]
pub mod support;
mod devices {
    pub use super::support::{bus, virtio};
}
use support::bus::MmioDevice;
use support::virtio::blk::VirtioBlk;
use support::virtio::*;
const DISCARD: u32 = 11;
const ZEROES: u32 = 13;
const F_DISCARD: u64 = 1 << 13;
const F_ZEROES: u64 = 1 << 14;
const BASE: u64 = 0x1000_0000;
fn pattern() -> Vec<u8> {
    (0..16384)
        .map(|n| (n as u8).wrapping_mul(17) ^ 0xa5)
        .collect()
}
fn metadata(ranges: &[(u64, u32, u32)]) -> Vec<u8> {
    ranges
        .iter()
        .flat_map(|(sector, count, flags)| {
            let mut b = sector.to_le_bytes().to_vec();
            b.extend(count.to_le_bytes());
            b.extend(flags.to_le_bytes());
            b
        })
        .collect()
}
struct Memory {
    inner: VecMem,
    fault: Option<u64>,
}
impl Memory {
    fn new() -> Self {
        Self {
            inner: VecMem::new(0x20000),
            fault: None,
        }
    }
    fn put(&mut self, address: usize, bytes: &[u8]) {
        self.inner.bytes[address..address + bytes.len()].copy_from_slice(bytes);
    }
}
impl Mem for Memory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        if self.fault == Some(address) {
            return false;
        }
        self.inner.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        self.inner.write(address, bytes)
    }
}
fn run_raw(
    device: &mut VirtioBlk,
    kind: u32,
    bytes: &[u8],
    split: Option<usize>,
    fault: bool,
    sector: u64,
) -> (u8, u32) {
    let mut memory = Memory::new();
    let mut header = [0; 16];
    header[..4].copy_from_slice(&kind.to_le_bytes());
    header[8..].copy_from_slice(&sector.to_le_bytes());
    memory.put(0x1000, &header);
    memory.put(0x2000, bytes);
    memory.put(0x10000, &[0xff]);
    let mut descriptors = vec![Descriptor {
        addr: 0x1000,
        len: 16,
        flags: 0,
        next: 0,
    }];
    if let Some(split) = split {
        memory.put(0x4000, &bytes[split..]);
        descriptors.push(Descriptor {
            addr: 0x2000,
            len: split as u32,
            flags: 0,
            next: 0,
        });
        descriptors.push(Descriptor {
            addr: 0x4000,
            len: (bytes.len() - split) as u32,
            flags: 0,
            next: 0,
        });
        if fault {
            memory.fault = Some(0x4000);
        }
    } else {
        descriptors.push(Descriptor {
            addr: 0x2000,
            len: bytes.len() as u32,
            flags: 0,
            next: 0,
        });
        if fault {
            memory.fault = Some(0x2000);
        }
    }
    descriptors.push(Descriptor {
        addr: 0x10000,
        len: 1,
        flags: 2,
        next: 0,
    });
    let used = device.handle_chain(
        &DescriptorChain {
            head: 0,
            descriptors,
        },
        &mut memory,
    );
    (memory.inner.bytes[0x10000], used)
}
fn run(device: &mut VirtioBlk, kind: u32, ranges: &[(u64, u32, u32)]) -> u8 {
    let (status, used) = run_raw(device, kind, &metadata(ranges), None, false, 0);
    assert_eq!(used, 1);
    status
}
fn assert_changed(device: &VirtioBlk, ranges: &[(usize, usize)]) {
    let mut expected = pattern();
    for (start, end) in ranges {
        expected[*start..*end].fill(0);
    }
    assert_eq!(device.disk(), expected);
}
#[test]
fn advertised_limits_match_range_parser_and_no_physical_unmap_claim() {
    let device = VirtioBlk::new(pattern());
    assert_eq!(
        device.device_features() & (F_DISCARD | F_ZEROES),
        F_DISCARD | F_ZEROES
    );
    let word = |offset| {
        u32::from_le_bytes(std::array::from_fn(|i| {
            device.config_read(offset + i as u64)
        }))
    };
    assert_eq!(word(0x24), u32::MAX);
    assert_eq!(word(0x28), 256);
    assert_eq!(word(0x2c), 1);
    assert_eq!(word(0x30), u32::MAX);
    assert_eq!(word(0x34), 256);
    assert_eq!(device.config_read(0x38), 0);
}
#[test]
fn write_zeroes_changes_exact_sector_extent() {
    let mut d = VirtioBlk::new(pattern());
    assert_eq!(run(&mut d, ZEROES, &[(3, 2, 0)]), 0);
    assert_changed(&d, &[(1536, 2560)]);
}
#[test]
fn write_zeroes_unmap_both_modes_have_zero_readback() {
    for flag in [0, 1] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(run(&mut d, ZEROES, &[(1, 1, flag)]), 0);
        assert_changed(&d, &[(512, 1024)]);
    }
}
#[test]
fn discard_selects_deterministic_zero_media() {
    let mut d = VirtioBlk::new(pattern());
    assert_eq!(run(&mut d, DISCARD, &[(5, 1, 0)]), 0);
    assert_changed(&d, &[(2560, 3072)]);
}
#[test]
fn overlapping_unordered_duplicate_and_adjacent_ranges_clear_the_union() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(
            run(
                &mut d,
                op,
                &[(8, 2, 0), (1, 3, 0), (3, 2, 0), (8, 2, 0), (10, 1, 0)]
            ),
            0
        );
        assert_changed(&d, &[(512, 2560), (4096, 5632)]);
    }
}
#[test]
fn final_invalid_extent_preserves_all_earlier_ranges() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(run(&mut d, op, &[(1, 1, 0), (32, 1, 0)]), 1);
        assert_changed(&d, &[]);
    }
}
#[test]
fn unsupported_flag_precedes_earlier_invalid_extent_without_mutation() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(run(&mut d, op, &[(u64::MAX, 1, 0), (1, 1, 2)]), 2);
        assert_changed(&d, &[]);
    }
}
#[test]
fn discard_rejects_unmap_without_deallocation_effects() {
    let mut d = VirtioBlk::new(pattern());
    assert_eq!(run(&mut d, DISCARD, &[(1, 1, 1)]), 2);
    assert_changed(&d, &[]);
}
#[test]
fn every_reserved_flag_bit_is_unsupported_before_media_changes() {
    for op in [DISCARD, ZEROES] {
        for bit in 1..32 {
            let mut d = VirtioBlk::new(pattern());
            assert_eq!(run(&mut d, op, &[(1, 1, 0), (2, 1, 1 << bit)]), 2);
            assert_changed(&d, &[]);
        }
    }
}
#[test]
fn sector_multiplication_end_overflow_and_capacity_are_checked() {
    for range in [
        (u64::MAX, 1, 0),
        (u64::MAX / 512, 1, 0),
        (31, 2, 0),
        (0, u32::MAX, 0),
    ] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(run(&mut d, ZEROES, &[range]), 1);
        assert_changed(&d, &[]);
    }
}
#[test]
fn empty_short_and_partial_range_records_return_ioerr() {
    for length in [0, 1, 15, 17, 31] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(
            run_raw(&mut d, ZEROES, &vec![0; length], None, false, 0),
            (1, 1)
        );
        assert_changed(&d, &[]);
    }
}
#[test]
fn descriptor_count_limit_rejects_257_without_prefix_effects() {
    let mut d = VirtioBlk::new(pattern());
    assert_eq!(run(&mut d, ZEROES, &vec![(1, 1, 0); 257]), 1);
    assert_changed(&d, &[]);
}
#[test]
fn all_256_range_records_are_processed_including_final_extent() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        let mut r = vec![(1, 1, 0); 256];
        r[255] = (30, 2, 0);
        assert_eq!(run(&mut d, op, &r), 0);
        assert_changed(&d, &[(512, 1024), (15360, 16384)]);
    }
}
#[test]
fn range_fields_may_cross_descriptor_boundaries() {
    for op in [DISCARD, ZEROES] {
        for split in [1, 7, 15, 17, 31] {
            let mut d = VirtioBlk::new(pattern());
            assert_eq!(
                run_raw(
                    &mut d,
                    op,
                    &metadata(&[(2, 1, 0), (7, 2, 0)]),
                    Some(split),
                    false,
                    0
                ),
                (0, 1)
            );
            assert_changed(&d, &[(1024, 1536), (3584, 4608)]);
        }
    }
}
#[test]
fn late_range_metadata_dma_failure_preserves_all_media() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(
            run_raw(
                &mut d,
                op,
                &metadata(&[(2, 1, 0), (7, 2, 0)]),
                Some(16),
                true,
                0
            ),
            (1, 1)
        );
        assert_changed(&d, &[]);
    }
}
#[test]
fn read_only_range_commands_never_change_media() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        d.set_read_only(true);
        assert_eq!(run(&mut d, op, &[(1, 1, 0)]), 1);
        assert_changed(&d, &[]);
    }
}
#[test]
fn zero_sector_ranges_are_noops_within_capacity() {
    for op in [DISCARD, ZEROES] {
        let mut d = VirtioBlk::new(pattern());
        assert_eq!(run(&mut d, op, &[(0, 0, 0), (32, 0, 0)]), 0);
        assert_changed(&d, &[]);
    }
}
#[test]
fn nonzero_unused_header_sector_is_rejected_before_media_changes() {
    let mut d = VirtioBlk::new(pattern());
    assert_eq!(
        run_raw(&mut d, ZEROES, &metadata(&[(1, 1, 0)]), None, false, 1),
        (1, 1)
    );
    assert_changed(&d, &[]);
}
fn mmio_range(features: u64, op: u32) -> (u8, u32, u16) {
    let mut mem = VecMem::new(0x10000);
    let mut header = op.to_le_bytes().to_vec();
    header.extend([0; 12]);
    mem.bytes[0x4000..0x4010].copy_from_slice(&header);
    mem.bytes[0x5000..0x5010].copy_from_slice(&metadata(&[(1, 1, 0)]));
    mem.bytes[0x6000] = 0xff;
    for (i, address, length, flags, next) in [
        (0, 0x4000u64, 16u32, 1u16, 1u16),
        (1, 0x5000, 16, 1, 2),
        (2, 0x6000, 1, 2, 0),
    ] {
        let mut raw = address.to_le_bytes().to_vec();
        raw.extend(length.to_le_bytes());
        raw.extend(flags.to_le_bytes());
        raw.extend(next.to_le_bytes());
        mem.bytes[0x1000 + i * 16..0x1010 + i * 16].copy_from_slice(&raw);
    }
    mem.bytes[0x2002..0x2004].copy_from_slice(&1u16.to_le_bytes());
    let mut t = VirtioMmio::new(BASE, Box::new(VirtioBlk::new(pattern())), mem);
    for (r, v) in [
        (REG_STATUS, 3),
        (REG_DRIVER_FEATURES_SEL, 0),
        (REG_DRIVER_FEATURES, features as u32),
        (REG_DRIVER_FEATURES_SEL, 1),
        (REG_DRIVER_FEATURES, 1),
        (REG_STATUS, 11),
        (REG_QUEUE_NUM, 16),
        (REG_QUEUE_DESC_LOW, 0x1000),
        (REG_QUEUE_DRIVER_LOW, 0x2000),
        (REG_QUEUE_DEVICE_LOW, 0x3000),
        (REG_QUEUE_READY, 1),
        (REG_STATUS, 15),
        (REG_QUEUE_NOTIFY, 0),
    ] {
        t.write(BASE + r, &v.to_le_bytes());
    }
    let m = &t.mem().bytes;
    (
        m[0x6000],
        u32::from_le_bytes(m[0x3008..0x300c].try_into().unwrap()),
        u16::from_le_bytes(m[0x3002..0x3004].try_into().unwrap()),
    )
}
#[test]
fn transport_rejects_unnegotiated_range_command_with_unsupp_completion() {
    for op in [DISCARD, ZEROES] {
        assert_eq!(mmio_range(0, op), (2, 1, 1));
    }
}
#[test]
fn transport_admits_each_range_command_only_with_its_feature() {
    for (op, feature) in [(DISCARD, F_DISCARD), (ZEROES, F_ZEROES)] {
        assert_eq!(mmio_range(feature, op), (0, 1, 1));
        let other = if feature == F_DISCARD {
            F_ZEROES
        } else {
            F_DISCARD
        };
        assert_eq!(mmio_range(other, op), (2, 1, 1));
    }
}

#[derive(Default)]
pub struct RangeReferenceReport {
    pub cases: usize,
    pub requests: usize,
    pub frame_bytes: usize,
    pub payload_bytes: usize,
    pub primary_media_bytes: usize,
    pub capability_profile_differences: usize,
    pub status_profile_differences: usize,
    pub advisory_media_difference_cases: usize,
    pub reference_exact_cases: usize,
    pub reference_fatal_cases: usize,
    pub reference_completed_requests: usize,
    pub failed: usize,
}
struct Wire<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Wire<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self.offset.checked_add(length).unwrap();
        let raw = &self.bytes[self.offset..end];
        self.offset = end;
        raw
    }
    fn word(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
}
#[derive(Clone)]
struct Physical(std::sync::Arc<std::sync::Mutex<VecMem>>);
impl Mem for Physical {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        address
            .checked_sub(0x40100000)
            .is_some_and(|o| self.0.lock().unwrap().read(o, bytes))
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        address
            .checked_sub(0x40100000)
            .is_some_and(|o| self.0.lock().unwrap().write(o, bytes))
    }
}
fn reference_write(t: &mut VirtioMmio<Physical>, offset: u64, value: u32) {
    t.write(BASE + offset, &value.to_le_bytes());
}
fn reference_read(t: &mut VirtioMmio<Physical>, offset: u64) -> u32 {
    let mut b = [0; 4];
    t.read(BASE + offset, &mut b);
    u32::from_le_bytes(b)
}
pub fn compare_ranges(folder: &std::path::Path) -> RangeReferenceReport {
    let mut report = RangeReferenceReport::default();
    for index in 0..16 {
        let result = std::panic::catch_unwind(|| {
            let case = folder.join(format!("case-{index:02}"));
            let input = std::fs::read(case.join("input.bin")).unwrap();
            let expected = std::fs::read(case.join("expected.bin")).unwrap();
            let records = std::fs::read(case.join("records.bin")).unwrap();
            let media = std::fs::read(case.join("disk.raw")).unwrap();
            let primary_media = std::fs::read(case.join("expected-media.bin")).unwrap();
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
            let feature_words = [reference.word(), reference.word()];
            let maximum = reference.word();
            assert_eq!(feature_words[0] & features, features);
            assert_ne!(feature_words[1] & 1, 0);
            assert!(maximum >= 16);
            let config = std::array::from_fn::<_, 6, _>(|_| reference.word());
            assert_eq!(config, [4194303, 1, 1, 4194303, 1, 1]);
            let status_profile = [3, 6].contains(&index);
            let fatal = index == 14;
            let advisory = [2, 4].contains(&index);
            let mut reference_expected = expected.clone();
            if status_profile {
                reference_expected[20] = 2;
                assert_eq!(media, pattern());
                let end = reference_expected.len();
                reference_expected[end - 16384..].copy_from_slice(&media);
            } else if advisory {
                let (start, end) = if index == 2 {
                    (5 * 512, 6 * 512)
                } else {
                    (8 * 512, 16 * 512)
                };
                let initial = pattern();
                for offset in (0..16384).step_by(512) {
                    let actual = &media[offset..offset + 512];
                    assert!(
                        actual == &initial[offset..offset + 512]
                            || (offset >= start && offset < end && actual == [0; 512])
                    );
                }
                let end = reference_expected.len();
                reference_expected[end - 16384..].copy_from_slice(&media);
            } else {
                assert_eq!(media, primary_media);
            }
            if fatal {
                assert_eq!(&records[48..], b"VIOFAIL!");
                assert_eq!(media, pattern());
            } else {
                assert_eq!(
                    &records[48..],
                    reference_expected,
                    "case{index}: retained reference contract"
                );
            }
            let advisory_difference = advisory && media != primary_media;
            let exact = !fatal && &records[48..] == expected && media == primary_media;
            let memory = Physical(std::sync::Arc::new(std::sync::Mutex::new(VecMem::new(
                0x20000,
            ))));
            let mut t = VirtioMmio::new(BASE, Box::new(VirtioBlk::new(pattern())), memory.clone());
            let product_features = [reference_read(&mut t, REG_DEVICE_FEATURES), {
                reference_write(&mut t, REG_DEVICE_FEATURES_SEL, 1);
                reference_read(&mut t, REG_DEVICE_FEATURES)
            }];
            assert_eq!(product_features[0] & features, features);
            assert_ne!(product_features[1] & 1, 0);
            let product_config = std::array::from_fn::<_, 6, _>(|i| {
                reference_read(&mut t, REG_CONFIG + 0x24 + i as u64 * 4)
            });
            assert_eq!(product_config, [u32::MAX, 256, 1, u32::MAX, 256, 0]);
            let capabilities =
                usize::from(config != product_config || feature_words != product_features);
            for (r, v) in [
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
                reference_write(&mut t, r, v);
            }
            let mut actual = vec![];
            let mut payload = 0;
            for i in 0..count {
                for _ in 0..wire.word() {
                    let offset = wire.word() as usize;
                    let length = wire.word() as usize;
                    memory.0.lock().unwrap().bytes[offset..offset + length]
                        .copy_from_slice(wire.take(length));
                    wire.take((4 - length % 4) % 4);
                }
                let head = wire.word() as u16;
                let outputs = (0..wire.word())
                    .map(|_| (wire.word() as usize, wire.word() as usize))
                    .collect::<Vec<_>>();
                {
                    let mut m = memory.0.lock().unwrap();
                    let slot = 0x1004 + (i % 16) as usize * 2;
                    m.bytes[slot..slot + 2].copy_from_slice(&head.to_le_bytes());
                    m.bytes[0x1002..0x1004].copy_from_slice(&((i + 1) as u16).to_le_bytes());
                }
                reference_write(&mut t, REG_QUEUE_NOTIFY, 0);
                {
                    let m = memory.0.lock().unwrap();
                    let slot = 0x2004 + (i % 16) as usize * 8;
                    actual.extend(&m.bytes[slot..slot + 8]);
                    actual.extend(
                        u32::from(u16::from_le_bytes(
                            m.bytes[0x2002..0x2004].try_into().unwrap(),
                        ))
                        .to_le_bytes(),
                    );
                }
                actual.extend(reference_read(&mut t, REG_INTERRUPT_STATUS).to_le_bytes());
                actual.extend(reference_read(&mut t, REG_STATUS).to_le_bytes());
                for (offset, length) in outputs {
                    actual.extend(&memory.0.lock().unwrap().bytes[offset..offset + length]);
                    payload += length;
                }
                reference_write(&mut t, REG_INTERRUPT_ACK, 3);
            }
            assert_eq!(wire.offset, input.len());
            assert_eq!(
                actual, expected,
                "case{index}: product completion and readback"
            );
            assert_eq!(&actual[actual.len() - 16384..], primary_media);
            (
                count as usize,
                records.len(),
                payload,
                capabilities,
                usize::from(status_profile),
                usize::from(advisory_difference),
                usize::from(exact),
                fatal,
            )
        });
        report.cases += 1;
        match result {
            Ok((requests, frames, payload, capabilities, status, advisory, exact, fatal)) => {
                report.requests += requests;
                report.frame_bytes += frames;
                report.payload_bytes += payload;
                report.primary_media_bytes += 16384;
                report.capability_profile_differences += capabilities;
                report.status_profile_differences += status;
                report.advisory_media_difference_cases += advisory;
                report.reference_exact_cases += exact;
                report.reference_fatal_cases += usize::from(fatal);
                if !fatal {
                    report.reference_completed_requests += requests;
                }
            }
            Err(_) => report.failed += 1,
        }
    }
    report
}
