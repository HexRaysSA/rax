//! Execute optional NVM data commands and their fault/advertisement contracts.
#[path = "nvme_prp.rs"]
mod support;
mod devices {
    pub use rax::devices::{bus, virtio};
}
use support::nvme::*;
use support::{Host, sqe};
// Independent NVMe 1.4c wire constants also admit the unchanged parent device
// as a negative control without adding missing production implementation.
const NVM_COMPARE: u8 = 0x05;
const NVM_WRITE_ZEROES: u8 = 0x08;
const NVM_DATASET_MANAGEMENT: u8 = 0x09;
const SC_COMPARE_FAILURE: u16 = 0x285;
const SC_INVALID_NAMESPACE: u16 = 0x0b;

fn command(op: u8, lba: u64, blocks: u32, first: u64, second: u64) -> [u8; 64] {
    let mut c = sqe(op, first, second, blocks);
    c[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
    c[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
    c
}
fn control(c: &mut [u8; 64], bits: u32) {
    let old = u32::from_le_bytes(c[48..52].try_into().unwrap());
    c[48..52].copy_from_slice(&(old | bits).to_le_bytes());
}
fn ranges(entries: &[(u64, u32)]) -> Vec<u8> {
    entries
        .iter()
        .enumerate()
        .flat_map(|(i, (lba, blocks))| {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&(i as u32).to_le_bytes());
            bytes[4..8].copy_from_slice(&blocks.to_le_bytes());
            bytes[8..].copy_from_slice(&lba.to_le_bytes());
            bytes
        })
        .collect()
}
fn dsm(count: usize, attributes: u32, first: u64, second: u64) -> [u8; 64] {
    let mut c = sqe(NVM_DATASET_MANAGEMENT, first, second, 1);
    c[40..44].copy_from_slice(&((count - 1) as u32).to_le_bytes());
    c[44..48].copy_from_slice(&attributes.to_le_bytes());
    c
}
fn split_source(h: &Host, bytes: &[u8]) {
    h.memory.put(0x10004, &bytes[..4092]);
    h.memory.put(0x20000, &bytes[4092..]);
}
#[test]
fn identify_advertises_only_implemented_optional_data_and_cache_properties() {
    let mut h = Host::new(32, 0x80000);
    let mut c = sqe(ADMIN_IDENTIFY, 0x10000, 0, 1);
    c[40..44].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(h.submit(true, c), 0);
    let data = h.memory.get(0x10000, 4096);
    assert_eq!(
        u16::from_le_bytes(data[0x208..0x20a].try_into().unwrap()),
        0x0d
    );
    assert_eq!(&data[0x20a..0x20c], &[0, 0]);
    assert_eq!(data[0x20d], 6);
    c[40..44].fill(0);
    assert_eq!(h.submit(true, c), 0);
    assert_eq!(h.memory.get(0x10000 + 33, 1), [9]);
}
#[test]
fn compare_prps_checks_every_byte_without_modifying_media_or_source() {
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    let bytes = before[512..512 + 4096].to_vec();
    split_source(&h, &bytes);
    let c = command(NVM_COMPARE, 1, 8, 0x10004, 0x20000);
    assert_eq!(h.submit(false, c), 0);
    h.memory.put(0x20003, &[bytes[4095] ^ 1]);
    assert_eq!(h.submit(false, c), SC_COMPARE_FAILURE);
    assert_eq!(h.device.disk(), before);
    assert_eq!(h.memory.get(0x10004, 4092), bytes[..4092]);
}
#[test]
fn compare_accepts_byte_granular_sgls_in_both_unused_metadata_modes() {
    for mode in [1, 2] {
        let mut h = Host::new(32, 0x80000);
        let bytes = h.device.disk()[..512].to_vec();
        h.memory.put(0x10003, &bytes);
        let mut c = command(NVM_COMPARE, 0, 1, 0x10003, 512);
        c[1] = mode << 6;
        assert_eq!(h.submit(false, c), 0);
    }
}
#[test]
fn compare_ignores_prchk_for_no_pi_but_rejects_pract_without_dma() {
    let mut h = Host::new(32, 0x80000);
    let bytes = h.device.disk()[..512].to_vec();
    h.memory.put(0x10000, &bytes);
    for checks in 0..8 {
        let mut c = command(NVM_COMPARE, 0, 1, 0x10000, 0);
        control(&mut c, checks << 26);
        assert_eq!(h.submit(false, c), 0);
    }
    h.memory.clear_calls();
    let mut c = command(NVM_COMPARE, 0, 1, u64::MAX, 0);
    control(&mut c, 1 << 29);
    assert_eq!(h.submit(false, c), 0x181);
    assert!(
        !h.memory
            .0
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|(_, a, _)| *a == u64::MAX)
    );
}
#[test]
fn maximum_nlb_compare_uses_every_byte_of_a_32_mib_sgl() {
    let mut h = Host::new(65536, 0x2020000);
    let bytes = h.device.disk().to_vec();
    h.memory.put(0x10000, &bytes);
    let mut c = command(NVM_COMPARE, 0, 65536, 0x10000, bytes.len() as u64);
    c[1] = 1 << 6;
    assert_eq!(h.submit(false, c), 0);
    h.memory.put(
        0x10000 + bytes.len() as u64 - 1,
        &[bytes[bytes.len() - 1] ^ 1],
    );
    assert_eq!(h.submit(false, c), SC_COMPARE_FAILURE);
    assert_eq!(h.device.disk(), bytes);
}
#[test]
fn late_compare_source_fault_precedes_miscompare_and_preserves_media() {
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    split_source(&h, &[0xaa; 4096]);
    h.memory.0.lock().unwrap().fail_read = Some(0x20000..0x20004);
    assert_eq!(
        h.submit(false, command(NVM_COMPARE, 0, 8, 0x10004, 0x20000)),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(h.device.disk(), before);
}
#[test]
fn write_zeroes_changes_exact_blocks_in_both_deallocate_modes_without_dma() {
    for cache_flags in 0..4 {
        for deallocate in [0, 1] {
            for pract in [0, 1] {
                let mut h = Host::new(32, 0x80000);
                let mut expected = h.device.disk().to_vec();
                expected[5 * 512..12 * 512].fill(0);
                let mut c = command(NVM_WRITE_ZEROES, 5, 7, u64::MAX, u64::MAX);
                control(
                    &mut c,
                    (deallocate << 25) | (pract << 29) | (cache_flags << 30),
                );
                assert_eq!(h.submit(false, c), 0);
                assert_eq!(h.device.disk(), expected);
                assert!(
                    !h.memory
                        .0
                        .lock()
                        .unwrap()
                        .calls
                        .iter()
                        .any(|(_, a, _)| *a == u64::MAX)
                );
            }
        }
    }
}

#[test]
fn maximum_nlb_zeroes_clears_32_mib_without_reading_a_payload() {
    let mut h = Host::new(65536, 0x80000);
    assert_eq!(
        h.submit(false, command(NVM_WRITE_ZEROES, 0, 65536, u64::MAX, 0)),
        0
    );
    assert!(h.device.disk().iter().all(|b| *b == 0));
}
#[test]
fn zeroes_prchk_errors_and_out_of_range_commands_preserve_all_media() {
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    for checks in 1..8 {
        let mut c = command(NVM_WRITE_ZEROES, 0, 1, 0, 0);
        control(&mut c, checks << 26);
        assert_eq!(h.submit(false, c), 0x181);
        assert_eq!(h.device.disk(), before);
    }
    for op in [NVM_COMPARE, NVM_WRITE_ZEROES] {
        for (lba, blocks) in [(31, 2), (32, 1), (u64::MAX, 1), (u64::MAX / 512, 65536)] {
            assert_eq!(
                h.submit(false, command(op, lba, blocks, 0x10000, 0)),
                SC_LBA_OUT_OF_RANGE
            );
            assert_eq!(h.device.disk(), before);
        }
    }
}
#[test]
fn dataset_attributes_deallocate_only_selected_valid_ranges() {
    for attributes in 0..8 {
        let mut h = Host::new(32, 0x80000);
        let mut expected = h.device.disk().to_vec();
        h.memory.put(
            0x10000,
            &ranges(&[(3, 2), (5, 1), (3, 1), (u64::MAX, 1), (32, 1), (0, 0)]),
        );
        if attributes & 4 != 0 {
            expected[3 * 512..6 * 512].fill(0);
        }
        assert_eq!(h.submit(false, dsm(6, attributes, 0x10000, 0)), 0);
        assert_eq!(h.device.disk(), expected);
    }
}
#[test]
fn dataset_lengths_are_one_based_and_zero_length_ranges_are_ignored() {
    let mut h = Host::new(32, 0x80000);
    let mut expected = h.device.disk().to_vec();
    expected[5 * 512..6 * 512].fill(0);
    h.memory.put(0x10000, &ranges(&[(3, 0), (5, 1)]));
    assert_eq!(h.submit(false, dsm(2, 4, 0x10000, 0)), 0);
    assert_eq!(h.device.disk(), expected);
}
#[test]
fn maximum_dataset_count_crosses_prp_pages_and_uses_last_descriptor() {
    let mut h = Host::new(128, 0x80000);
    let mut entries = vec![(3, 1); 256];
    entries[255] = (120, 1);
    let bytes = ranges(&entries);
    split_source(&h, &bytes);
    let mut expected = h.device.disk().to_vec();
    expected[3 * 512..4 * 512].fill(0);
    expected[120 * 512..121 * 512].fill(0);
    assert_eq!(h.submit(false, dsm(256, 4, 0x10004, 0x20000)), 0);
    assert_eq!(h.device.disk(), expected);
}
#[test]
fn late_dataset_metadata_dma_failure_cannot_deallocate_an_earlier_range() {
    let mut h = Host::new(128, 0x80000);
    let before = h.device.disk().to_vec();
    split_source(&h, &ranges(&vec![(3, 1); 256]));
    h.memory.0.lock().unwrap().fail_read = Some(0x20000..0x20004);
    assert_eq!(
        h.submit(false, dsm(256, 4, 0x10004, 0x20000)),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(h.device.disk(), before);
}
#[test]
fn dataset_sgls_and_ignored_advisory_buffers_have_distinct_dma_policies() {
    for mode in [1, 2] {
        let mut h = Host::new(32, 0x80000);
        let mut expected = h.device.disk().to_vec();
        expected[2 * 512..3 * 512].fill(0);
        h.memory.put(0x10003, &ranges(&[(2, 1)]));
        let mut c = dsm(1, 4, 0x10003, 16);
        c[1] = mode << 6;
        assert_eq!(h.submit(false, c), 0);
        assert_eq!(h.device.disk(), expected);
    }
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    for attributes in 0..4 {
        assert_eq!(h.submit(false, dsm(256, attributes, u64::MAX, u64::MAX)), 0);
    }
    assert_eq!(h.device.disk(), before);
    assert!(
        !h.memory
            .0
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|(_, a, _)| *a == u64::MAX)
    );
}
#[test]
fn unsupported_fused_members_never_execute_independently() {
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    h.memory.put(0x10000, &[0x5a; 4096]);
    for op in [
        NVM_READ,
        NVM_WRITE,
        NVM_COMPARE,
        NVM_WRITE_ZEROES,
        NVM_DATASET_MANAGEMENT,
        NVM_FLUSH,
    ] {
        for fuse in 1..4 {
            let mut c = command(op, 0, 1, 0x10000, 0);
            c[1] = fuse;
            assert_eq!(h.submit(false, c), SC_INVALID_FIELD);
            assert_eq!(h.device.disk(), before);
        }
    }
    for fuse in 1..4 {
        let mut c = sqe(ADMIN_IDENTIFY, 0x10000, 0, 1);
        c[1] = fuse;
        c[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(h.submit(true, c), SC_INVALID_FIELD);
        assert_eq!(h.memory.get(0x10000, 4096), [0x5a; 4096]);
    }
}
#[test]
fn invalid_namespaces_fail_without_payload_effects_and_flush_supports_broadcast() {
    let mut h = Host::new(32, 0x80000);
    let before = h.device.disk().to_vec();
    for op in [
        NVM_READ,
        NVM_WRITE,
        NVM_COMPARE,
        NVM_WRITE_ZEROES,
        NVM_DATASET_MANAGEMENT,
        NVM_FLUSH,
    ] {
        for nsid in [0u32, 2, u32::MAX] {
            let mut c = command(op, 0, 1, u64::MAX, u64::MAX);
            c[4..8].copy_from_slice(&nsid.to_le_bytes());
            assert_eq!(
                h.submit(false, c),
                if op == NVM_FLUSH && nsid == u32::MAX {
                    0
                } else {
                    SC_INVALID_NAMESPACE
                }
            );
            assert_eq!(h.device.disk(), before);
        }
    }
}
#[test]
fn absent_volatile_cache_feature_is_not_reported_as_a_successful_noop() {
    let mut h = Host::new(32, 0x80000);
    for op in [ADMIN_SET_FEATURES, ADMIN_GET_FEATURES] {
        let mut c = sqe(op, 0, 0, 1);
        c[40..44].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(h.submit(true, c), SC_INVALID_FIELD);
    }
}
#[derive(Default)]
pub struct ReferenceSummary {
    pub cases: usize,
    pub commands: usize,
    pub frame_bytes: usize,
    pub media_bytes: usize,
    pub payload_bytes: usize,
    pub dnr_differences: usize,
    pub namespace_differences: usize,
    pub capability_differences: usize,
    pub completion_failures: usize,
    pub media_failures: usize,
    pub output_failures: usize,
    pub capability_failures: usize,
    pub advisory_media_differences: usize,
    pub advisory_output_differences: usize,
    pub reference_contract_failures: usize,
    pub failed: usize,
}
fn word(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
}
fn media_contract(index: usize) -> (Vec<usize>, Vec<usize>) {
    let mandatory = match index {
        3 => vec![3, 4],
        4 => vec![31],
        11 => vec![7],
        _ => vec![],
    };
    let advisory = match index {
        5 => vec![3, 4, 5],
        7 => vec![1, 30],
        8 => vec![2, 3, 31],
        11 => vec![10, 11],
        12 => (0..8).chain(16..24).collect(),
        13 => (0..8).chain([9]).chain(16..24).collect(),
        14 => (0..8).chain(24..32).collect(),
        15 => (8..16).chain(24..32).collect(),
        _ => vec![],
    };
    (mandatory, advisory)
}

/// Execute exactly the retained SQEs and compare actual media/output/CQE bytes.
pub fn compare_reference(directory: &std::path::Path) -> ReferenceSummary {
    let mut report = ReferenceSummary::default();
    for index in 0..16 {
        let folder = directory.join(format!("case-{index}"));
        let input = std::fs::read(folder.join("input.bin")).unwrap();
        let raw = std::fs::read(folder.join("records.bin")).unwrap();
        let initial = std::fs::read(folder.join("initial.raw")).unwrap();
        let count = word(&input, 0) as usize;
        let writes = word(&input, 4) as usize;
        let outputs = word(&input, 8) as usize;
        assert_eq!(input.len(), 12 + 64 * count + 8 * (writes + outputs));
        let mut h = Host::new(32, 0x3000000);
        assert_eq!(h.device.disk(), initial);
        let mut identify = sqe(ADMIN_IDENTIFY, 0x01200000, 0, 1);
        identify[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(h.submit(true, identify), 0);
        identify[24..32].copy_from_slice(&0x01201000u64.to_le_bytes());
        identify[40..44].fill(0);
        assert_eq!(h.submit(true, identify), 0);
        let controller = h.memory.get(0x01200000, 4096);
        let namespace = h.memory.get(0x01201000, 4096);
        let capability = u32::from(u16::from_le_bytes(
            controller[0x208..0x20a].try_into().unwrap(),
        )) | (u32::from(controller[0x20d]) << 16)
            | (u32::from(namespace[33]) << 24);
        let sgls = word(&controller, 0x218);
        let nn = word(&controller, 0x204);
        let capability_failure = capability != 0x0906000d || sgls != 0x40001 || nn != 1;
        if (capability, sgls, nn) != (word(&raw, 20), word(&raw, 24), word(&raw, 28)) {
            report.capability_differences += 1;
            eprintln!(
                "case {index}: raw capabilities product({capability:#x},{sgls:#x},{nn}) reference({:#x},{:#x},{})",
                word(&raw, 20),
                word(&raw, 24),
                word(&raw, 28)
            );
        }
        let mut at = 12 + 64 * count;
        for _ in 0..writes {
            let address = word(&input, at);
            h.memory.put(u64::from(address), &input[at + 4..at + 8]);
            at += 8;
        }
        let mut completion_failure = false;
        for slot in 0..count {
            let command: [u8; 64] = input[12 + 64 * slot..76 + 64 * slot].try_into().unwrap();
            let position = h.io;
            h.submit(false, command);
            let mut got = h.memory.get(0x4000 + u64::from(position) * 16, 16);
            let mut expected = raw[32 + 16 * slot..48 + 16 * slot].to_vec();
            if (got[15] ^ expected[15]) & 0x80 != 0 {
                report.dnr_differences += 1;
                eprintln!(
                    "case {index} command {slot}: DNR product{} reference{}",
                    got[15] >> 7,
                    expected[15] >> 7
                );
            }
            got[15] &= 0x7f;
            expected[15] &= 0x7f;
            if got != expected {
                let mut profile = expected.clone();
                profile[14..16].copy_from_slice(&((SC_INVALID_NAMESPACE << 1) | 1).to_le_bytes());
                if index == 9 && slot == 0 && nn == 1 && word(&raw, 28) >= 2 && got == profile {
                    report.namespace_differences += 1;
                    eprintln!(
                        "case9 command0: retained invalid/out-of-range versus inactive in-range namespace status difference"
                    );
                } else {
                    completion_failure = true;
                    eprintln!(
                        "case {index} command {slot}: unexpected CQE product{got:02x?} reference{expected:02x?}"
                    );
                }
            }
        }
        let media = std::fs::read(folder.join("disk.raw")).unwrap();
        let (mandatory, advisory) = media_contract(index);
        let mut selected = initial.clone();
        for block in mandatory.iter().chain(&advisory) {
            selected[block * 512..(block + 1) * 512].fill(0);
        }
        let media_failure = h.device.disk() != selected;
        let mut reference_failure = false;
        for block in 0..32 {
            let got = &media[block * 512..(block + 1) * 512];
            let original = &initial[block * 512..(block + 1) * 512];
            let valid = if mandatory.contains(&block) {
                got.iter().all(|b| *b == 0)
            } else if advisory.contains(&block) {
                got == original || got.iter().all(|b| *b == 0)
            } else {
                got == original
            };
            if !valid {
                reference_failure = true;
            }
        }
        let advisory_difference = h.device.disk() != media;
        if advisory_difference {
            report.advisory_media_differences += 1;
            eprintln!(
                "case {index}: retained advisory deallocation choices differ;both complete namespace contracts are checked"
            );
        }
        let mut output_failure = false;
        let mut payload = 0;
        let mut offset = 32 + 16 * count;
        let mut advisory_output = false;
        for _ in 0..outputs {
            let address = word(&input, at);
            let length = word(&input, at + 4) as usize;
            at += 8;
            let bytes = h.memory.get(u64::from(address), length);
            let observed = &raw[offset..offset + length];
            // Each output is the final Read of the complete namespace. Verify
            // both actual reads against their own media, then retain advisory
            // cross-device differences; never permit arbitrary byte masking.
            if length != initial.len() || bytes != h.device.disk() || observed != media {
                output_failure = true;
                eprintln!("case {index}: actual Read output does not equal its complete namespace");
            }
            if bytes != observed {
                advisory_output = true;
            }
            offset += length;
            payload += length;
        }
        report.advisory_output_differences += usize::from(advisory_output);
        assert_eq!(&raw[..8], b"RAXNVCM2");
        assert_eq!(&raw[8..20], &input[..12]);
        assert_eq!(&raw[offset..], b"NVCMDONE");
        if media_failure {
            eprintln!("case {index}: product violates selected complete deallocation behavior");
        }
        if reference_failure {
            eprintln!("case {index}: reference violates permitted per-block outcomes");
        }
        report.reference_contract_failures += usize::from(reference_failure);
        report.cases += 1;
        report.commands += count;
        report.frame_bytes += raw.len();
        report.media_bytes += media.len();
        report.payload_bytes += payload;
        report.completion_failures += usize::from(completion_failure);
        report.output_failures += usize::from(output_failure);
        report.media_failures += usize::from(media_failure);
        report.capability_failures += usize::from(capability_failure);
        report.failed += usize::from(
            completion_failure
                || output_failure
                || media_failure
                || capability_failure
                || reference_failure,
        );
    }
    report
}
