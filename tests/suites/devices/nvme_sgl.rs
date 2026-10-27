//! Basic PCIe SGL transfers through actual production NVMe queues.
#[path = "nvme_prp.rs"]
mod support;
mod devices {
    pub use rax::devices::{bus, virtio};
}
use support::nvme::*;
use support::{Host, sqe};
fn descriptor(address: u64, length: u32, kind: u8) -> [u8; 16] {
    let mut raw = [0; 16];
    raw[..8].copy_from_slice(&address.to_le_bytes());
    raw[8..12].copy_from_slice(&length.to_le_bytes());
    raw[15] = kind << 4;
    raw
}
fn command(opcode: u8, root: [u8; 16], blocks: u32, psdt: u8) -> [u8; 64] {
    let mut command = sqe(
        opcode,
        u64::from_le_bytes(root[..8].try_into().unwrap()),
        u64::from_le_bytes(root[8..].try_into().unwrap()),
        blocks,
    );
    command[1] = psdt << 6;
    command
}
#[test]
fn basic_sgl_capabilities_are_visible_through_identify() {
    let mut host = Host::new(1, 1 << 20);
    let mut identify = sqe(ADMIN_IDENTIFY, 0x8000, 0, 1);
    identify[40..44].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(host.submit(true, identify), SC_SUCCESS);
    assert_eq!(host.memory.get(0x8218, 4), (1u32 | (1 << 18)).to_le_bytes());
}
#[test]
fn direct_unaligned_data_block_reads_and_writes_in_both_unused_metadata_modes() {
    for psdt in [1, 2] {
        for offset in 0..16 {
            let mut host = Host::new(2, 1 << 20);
            let root = descriptor(0x40000 + offset, 1024, 0);
            assert_eq!(
                host.submit(false, command(NVM_READ, root, 2, psdt)),
                SC_SUCCESS
            );
            assert_eq!(host.memory.get(0x40000 + offset, 1024), host.device.disk());
            host.memory.put(0x40000 + offset, &vec![0xa7; 1024]);
            assert_eq!(
                host.submit(false, command(NVM_WRITE, root, 2, psdt)),
                SC_SUCCESS
            );
            assert!(host.device.disk().iter().all(|byte| *byte == 0xa7));
        }
    }
}
#[test]
fn segment_and_last_segment_chain_accepts_nulls_and_byte_granular_lengths() {
    let mut host = Host::new(2, 1 << 20);
    host.memory.put(0x9000, &descriptor(0x40001, 333, 0));
    host.memory.put(0x9010, &descriptor(0xa000, 48, 3));
    host.memory.put(0xa000, &descriptor(0, 0, 0));
    host.memory.put(0xa010, &descriptor(0x80003, 691, 0));
    host.memory.put(0xa020, &descriptor(u64::MAX, 0, 0));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 32, 2), 2, 1)),
        SC_SUCCESS
    );
    let mut bytes = host.memory.get(0x40001, 333);
    bytes.extend(host.memory.get(0x80003, 691));
    assert_eq!(bytes, host.device.disk());
}
#[test]
fn oversized_data_buffers_are_truncated_without_touching_the_tail() {
    let mut host = Host::new(1, 1 << 20);
    assert_eq!(
        host.submit(
            false,
            command(NVM_READ, descriptor(0x8001, u32::MAX, 0), 1, 1)
        ),
        SC_SUCCESS
    );
    assert_eq!(host.memory.get(0x8001, 512), host.device.disk());
    assert!(
        host.memory
            .get(0x8001 + 512, 512)
            .iter()
            .all(|byte| *byte == 0)
    );
}
#[test]
fn short_data_and_null_only_segments_report_length_errors_before_payload() {
    for length in [0, 1, 255, 511] {
        let mut host = Host::new(1, 1 << 20);
        assert_eq!(
            host.submit(
                false,
                command(NVM_READ, descriptor(0x8000, length, 0), 1, 1)
            ),
            0x0f
        );
        assert!(host.memory.get(0x8000, 512).iter().all(|byte| *byte == 0));
    }
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0, 0, 0));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 16, 3), 1, 1)),
        0x0f
    );
}
#[test]
fn unsupported_types_and_pcie_reserved_subtypes_report_descriptor_type_errors() {
    for kind in 0..16 {
        for subtype in 0..16 {
            if matches!(kind, 0 | 2 | 3) && subtype == 0 {
                continue;
            }
            let mut host = Host::new(1, 1 << 20);
            let mut root = descriptor(0x8000, 512, kind);
            root[15] |= subtype;
            assert_eq!(
                host.submit(false, command(NVM_READ, root, 1, 1)),
                0x11,
                "kind{kind}subtype{subtype}"
            );
        }
    }
}
#[test]
fn segment_alignment_and_length_errors_have_no_payload_effects() {
    for (address, length) in [
        (0x9001, 16),
        (0x9004, 16),
        (0x9000, 0),
        (0x9000, 1),
        (0x9000, 15),
        (0x9000, 17),
    ] {
        let mut host = Host::new(1, 1 << 20);
        assert_eq!(
            host.submit(
                false,
                command(NVM_READ, descriptor(address, length, 3), 1, 1)
            ),
            0x0d
        );
    }
}
#[test]
fn nonterminal_links_and_links_inside_last_segments_are_rejected() {
    for last in [false, true] {
        let mut host = Host::new(1, 1 << 20);
        host.memory.put(0x9000, &descriptor(0xa000, 16, 3));
        host.memory.put(0x9010, &descriptor(0x8000, 512, 0));
        host.memory.put(0xa000, &descriptor(0x8000, 512, 0));
        assert_eq!(
            host.submit(
                false,
                command(
                    NVM_READ,
                    descriptor(0x9000, 32, if last { 3 } else { 2 }),
                    1,
                    1
                )
            ),
            if last { 0x0d } else { 0x0e }
        );
        assert!(host.memory.get(0x8000, 512).iter().all(|byte| *byte == 0));
    }
}
#[test]
fn a_nonfinal_segment_requires_a_terminal_link() {
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0x8000, 512, 0));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 16, 2), 1, 1)),
        0x0d
    );
}
#[test]
fn repeated_immutable_metadata_view_is_a_cycle_and_fails_before_dma() {
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0x9000, 16, 2));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 16, 2), 1, 1)),
        0x0d
    );
    assert!(host.memory.0.lock().unwrap().calls.len() < 12);
}
#[test]
fn descriptor_range_overflow_is_distinct_from_unmapped_dma_at_the_last_byte() {
    let mut host = Host::new(1, 1 << 20);
    assert_eq!(
        host.submit(
            false,
            command(NVM_READ, descriptor(u64::MAX - 510, 512, 0), 1, 1)
        ),
        0x0f
    );
    assert_eq!(
        host.submit(
            false,
            command(NVM_READ, descriptor(u64::MAX - 511, 512, 0), 1, 1)
        ),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(
        host.submit(
            false,
            command(NVM_READ, descriptor(u64::MAX - 7, 16, 3), 1, 1)
        ),
        0x0f
    );
    assert_eq!(
        host.submit(
            false,
            command(NVM_READ, descriptor(u64::MAX - 15, 16, 3), 1, 1)
        ),
        SC_DATA_XFER_ERROR
    );
}
#[test]
fn metadata_after_sufficient_data_is_still_validated_before_payload() {
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0x8000, 512, 0));
    host.memory.put(0x9010, &descriptor(0xa000, 0, 4));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 32, 3), 1, 1)),
        0x11
    );
    assert!(host.memory.get(0x8000, 512).iter().all(|byte| *byte == 0));
}
#[test]
fn all_metadata_and_source_reads_complete_before_media_mutation() {
    let mut host = Host::new(2, 1 << 20);
    let disk = host.device.disk().to_vec();
    host.memory.put(0x9000, &descriptor(0x8000, 512, 0));
    host.memory.put(0x9010, &descriptor(0xa000, 512, 0));
    host.memory.0.lock().unwrap().fail_read = Some(0xa000..0xa001);
    assert_eq!(
        host.submit(false, command(NVM_WRITE, descriptor(0x9000, 32, 3), 2, 1)),
        SC_DATA_XFER_ERROR
    );
    assert_eq!(host.device.disk(), disk);
}
#[test]
fn pcie_admin_commands_remain_prp_only_and_reserved_psdt_is_invalid() {
    let mut host = Host::new(1, 1 << 20);
    for psdt in [1, 2, 3] {
        assert_eq!(
            host.submit(
                true,
                command(ADMIN_IDENTIFY, descriptor(0x8000, 4096, 0), 1, psdt)
            ),
            SC_INVALID_FIELD
        );
    }
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x8000, 512, 0), 1, 3)),
        SC_INVALID_FIELD
    );
}

#[test]
fn data_less_nonfinal_segments_are_valid_when_the_chain_terminates() {
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0xa000, 16, 3));
    host.memory.put(0xa000, &descriptor(0x8001, 512, 0));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 16, 2), 1, 1)),
        SC_SUCCESS
    );
    assert_eq!(host.memory.get(0x8001, 512), host.device.disk());
}

#[test]
fn three_segment_chain_preserves_parent_type_when_metadata_arrays_overlap_in_size() {
    let mut host = Host::new(1, 1 << 20);
    host.memory.put(0x9000, &descriptor(0x8001, 128, 0));
    host.memory.put(0x9010, &descriptor(0xa000, 32, 2));
    host.memory.put(0xa000, &descriptor(0x10001, 129, 0));
    host.memory.put(0xa010, &descriptor(0xb000, 16, 3));
    host.memory.put(0xb000, &descriptor(0x18003, 255, 0));
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 32, 2), 1, 1)),
        SC_SUCCESS
    );
    let mut data = host.memory.get(0x8001, 128);
    data.extend(host.memory.get(0x10001, 129));
    data.extend(host.memory.get(0x18003, 255));
    assert_eq!(data, host.device.disk());
}

/// Replay actual independent PCIe SGL data and full completion records.
#[allow(dead_code)]
pub fn compare_reference(directory: &std::path::Path) -> (usize, usize, usize) {
    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }
    let mut failed = 0;
    let mut compared = 0;
    for index in 0..9 {
        let case = directory.join(format!("case-{index}"));
        let input = std::fs::read(case.join("input.bin")).unwrap();
        let records = std::fs::read(case.join("records.bin")).unwrap();
        let total = word(&input, 0) as usize;
        let psdt = word(&input, 4) as u8;
        let root: [u8; 16] = input[8..24].try_into().unwrap();
        let count = word(&input, 24) as usize;
        let entries = word(&input, 28) as usize;
        assert_eq!(input.len(), 32 + 8 * (count + entries));
        assert_eq!(records.len(), 100 + 2 * total);
        assert_eq!(&records[..8], b"RAXNVSG1");
        assert_eq!(&records[8..40], &input[..32]);
        assert_eq!(&records[records.len() - 8..], b"NVSGDONE");
        // Preserve the reference's complete capability value. The common
        // byte-granular field is shared;capability equivalence is not claimed.
        assert_eq!(word(&records, 40), 0x0008_0001);
        let segments: Vec<_> = (0..count)
            .map(|n| {
                (
                    u64::from(word(&input, 32 + n * 8)),
                    word(&input, 36 + n * 8) as usize,
                )
            })
            .collect();
        assert_eq!(segments.iter().map(|x| x.1).sum::<usize>(), total);
        let mut host = Host::new(total / 512, 128 << 20);
        for n in 0..entries {
            let at = 32 + 8 * (count + n);
            host.memory.put(
                u64::from(word(&input, at)),
                &word(&input, at + 4).to_le_bytes(),
            );
        }
        let mut at = 44;
        let mut passed = true;
        for (slot, opcode) in [NVM_READ, NVM_WRITE, NVM_READ].into_iter().enumerate() {
            if slot != 0 {
                for (address, length) in &segments {
                    host.memory
                        .put(*address, &vec![if slot == 1 { 0x5a } else { 0 }; *length]);
                }
            }
            passed &=
                host.submit(false, command(opcode, root, (total / 512) as u32, psdt)) == SC_SUCCESS;
            passed &= host.memory.get(0x4000 + slot as u64 * 16, 16) == records[at..at + 16];
            at += 16;
            if slot != 1 {
                passed &= support::collect(&host.memory, &segments) == records[at..at + total];
                at += total;
                compared += total;
            }
        }
        passed &= host.device.disk().iter().all(|byte| *byte == 0x5a);
        assert_eq!(at, records.len() - 8);
        if !passed {
            failed += 1;
            eprintln!("SGL reference case{index} differs:total{total} PSDT{psdt}");
        }
    }
    (9, compared, failed)
}

#[test]
fn maximum_nlb_sgl_reads_and_writes_every_byte() {
    let total = 65536 * 512;
    let mut host = Host::new(65536, 34 << 20);
    let root = descriptor(0x40003, total, 0);
    assert_eq!(
        host.submit(false, command(NVM_READ, root, 65536, 1)),
        SC_SUCCESS
    );
    assert_eq!(host.memory.get(0x40003, total as usize), host.device.disk());
    host.memory.put(0x40003, &vec![0x3c; total as usize]);
    assert_eq!(
        host.submit(false, command(NVM_WRITE, root, 65536, 1)),
        SC_SUCCESS
    );
    assert!(host.device.disk().iter().all(|byte| *byte == 0x3c));
}

#[test]
fn descriptor_array_crosses_pages_with_512_independent_byte_extents() {
    let mut host = Host::new(1, 1 << 20);
    for index in 0..512 {
        host.memory
            .put(0x9000 + index * 16, &descriptor(0x40001 + index * 2, 1, 0));
    }
    assert_eq!(
        host.submit(false, command(NVM_READ, descriptor(0x9000, 8192, 3), 1, 1)),
        SC_SUCCESS
    );
    for index in 0..512 {
        assert_eq!(
            host.memory.get(0x40001 + index * 2, 1)[0],
            host.device.disk()[index as usize]
        );
        assert_eq!(host.memory.get(0x40002 + index * 2, 1), [0]);
    }
}
