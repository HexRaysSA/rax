//! NVMe queue identity, size, entry-format, alignment and feature admission.
#[path = "nvme_prp.rs"]
mod support;
mod devices {
    pub use rax::devices::{bus, virtio};
}
use support::nvme::*;
use support::{Host, sqe};
fn queue(h: &mut Host, op: u8, id: u32, size: u32, base: u64, flags: u32) -> u16 {
    let mut c = sqe(op, base, 0, 1);
    c[40..44].copy_from_slice(&(id | ((size - 1) << 16)).to_le_bytes());
    c[44..48].copy_from_slice(&flags.to_le_bytes());
    h.submit(true, c)
}
fn delete(h: &mut Host, op: u8, id: u32) -> u16 {
    queue(h, op, id, 1, 0, 0)
}
fn empty() -> Host {
    let memory = support::Memory::new(0x80000);
    let mut h = Host {
        device: NvmeController::with_blocks(0xfeb00000, memory.clone(), 128),
        memory,
        admin: 0,
        io: 0,
    };
    h.write(REG_AQA, 63 | (63 << 16));
    h.write(REG_ASQ, 0x1000);
    h.write(REG_ACQ, 0x2000);
    h.write(REG_CC, CC_EN | 0x00460000);
    h
}

#[test]
fn duplicate_queue_creation_preserves_existing_addresses_and_ring_state() {
    let mut h = Host::new(128, 0x80000);
    let cq = h.device.io_cq(1).unwrap().base;
    let sq = h.device.io_sq(1).unwrap().base;
    assert_eq!(queue(&mut h, ADMIN_CREATE_IO_CQ, 1, 4, 0x6000, 1), 0x101);
    assert_eq!(
        queue(&mut h, ADMIN_CREATE_IO_SQ, 1, 4, 0x7000, 1 | (1 << 16)),
        0x101
    );
    assert_eq!(h.device.io_cq(1).unwrap().base, cq);
    assert_eq!(h.device.io_sq(1).unwrap().base, sq);
}
#[test]
fn every_wire_queue_size_obeys_advertised_mqes_and_two_slot_minimum() {
    let mut h = Host::new(128, 0x80000);
    for size in 1..=65536u32 {
        let expected = if (2..=256).contains(&size) { 0 } else { 0x102 };
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_CQ, 2, size, 0x6000, 1),
            expected,
            "CQ {size}"
        );
        if expected == 0 {
            assert_eq!(h.device.io_cq(2).unwrap().size, size);
            assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, 2), 0);
        }
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_SQ, 2, size, 0x8000, 1 | (1 << 16)),
            expected,
            "SQ {size}"
        );
        if expected == 0 {
            assert_eq!(h.device.io_sq(2).unwrap().size, size);
            assert_eq!(delete(&mut h, ADMIN_DELETE_IO_SQ, 2), 0);
        }
    }
}
#[test]
fn admin_and_out_of_allocation_ids_are_not_io_queue_ids() {
    let mut h = Host::new(128, 0x80000);
    for id in [0, 5, 255, 256, 65535] {
        assert_eq!(queue(&mut h, ADMIN_CREATE_IO_CQ, id, 2, 0x6000, 1), 0x101);
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_SQ, id, 2, 0x8000, 1 | (1 << 16)),
            0x101
        );
        assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, id), 0x101);
        assert_eq!(delete(&mut h, ADMIN_DELETE_IO_SQ, id), 0x101);
    }
}
#[test]
fn sq_binding_distinguishes_invalid_and_uncreated_completion_queues() {
    let mut h = Host::new(128, 0x80000);
    for id in [0, 5, 65535] {
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_SQ, 2, 2, 0x8000, 1 | (id << 16)),
            0x101
        );
    }
    assert_eq!(
        queue(&mut h, ADMIN_CREATE_IO_SQ, 2, 2, 0x8000, 1 | (2 << 16)),
        0x100
    );
    assert!(!h.device.io_sq(2).unwrap().active);
}
#[test]
fn all_nonzero_page_offsets_are_rejected_without_queue_creation() {
    let mut h = Host::new(128, 0x80000);
    for offset in 1..4096 {
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_CQ, 2, 2, 0x6000 + offset, 1),
            SC_PRP_OFFSET_INVALID
        );
        assert_eq!(
            queue(
                &mut h,
                ADMIN_CREATE_IO_SQ,
                2,
                2,
                0x8000 + offset,
                1 | (1 << 16)
            ),
            SC_PRP_OFFSET_INVALID
        );
    }
}
#[test]
fn physically_contiguous_requirement_is_enforced() {
    let mut h = Host::new(128, 0x80000);
    assert_eq!(
        queue(&mut h, ADMIN_CREATE_IO_CQ, 2, 2, 0x6000, 0),
        SC_INVALID_FIELD
    );
    assert_eq!(
        queue(&mut h, ADMIN_CREATE_IO_SQ, 2, 2, 0x8000, 1 << 16),
        SC_INVALID_FIELD
    );
}
#[test]
fn physical_page_zero_is_valid_for_both_queue_sides() {
    for zero_cq in [false, true] {
        let mut h = Host::new(128, 0x80000);
        let cq = if zero_cq { 0 } else { 0x6000 };
        let sq = if zero_cq { 0x8000 } else { 0 };
        assert_eq!(queue(&mut h, ADMIN_CREATE_IO_CQ, 2, 2, cq, 1), 0);
        assert_eq!(
            queue(&mut h, ADMIN_CREATE_IO_SQ, 2, 2, sq, 1 | (2 << 16)),
            0
        );
        let c = sqe(NVM_FLUSH, 0, 0, 1);
        h.memory.put(sq, &c);
        h.write(REG_DOORBELL_BASE + 16, 1);
        let raw = h.memory.get(cq, 16);
        assert_eq!(&raw[12..14], &c[2..4]);
        assert_eq!(&raw[14..], &1u16.to_le_bytes());
    }
}
#[test]
fn queue_entry_size_fields_are_validated_at_creation_after_admin_enable() {
    for field in [16, 20] {
        for value in 0..16 {
            let mut h = empty();
            let cc = (CC_EN | 0x00460000) & !(15 << field) | (value << field);
            h.write(REG_CC, cc);
            let (op, good, flags) = if field == 16 {
                (ADMIN_CREATE_IO_SQ, 6, 1 | (1 << 16))
            } else {
                (ADMIN_CREATE_IO_CQ, 4, 1)
            };
            if field == 16 {
                assert_eq!(queue(&mut h, ADMIN_CREATE_IO_CQ, 1, 2, 0x6000, 1), 0);
            }
            assert_eq!(
                queue(&mut h, op, 2, 2, 0x8000, flags),
                if value == good { 0 } else { 0x102 },
                "field {field} value {value}"
            );
        }
    }
}
#[test]
fn deleting_a_bound_cq_reports_specific_status_and_preserves_the_pair() {
    let mut h = Host::new(128, 0x80000);
    assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, 1), 0x10c);
    assert!(h.device.io_cq(1).unwrap().active);
    assert!(h.device.io_sq(1).unwrap().active);
    assert_eq!(delete(&mut h, ADMIN_DELETE_IO_SQ, 1), 0);
    assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, 1), 0);
    assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, 1), 0x101);
}
fn feature(h: &mut Host, op: u8, dword10: u32, dword11: u32) -> (u16, u32) {
    let slot = h.admin;
    let mut c = sqe(op, 0, 0, 1);
    c[40..44].copy_from_slice(&dword10.to_le_bytes());
    c[44..48].copy_from_slice(&dword11.to_le_bytes());
    let status = h.submit(true, c);
    let result = h.memory.get(0x2000 + u64::from(slot) * 16, 4);
    (status, u32::from_le_bytes(result.try_into().unwrap()))
}
#[test]
fn number_of_queues_rejects_late_invalid_and_unsaveable_requests() {
    let mut h = Host::new(128, 0x80000);
    assert_eq!(feature(&mut h, ADMIN_SET_FEATURES, 7, 0).0, 0x0c);
    let mut h = empty();
    for value in [0xffff, 0xffff0000, 0xffffffff] {
        assert_eq!(
            feature(&mut h, ADMIN_SET_FEATURES, 7, value).0,
            SC_INVALID_FIELD
        );
    }
    assert_eq!(
        feature(&mut h, ADMIN_SET_FEATURES, (1 << 31) | 7, 0).0,
        0x10d
    );
    for value in [0, 1, 3, 0x1234abcd, 0xfffefffe] {
        assert_eq!(feature(&mut h, ADMIN_SET_FEATURES, 7, value), (0, 0x30003));
    }
}
#[test]
fn number_of_queues_get_selectors_retain_fixed_allocation_and_report_capabilities() {
    let mut h = empty();
    for selector in 0..8 {
        assert_eq!(
            feature(&mut h, ADMIN_GET_FEATURES, 7 | (selector << 8), 0xffffffff),
            match selector {
                0..=2 => (0, 0x30003),
                3 => (0, 4),
                _ => (SC_INVALID_FIELD, 0),
            }
        );
    }
}
#[test]
fn one_slot_admin_queues_do_not_arm_and_admin_base_registers_mask_reserved_bits() {
    use devices::bus::MmioDevice;
    for aqa in [0, 1, 1 << 16] {
        let mut h = empty();
        h.write(REG_CC, 0);
        h.write(REG_AQA, aqa);
        h.write(REG_CC, CC_EN);
        assert_eq!(h.device.csts() & (CSTS_RDY | CSTS_CFS), CSTS_CFS);
        assert!(!h.device.admin_sq().active);
        assert!(!h.device.admin_cq().active);
    }
    let mut h = empty();
    h.write(REG_CC, 0);
    for register in [REG_ASQ, REG_ACQ] {
        h.write(register, 0x12345fff);
        let mut bytes = [0; 4];
        h.device.read(0xfeb00000 + register, &mut bytes);
        assert_eq!(u32::from_le_bytes(bytes), 0x12345000);
    }
}
#[test]
fn queue_feature_lock_survives_deletion_and_clears_only_on_controller_reset() {
    let mut h = empty();
    assert_eq!(feature(&mut h, ADMIN_SET_FEATURES, 7, 0), (0, 0x30003));
    assert_eq!(queue(&mut h, ADMIN_CREATE_IO_CQ, 1, 2, 0x6000, 1), 0);
    assert_eq!(delete(&mut h, ADMIN_DELETE_IO_CQ, 1), 0);
    assert_eq!(feature(&mut h, ADMIN_SET_FEATURES, 7, 0).0, 0x0c);
    h.write(REG_CC, 0);
    h.write(REG_CC, CC_EN | 0x00460000);
    h.admin = 0;
    assert_eq!(feature(&mut h, ADMIN_SET_FEATURES, 7, 0), (0, 0x30003));
}
/// Preserve raw DNR differences while comparing every mandatory completion field.
pub fn compare_reference(directory: &std::path::Path) -> (usize, usize, usize, usize, usize) {
    let mut bytes = 0;
    let mut failed = 0;
    let mut dnr_differences = 0;
    let mut policy_differences = 0;
    for index in 0..14 {
        let folder = directory.join(format!("case-{index}"));
        let input = std::fs::read(folder.join("input.bin")).unwrap();
        let records = std::fs::read(folder.join("records.bin")).unwrap();
        let cc = u32::from_le_bytes(input[..4].try_into().unwrap());
        let count = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
        assert!((1..=64).contains(&count));
        assert_eq!(input.len(), 8 + 64 * count);
        assert_eq!(records.len(), 24 + 16 * count);
        let mut h = empty();
        h.write(REG_CC, cc);
        let mut mismatch = false;
        for slot in 0..count {
            let c: [u8; 64] = input[8 + 64 * slot..72 + 64 * slot].try_into().unwrap();
            let position = h.admin;
            h.submit(true, c);
            let mut got = h.memory.get(0x2000 + u64::from(position) * 16, 16);
            let mut expected = records[16 + slot * 16..32 + slot * 16].to_vec();
            if (got[15] ^ expected[15]) & 0x80 != 0 {
                dnr_differences += 1;
                eprintln!(
                    "case {index} command {slot}: raw DNR product {} reference {}",
                    got[15] >> 7,
                    expected[15] >> 7
                );
            }
            got[15] &= 0x7f;
            expected[15] &= 0x7f;
            if got != expected {
                let mut primary = expected.clone();
                let known = if index == 5 && slot == 4 {
                    // Figure161 specifies Invalid Queue Identifier for DeleteCQ0.
                    // QEMU returns Completion Queue Invalid for this exact input.
                    primary[14..16].copy_from_slice(&((0x101u16 << 1) | 1).to_le_bytes());
                    true
                } else if index == 12 && (4..=7).contains(&slot) {
                    // Reserved SEL values have no advertised behavior. RAX's
                    // explicit rejection differs from QEMU's current-value path.
                    primary[..4].fill(0);
                    primary[14..16].copy_from_slice(&((SC_INVALID_FIELD << 1) | 1).to_le_bytes());
                    true
                } else {
                    false
                };
                if known && got == primary {
                    policy_differences += 1;
                    eprintln!(
                        "case {index} command {slot}: retained primary/profile policy difference; product {got:02x?} reference {expected:02x?}"
                    );
                } else {
                    mismatch = true;
                    eprintln!(
                        "case {index} command {slot}: unexpected mandatory CQE product {got:02x?} reference {expected:02x?}"
                    );
                }
            }
        }
        bytes += records.len();
        failed += usize::from(mismatch);
    }
    (14, bytes, failed, dnr_differences, policy_differences)
}

#[test]
fn every_admin_queue_wire_size_is_independent_of_io_mqes() {
    use devices::bus::MmioDevice;
    let mut h = empty();
    assert_eq!((h.device.cap() & 0xffff) + 1, 256);
    for side in [0, 1] {
        for size in 1..=4096u32 {
            h.write(REG_CC, 0);
            h.write(REG_ASQ, 0x1000);
            h.write(REG_ACQ, 0x50000); // Nonoverlapping even at 4096 entries.
            let aqa = if side == 0 {
                (size - 1) | (63 << 16)
            } else {
                63 | ((size - 1) << 16)
            };
            h.write(REG_AQA, aqa);
            h.write(REG_CC, 0x00460001);
            let mut bytes = [0; 4];
            h.device.read(0xfeb00000 + REG_CSTS, &mut bytes);
            let status = u32::from_le_bytes(bytes);
            if (2..=4096).contains(&size) {
                assert_eq!(status & CSTS_RDY, CSTS_RDY, "side{side}/size{size}");
                assert_eq!(status & CSTS_CFS, 0);
            } else {
                assert_eq!(status & CSTS_RDY, 0, "side{side}/size{size}");
                assert_ne!(status & CSTS_CFS, 0);
            }
        }
    }
}
#[test]
fn minimum_one_entry_admin_queue_never_enables_or_performs_dma() {
    use devices::bus::MmioDevice;
    for (sq, cq) in [(1u32, 2u32), (2, 1), (1, 1)] {
        let mut h = empty();
        h.write(REG_CC, 0);
        h.write(REG_AQA, (sq - 1) | ((cq - 1) << 16));
        h.memory.clear_calls();
        h.write(REG_CC, 0x00460001);
        h.write(REG_DOORBELL_BASE, 1);
        let mut bytes = [0; 4];
        h.device.read(0xfeb00000 + REG_CSTS, &mut bytes);
        assert_eq!(u32::from_le_bytes(bytes) & CSTS_RDY, 0);
        assert!(h.memory.0.lock().unwrap().calls.is_empty());
    }
}
