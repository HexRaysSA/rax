//! Production completion backpressure, DMA failure and pin-level behavior.
#[path = "nvme_prp.rs"]
mod support;
mod devices {
    pub use rax::devices::{bus, virtio};
}
use support::nvme::*;
use support::{Host, sqe};
fn host(entries: u32, interrupts: bool) -> Host {
    let mut h = Host::new(128, 0x80000);
    for op in [ADMIN_DELETE_IO_SQ, ADMIN_DELETE_IO_CQ] {
        let mut c = sqe(op, 0, 0, 1);
        c[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(h.submit(true, c), SC_SUCCESS);
    }
    for (op, base, size, flags) in [
        (
            ADMIN_CREATE_IO_CQ,
            0x4000,
            entries,
            1 | (u32::from(interrupts) << 1),
        ),
        (ADMIN_CREATE_IO_SQ, 0x3000, 64, 1 | (1 << 16)),
    ] {
        let mut c = sqe(op, base, 0, 1);
        c[40..44].copy_from_slice(&(1 | ((size - 1) << 16)).to_le_bytes());
        c[44..48].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(h.submit(true, c), SC_SUCCESS);
    }
    h.memory.clear_calls();
    h
}
fn command(h: &mut Host, slot: u32, op: u8, cid: u16) {
    let address = 0x10000 + u64::from(slot) * 4096;
    let mut c = sqe(op, address, 0, 1);
    c[2..4].copy_from_slice(&cid.to_le_bytes());
    c[40..44].copy_from_slice(&slot.to_le_bytes());
    h.memory.put(0x3000 + u64::from(slot) * 64, &c);
    h.memory.put(address, &[cid as u8; 512]);
}
fn raw(h: &Host, slot: u32) -> [u8; 16] {
    h.memory
        .get(0x4000 + u64::from(slot) * 16, 16)
        .try_into()
        .unwrap()
}
fn cid(h: &Host, slot: u32) -> u16 {
    u16::from_le_bytes(raw(h, slot)[12..14].try_into().unwrap())
}
#[test]
fn full_cq_retains_unread_entries_and_stops_payload_effects() {
    let mut h = host(4, true);
    let original = h.device.disk().to_vec();
    for i in 0..7 {
        command(&mut h, i, NVM_WRITE, 0x20 + i as u16);
    }
    h.write(REG_DOORBELL_BASE + 8, 7);
    assert_eq!(h.device.io_sq(1).unwrap().head, 3);
    assert_eq!(h.device.io_cq(1).unwrap().tail, 3);
    assert_eq!(h.device.csts() & CSTS_CFS, 0);
    for i in 0..3 {
        assert_eq!(cid(&h, i), 0x20 + i as u16);
    }
    assert_eq!(&h.device.disk()[3 * 512..], &original[3 * 512..]);
    let saved = h.memory.get(0x4000, 64);
    h.write(REG_DOORBELL_BASE + 8, 7);
    assert_eq!(h.memory.get(0x4000, 64), saved);
    assert_eq!(h.device.io_sq(1).unwrap().head, 3);
}
#[test]
fn cq_head_progress_resumes_pending_commands_without_sq_notification() {
    let mut h = host(4, true);
    for i in 0..7 {
        command(&mut h, i, NVM_WRITE, 0x30 + i as u16);
    }
    h.write(REG_DOORBELL_BASE + 8, 7);
    for i in 0..7 {
        let slot = i % 4;
        let c = raw(&h, slot);
        assert_eq!(cid(&h, slot), 0x30 + i as u16);
        assert_eq!(
            u16::from_le_bytes(c[8..10].try_into().unwrap()),
            (i + 1) as u16
        );
        assert_eq!(u16::from_le_bytes(c[10..12].try_into().unwrap()), 1);
        assert_eq!(c[14] & 1, u8::from(i < 4));
        assert!(h.device.take_interrupt());
        h.write(REG_DOORBELL_BASE + 12, (slot + 1) % 4);
    }
    assert_eq!(h.device.io_sq(1).unwrap().head, 7);
    assert!(!h.device.take_interrupt());
    for i in 0..7 {
        assert_eq!(
            &h.device.disk()[i * 512..(i + 1) * 512],
            &[0x30 + i as u8; 512]
        );
    }
}
#[test]
fn masked_completion_remains_available_and_reasserts_on_unmask() {
    let mut h = host(4, true);
    h.write(REG_INTMS, 1);
    command(&mut h, 0, NVM_FLUSH, 17);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert_eq!(cid(&h, 0), 17);
    assert!(!h.device.take_interrupt());
    h.write(REG_INTMC, 1);
    assert!(h.device.take_interrupt());
    h.write(REG_DOORBELL_BASE + 12, 1);
    assert!(!h.device.take_interrupt());
}
#[test]
fn injection_does_not_acknowledge_the_pin_interrupt() {
    let mut h = host(4, true);
    command(&mut h, 0, NVM_FLUSH, 18);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert!(h.device.take_interrupt());
    h.device.clear_interrupt();
    assert!(h.device.take_interrupt());
    h.write(REG_DOORBELL_BASE + 12, 1);
    assert!(!h.device.take_interrupt());
}
#[test]
fn disabled_cq_interrupts_do_not_assert_the_pin() {
    let mut h = host(4, false);
    command(&mut h, 0, NVM_FLUSH, 19);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert_eq!(cid(&h, 0), 19);
    assert!(!h.device.take_interrupt());
    h.write(REG_INTMS, 1);
    h.write(REG_INTMC, 1);
    assert!(!h.device.take_interrupt());
}
#[test]
fn mask_bits_other_than_vector_zero_do_not_suppress_the_pin() {
    let mut h = host(4, true);
    h.write(REG_INTMS, !1);
    command(&mut h, 0, NVM_FLUSH, 20);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert!(h.device.take_interrupt());
}
#[test]
fn sq_read_failure_is_fatal_without_consumption_or_media_effect() {
    let mut h = host(4, true);
    let original = h.device.disk().to_vec();
    command(&mut h, 0, NVM_WRITE, 21);
    h.memory.0.lock().unwrap().fail_read = Some(0x3000..0x3040);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert_ne!(h.device.csts() & CSTS_CFS, 0);
    assert_eq!(h.device.io_sq(1).unwrap().head, 0);
    assert_eq!(h.device.io_cq(1).unwrap().tail, 0);
    assert_eq!(h.device.disk(), original);
    h.memory.0.lock().unwrap().fail_read = None;
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert_eq!(h.device.disk(), original);
}
#[test]
fn cq_write_failure_is_fatal_without_publication_or_duplicate_execution() {
    let mut h = host(4, true);
    command(&mut h, 0, NVM_WRITE, 22);
    h.memory.0.lock().unwrap().fail_write = Some(0x4000..0x4010);
    h.write(REG_DOORBELL_BASE + 8, 1);
    assert_ne!(h.device.csts() & CSTS_CFS, 0);
    assert_eq!(h.device.io_sq(1).unwrap().head, 1);
    assert_eq!(h.device.io_cq(1).unwrap().tail, 0);
    assert_eq!(&h.device.disk()[..512], &[22; 512]);
    assert!(!h.device.take_interrupt());
    h.memory.0.lock().unwrap().fail_write = None;
    h.memory.put(0x10000, &[99; 512]);
    h.write(REG_DOORBELL_BASE + 8, 1);
    h.write(REG_DOORBELL_BASE + 12, 0);
    assert_eq!(&h.device.disk()[..512], &[22; 512]);
    assert_eq!(h.device.io_cq(1).unwrap().tail, 0);
}
#[test]
fn advancing_cq_head_beyond_published_entries_preserves_queue_and_is_fatal() {
    let mut h = host(4, true);
    command(&mut h, 0, NVM_FLUSH, 23);
    h.write(REG_DOORBELL_BASE + 8, 1);
    h.write(REG_DOORBELL_BASE + 12, 2);
    assert_ne!(h.device.csts() & CSTS_CFS, 0);
    assert_eq!(h.device.io_cq(1).unwrap().head, 0);
    assert_eq!(h.device.io_cq(1).unwrap().tail, 1);
}
#[test]
fn reset_discards_stalled_work_and_interrupts_while_preserving_media() {
    let mut h = host(4, true);
    for i in 0..7 {
        command(&mut h, i, NVM_WRITE, 0x40 + i as u16);
    }
    h.write(REG_DOORBELL_BASE + 8, 7);
    let written = h.device.disk().to_vec();
    assert!(h.device.take_interrupt());
    h.write(REG_CC, 0);
    assert_eq!(h.device.csts() & (CSTS_RDY | CSTS_CFS), 0);
    assert!(!h.device.take_interrupt());
    assert!(!h.device.io_sq(1).unwrap().active);
    assert!(!h.device.io_cq(1).unwrap().active);
    h.write(REG_DOORBELL_BASE + 8, 7);
    h.write(REG_DOORBELL_BASE + 12, 1);
    assert_eq!(h.device.disk(), written);
}
#[test]
fn admin_cq_backpressure_preserves_commands_and_resumes_on_acknowledgement() {
    let mut h = host(4, true);
    h.write(REG_CC, 0);
    h.write(REG_AQA, 7 | (3 << 16));
    h.write(REG_CC, CC_EN);
    for i in 0..7u32 {
        let mut c = sqe(0xff, 0, 0, 1);
        c[2..4].copy_from_slice(&(100 + i as u16).to_le_bytes());
        h.memory.put(0x1000 + u64::from(i) * 64, &c);
    }
    h.write(REG_DOORBELL_BASE, 7);
    assert_eq!(h.device.admin_sq().head, 3);
    assert_eq!(h.device.admin_cq().tail, 3);
    for i in 0..7u32 {
        let c = h.memory.get(0x2000 + u64::from(i % 4) * 16, 16);
        assert_eq!(
            u16::from_le_bytes(c[12..14].try_into().unwrap()),
            100 + i as u16
        );
        h.write(REG_DOORBELL_BASE + 4, (i + 1) % 4);
    }
    assert_eq!(h.device.admin_sq().head, 7);
    assert!(!h.device.take_interrupt());
}
#[test]
fn reset_clears_control_mask_and_fatal_state_but_retains_admin_addresses() {
    use devices::bus::MmioDevice;
    let mut h = host(4, true);
    h.write(REG_INTMS, u32::MAX);
    h.write(REG_DOORBELL_BASE + 12, 2);
    assert_ne!(h.device.csts() & CSTS_CFS, 0);
    h.write(REG_CC, 0);
    for (off, want) in [
        (REG_CC, 0),
        (REG_CSTS, 0),
        (REG_INTMS, 0),
        (REG_AQA, 63 | (63 << 16)),
        (REG_ASQ, 0x1000),
        (REG_ACQ, 0x2000),
    ] {
        let mut bytes = [0; 4];
        h.device.read(0xfeb00000 + off, &mut bytes);
        assert_eq!(u32::from_le_bytes(bytes), want, "offset {off:#x}");
    }
    h.write(REG_CC, CC_EN);
    assert_eq!(h.device.csts(), CSTS_RDY);
    assert!(!h.device.io_sq(1).unwrap().active);
}
fn create_second_sq(h: &mut Host, cqid: u32) {
    let mut c = sqe(ADMIN_CREATE_IO_SQ, 0x5000, 0, 1);
    c[40..44].copy_from_slice(&(2u32 | (63 << 16)).to_le_bytes());
    c[44..48].copy_from_slice(&(1 | (cqid << 16)).to_le_bytes());
    assert_eq!(h.submit(true, c), SC_SUCCESS);
    let mut c = sqe(NVM_FLUSH, 0, 0, 1);
    c[2..4].copy_from_slice(&900u16.to_le_bytes());
    h.memory.put(0x5000, &c);
}
#[test]
fn freeing_a_shared_cq_resumes_bound_sqs_without_losing_their_identity() {
    let mut h = host(4, true);
    create_second_sq(&mut h, 1);
    for i in 0..4 {
        command(&mut h, i, NVM_FLUSH, 50 + i as u16);
    }
    h.write(REG_DOORBELL_BASE + 8, 4);
    h.write(REG_DOORBELL_BASE + 16, 1);
    assert_eq!(h.device.io_sq(1).unwrap().head, 3);
    assert_eq!(h.device.io_sq(2).unwrap().head, 0);
    h.write(REG_DOORBELL_BASE + 12, 1);
    assert_eq!(h.device.io_sq(1).unwrap().head, 4);
    assert_eq!(h.device.io_sq(2).unwrap().head, 0);
    assert_eq!(cid(&h, 3), 53);
    h.write(REG_DOORBELL_BASE + 12, 2);
    assert_eq!(h.device.io_sq(2).unwrap().head, 1);
    let c = raw(&h, 0);
    assert_eq!(u16::from_le_bytes(c[8..10].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes(c[10..12].try_into().unwrap()), 2);
    assert_eq!(cid(&h, 0), 900);
}
#[test]
fn acknowledging_one_cq_keeps_another_enabled_cq_asserted() {
    let mut h = host(4, true);
    let mut c = sqe(ADMIN_CREATE_IO_CQ, 0x6000, 0, 1);
    c[40..44].copy_from_slice(&(2u32 | (3 << 16)).to_le_bytes());
    c[44..48].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(h.submit(true, c), SC_SUCCESS);
    create_second_sq(&mut h, 2);
    command(&mut h, 0, NVM_FLUSH, 60);
    h.write(REG_DOORBELL_BASE + 8, 1);
    h.write(REG_DOORBELL_BASE + 16, 1);
    assert!(h.device.take_interrupt());
    h.write(REG_DOORBELL_BASE + 12, 1);
    assert!(h.device.take_interrupt());
    h.write(REG_DOORBELL_BASE + 20, 1);
    assert!(!h.device.take_interrupt());
}
#[test]
fn seeded_ring_model_preserves_every_completion_across_sizes_and_wraps() {
    use std::collections::VecDeque;
    for size in [2u32, 3, 4, 7, 64, 256] {
        let mut h = host(size, true);
        let mut published = 0u32;
        let mut consumed = 0u32;
        let mut acked = 0u32;
        let mut pending = VecDeque::new();
        let mut rng = 0x61c8864680b583ebu64;
        for event in 0..512 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            if event % 3 != 2 && published - consumed < 63 {
                let count = ((rng >> 32) as u32 % 7 + 1).min(63 - (published - consumed));
                for _ in 0..count {
                    command(&mut h, published % 64, NVM_FLUSH, (1000 + published) as u16);
                    published += 1;
                }
                h.write(REG_DOORBELL_BASE + 8, published % 64);
            } else if consumed > acked {
                let count = ((rng >> 32) as u32 % (consumed - acked)) + 1;
                for _ in 0..count {
                    let expected = pending.pop_front().unwrap();
                    let c = raw(&h, acked % size);
                    assert_eq!(u16::from_le_bytes(c[12..14].try_into().unwrap()), expected);
                    assert_eq!(c[14] & 1, 1 ^ ((acked / size) & 1) as u8);
                    acked += 1;
                }
                h.write(REG_DOORBELL_BASE + 12, acked % size);
            }
            let completed = (published - consumed).min(size - 1 - (consumed - acked));
            for _ in 0..completed {
                pending.push_back((1000 + consumed) as u16);
                consumed += 1;
            }
            assert_eq!(
                h.device.io_sq(1).unwrap().head,
                consumed % 64,
                "size {size}, event {event}"
            );
            assert_eq!(h.device.io_cq(1).unwrap().tail, consumed % size);
            assert_eq!(h.device.take_interrupt(), consumed != acked);
            assert_eq!(h.device.csts() & CSTS_CFS, 0);
        }
    }
}
/// Compare the complete retained frames from independently executed PCI guests.
pub fn compare_reference(directory: &std::path::Path) -> (usize, usize, usize) {
    let mut total_bytes = 0;
    let mut failed = 0;
    for index in 0..7 {
        let folder = directory.join(format!("case-{index}"));
        let input = std::fs::read(folder.join("input.bin")).unwrap();
        let reference = std::fs::read(folder.join("records.bin")).unwrap();
        let size = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let enabled = u32::from_le_bytes(input[4..8].try_into().unwrap()) != 0;
        let count = u32::from_le_bytes(input[8..12].try_into().unwrap());
        let mut h = host(size, enabled);
        let mut got = b"RAXNVQ01".to_vec();
        got.extend_from_slice(&input);
        let mut acknowledged = 0;
        let pin = |h: &Host, got: &mut Vec<u8>| {
            got.extend_from_slice(&u32::from(h.device.take_interrupt()).to_le_bytes())
        };
        for sequence in 0..count {
            command(&mut h, sequence % 64, NVM_FLUSH, 0x5000 + sequence as u16);
            h.write(REG_DOORBELL_BASE + 8, (sequence + 1) % 64);
            if sequence + 1 - acknowledged >= size {
                got.extend_from_slice(&h.memory.get(0x4000, size as usize * 16));
                acknowledged += 1;
                h.write(REG_DOORBELL_BASE + 12, acknowledged % size);
            }
            got.extend_from_slice(&raw(&h, sequence % size));
            pin(&h, &mut got);
        }
        h.write(REG_DOORBELL_BASE + 12, count % size);
        pin(&h, &mut got);
        command(&mut h, count % 64, NVM_FLUSH, 0x5000 + count as u16);
        h.write(REG_DOORBELL_BASE + 8, (count + 1) % 64);
        got.extend_from_slice(&raw(&h, count % size));
        pin(&h, &mut got);
        h.write(REG_INTMS, 1);
        pin(&h, &mut got);
        h.write(REG_INTMC, 1);
        pin(&h, &mut got);
        h.write(REG_DOORBELL_BASE + 12, (count + 1) % size);
        pin(&h, &mut got);
        h.write(REG_INTMS, u32::MAX);
        h.write(REG_CC, 0);
        use devices::bus::MmioDevice;
        let mut mask = [0; 4];
        h.device.read(0xfeb00000 + REG_INTMS, &mut mask);
        got.extend_from_slice(&mask);
        pin(&h, &mut got);
        got.extend_from_slice(b"NVQ0DONE");
        total_bytes += reference.len();
        if got != reference {
            let mismatch = got.iter().zip(&reference).position(|(a, b)| a != b);
            eprintln!(
                "case {index}: first difference {mismatch:?}, product {} reference {} bytes",
                got.len(),
                reference.len()
            );
            failed += 1;
        }
    }
    (7, total_bytes, failed)
}
#[test]
fn nonzero_interrupt_vectors_are_rejected_before_queue_replacement() {
    let mut h = host(4, true);
    let before = h.device.io_cq(1).unwrap().base;
    for vector in [1u32, 2, 31, 32, 2047, 2048, 65535] {
        let mut c = sqe(ADMIN_CREATE_IO_CQ, 0x7000, 0, 1);
        c[40..44].copy_from_slice(&(1u32 | (3 << 16)).to_le_bytes());
        c[44..48].copy_from_slice(&(3 | (vector << 16)).to_le_bytes());
        assert_eq!(h.submit(true, c), 0x108);
        assert_eq!(h.device.io_cq(1).unwrap().base, before);
    }
}
