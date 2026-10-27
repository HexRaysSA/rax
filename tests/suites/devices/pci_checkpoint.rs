//! Public host-bridge checkpoint and routing controls.
use rax::devices::bus::{IoDevice, MmioDevice};
use rax::devices::pci::{Bar, ConfigSpace, PciCheckpoint, PciStub};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct Mmio(u8, Arc<AtomicUsize>);
impl MmioDevice for Mmio {
    fn read(&mut self, _: u64, data: &mut [u8]) {
        self.1.fetch_add(1, Ordering::SeqCst);
        data.fill(self.0);
    }
    fn write(&mut self, _: u64, _: &[u8]) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
struct Pio(u8, Arc<AtomicUsize>);
impl IoDevice for Pio {
    fn read(&mut self, _: u16) -> u8 {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0
    }
    fn write(&mut self, _: u16, _: u8) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
fn config(io: bool, base: u32, size: u32) -> ConfigSpace {
    let mut c = ConfigSpace::device(0x8086, 0x1234, 0x010802, 0);
    c.set_bar(0, if io { Bar::io(size) } else { Bar::mem32(size) });
    c.set_u32(0x10, base | u32::from(io));
    c.set_u16(4, if io { 1 } else { 2 });
    c
}
fn fixture(io: bool) -> (PciStub, Arc<AtomicUsize>) {
    let mut p = PciStub::new();
    let calls = Arc::new(AtomicUsize::new(0));
    if io {
        p.attach_pio(
            0,
            1,
            0,
            config(true, 0xc000, 32),
            0,
            Box::new(Pio(0x69, calls.clone())),
        );
    } else {
        p.attach_mmio(
            0,
            1,
            0,
            config(false, 0x100000, 4096),
            0,
            Box::new(Mmio(0x5a, calls.clone())),
        );
    }
    (p, calls)
}
fn address(p: &mut PciStub, v: u32) {
    for (i, b) in v.to_le_bytes().into_iter().enumerate() {
        p.write(0xcf8 + i as u16, b);
    }
}
fn write_config(p: &mut PciStub, off: u8, v: u32) {
    address(p, 0x80000800 | u32::from(off));
    for (i, b) in v.to_le_bytes().into_iter().enumerate() {
        p.write(0xcfc + i as u16, b);
    }
}
fn read_config(p: &mut PciStub, off: u8) -> u32 {
    address(p, 0x80000800 | u32::from(off));
    u32::from_le_bytes(std::array::from_fn(|i| p.read(0xcfc + i as u16)))
}
fn read_mmio(p: &mut PciStub, base: u64) -> Option<u8> {
    let mut data = [0];
    p.mmio_read(base, &mut data).then_some(data[0])
}
fn reject(p: &mut PciStub, state: Vec<u8>) {
    let before = p.checkpoint().unwrap();
    assert!(p.restore_checkpoint(PciCheckpoint { state }).is_err());
    assert_eq!(p.checkpoint().unwrap(), before);
}
#[test]
fn default_and_partial_latch_roundtrip() {
    let mut p = PciStub::new();
    p.write(0xcf8, 0xa5);
    p.write(0xcfb, 0x81);
    let c = p.checkpoint().unwrap();
    let mut q = PciStub::new();
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.read(0xcf8), 0xa5);
    assert_eq!(q.read(0xcfb), 0x81);
    assert_eq!(q.checkpoint().unwrap(), c);
}
#[test]
fn remapped_mmio_continues_at_restored_bar() {
    let (mut p, _) = fixture(false);
    write_config(&mut p, 0x10, 0x300000);
    let c = p.checkpoint().unwrap();
    let (mut q, _) = fixture(false);
    q.restore_checkpoint(c).unwrap();
    assert_eq!(read_mmio(&mut q, 0x100000), None);
    assert_eq!(read_mmio(&mut q, 0x300000), Some(0x5a));
    assert_eq!(q.mmio_aperture(), Some((0x300000, 0x301000)));
}
#[test]
fn disabled_decode_stays_disabled_until_guest_enable() {
    let (mut p, _) = fixture(false);
    write_config(&mut p, 4, 0);
    let (mut q, _) = fixture(false);
    q.restore_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(q.mmio_aperture(), None);
    assert_eq!(read_mmio(&mut q, 0x100000), None);
    write_config(&mut q, 4, 2);
    assert_eq!(read_mmio(&mut q, 0x100000), Some(0x5a));
}
#[test]
fn sizing_probe_preserves_raw_bytes_and_late_remap() {
    let (mut p, _) = fixture(false);
    write_config(&mut p, 0x10, u32::MAX);
    let c = p.checkpoint().unwrap();
    let (mut q, _) = fixture(false);
    q.restore_checkpoint(c).unwrap();
    assert_eq!(q.mmio_aperture(), None);
    assert_eq!(read_config(&mut q, 0x10), 0xfffff000);
    write_config(&mut q, 0x10, 0x400000);
    assert_eq!(read_mmio(&mut q, 0x400000), Some(0x5a));
}
#[test]
fn pio_mapping_and_command_follow_restored_config() {
    let (mut p, _) = fixture(true);
    write_config(&mut p, 0x10, 0xd001);
    let (mut q, _) = fixture(true);
    q.restore_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(q.io_read(0xc000), None);
    assert_eq!(q.io_read(0xd003), Some(0x69));
    write_config(&mut q, 4, 0);
    assert_eq!(q.io_read(0xd003), None);
}
#[test]
fn function_insertion_order_has_canonical_encoding() {
    let mut p = PciStub::new();
    let mut q = PciStub::new();
    for i in 1..8 {
        p.add_function(0, i, 0, config(false, u32::from(i) * 4096, 4096));
    }
    for i in (1..8).rev() {
        q.add_function(0, i, 0, config(false, u32::from(i) * 4096, 4096));
    }
    assert_eq!(p.checkpoint().unwrap(), q.checkpoint().unwrap());
}
#[test]
fn every_truncated_prefix_and_trailing_input_is_atomic() {
    let (mut p, calls) = fixture(false);
    let c = p.checkpoint().unwrap();
    for end in 0..c.state.len() {
        reject(&mut p, c.state[..end].to_vec());
    }
    let mut bad = c.state;
    bad.push(0);
    reject(&mut p, bad);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn strict_boolean_and_absent_bar_metadata_are_atomic() {
    let (mut p, _) = fixture(false);
    let c = p.checkpoint().unwrap();
    for off in [279, 284, 285, 286, 586, 591, 592, 593, 646] {
        let mut b = c.state.clone();
        b[off] = 2;
        reject(&mut p, b);
    }
    let mut b = c.state;
    b[280] = 1;
    reject(&mut p, b);
}
#[test]
fn duplicate_and_unsorted_function_keys_are_rejected() {
    let (mut p, _) = fixture(false);
    let c = p.checkpoint().unwrap();
    let mut b = c.state.clone();
    b[327..330].fill(0);
    reject(&mut p, b);
    let mut b = c.state;
    b[20] = 1;
    reject(&mut p, b);
}
#[test]
fn topology_and_bar_profile_mismatches_leave_state_unchanged() {
    let (mut p, _) = fixture(false);
    let c = p.checkpoint().unwrap();
    for off in [327, 587, 634, 637, 638, 646] {
        let mut b = c.state.clone();
        b[off] ^= 1;
        reject(&mut p, b);
    }
}
#[test]
fn huge_counts_reject_before_allocating() {
    let (mut p, _) = fixture(false);
    let c = p.checkpoint().unwrap();
    for off in [12, 16] {
        let mut b = c.state.clone();
        b[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        reject(&mut p, b);
    }
}
#[test]
fn late_invalid_routing_base_does_not_change_raw_config() {
    let (mut p, _) = fixture(false);
    write_config(&mut p, 0x10, 0x300000);
    let mut c = p.checkpoint().unwrap().state;
    c[647..655].copy_from_slice(&u64::MAX.to_le_bytes());
    let (mut q, _) = fixture(false);
    reject(&mut q, c);
    assert_eq!(read_mmio(&mut q, 0x100000), Some(0x5a));
}
#[test]
fn replacing_function_without_recompute_preserves_cached_route() {
    let (mut p, _) = fixture(false);
    p.add_function(0, 1, 0, config(false, 0x300000, 4096));
    assert_eq!(read_mmio(&mut p, 0x100000), Some(0x5a));
    let (mut q, _) = fixture(false);
    q.restore_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(read_config(&mut q, 0x10), 0x300000);
    assert_eq!(read_mmio(&mut q, 0x100000), Some(0x5a));
    assert_eq!(read_mmio(&mut q, 0x300000), None);
    write_config(&mut q, 4, 2);
    assert_eq!(read_mmio(&mut q, 0x300000), Some(0x5a));
}
fn overlap(reverse: bool) -> PciStub {
    let mut p = PciStub::new();
    let order = if reverse { [2, 1] } else { [1, 2] };
    for key in order {
        p.attach_mmio(
            0,
            key,
            0,
            config(false, 0x100000, 4096),
            0,
            Box::new(Mmio(key, Arc::new(AtomicUsize::new(0)))),
        );
    }
    p
}
#[test]
fn overlap_priority_survives_and_reordered_handlers_reject() {
    let p = overlap(false);
    let mut q = overlap(false);
    q.restore_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(read_mmio(&mut q, 0x100000), Some(1));
    let mut reversed = overlap(true);
    reject(&mut reversed, p.checkpoint().unwrap().state);
    assert_eq!(read_mmio(&mut reversed, 0x100000), Some(2));
}
#[test]
fn restore_never_calls_handler_and_keeps_destination_identity() {
    let (p, source) = fixture(false);
    let (mut q, dest) = fixture(false);
    q.restore_checkpoint(p.checkpoint().unwrap()).unwrap();
    assert_eq!(source.load(Ordering::SeqCst), 0);
    assert_eq!(dest.load(Ordering::SeqCst), 0);
    assert_eq!(read_mmio(&mut q, 0x100000), Some(0x5a));
    assert_eq!(source.load(Ordering::SeqCst), 0);
    assert_eq!(dest.load(Ordering::SeqCst), 1);
}
#[test]
fn all_raw_config_bytes_and_bar_probe_values_survive() {
    let (mut p, _) = fixture(false);
    for off in (0..256).step_by(4) {
        write_config(&mut p, off as u8, 0x12345678u32.wrapping_add(off as u32));
    }
    let c = p.checkpoint().unwrap();
    let (mut q, _) = fixture(false);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    for off in (0..256).step_by(4) {
        assert_eq!(
            read_config(&mut p, off as u8),
            read_config(&mut q, off as u8)
        );
    }
}
#[test]
fn unknown_record_tag_is_rejected_atomically() {
    let (mut p, _) = fixture(false);
    let mut b = p.checkpoint().unwrap().state;
    b[7] = b'2';
    reject(&mut p, b);
}
/// Publish actual bridge state and routing results for an independent decoder.
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    for index in 0..7 {
        let mut source = if index == 6 {
            overlap(false)
        } else {
            fixture(index == 5).0
        };
        match index {
            1 => write_config(&mut source, 0x10, 0x300000),
            2 => write_config(&mut source, 4, 0),
            3 => write_config(&mut source, 0x10, u32::MAX),
            4 => source.add_function(0, 1, 0, config(false, 0x300000, 4096)),
            5 => write_config(&mut source, 0x10, 0xd001),
            _ => {}
        }
        let mut dest = if index == 6 {
            overlap(false)
        } else {
            fixture(index == 5).0
        };
        let captured = source.checkpoint().unwrap();
        dest.restore_checkpoint(captured.clone()).unwrap();
        let case = directory.join(format!("case-{index}"));
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(case.join("source.bin"), &captured.state).unwrap();
        std::fs::write(case.join("restored.bin"), dest.checkpoint().unwrap().state).unwrap();
        for (name, bridge) in [
            ("source-routes.bin", &mut source),
            ("restored-routes.bin", &mut dest),
        ] {
            let mut bytes = Vec::new();
            for value in [
                read_mmio(bridge, 0x100000),
                read_mmio(bridge, 0x300000),
                bridge.io_read(0xc000),
                bridge.io_read(0xd003),
            ] {
                bytes.extend([u8::from(value.is_some()), value.unwrap_or(0)]);
            }
            std::fs::write(case.join(name), bytes).unwrap();
        }
    }
}
