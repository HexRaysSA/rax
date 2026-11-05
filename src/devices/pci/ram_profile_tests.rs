//! Public bridge routing and checkpoint contracts for native high RAM.
use crate::devices::bus::{IoDevice, MmioDevice};
use crate::devices::pci::{Bar, ConfigSpace, PciStub};

struct Data;
impl MmioDevice for Data {
    fn read(&mut self, _address: u64, bytes: &mut [u8]) {
        bytes.fill(0x5a);
    }
    fn write(&mut self, _address: u64, _bytes: &[u8]) {}
}

fn endpoint(high: u32, wide: bool) -> PciStub {
    let mut bridge = PciStub::new();
    let bar = if wide {
        Bar::mem64(0x20)
    } else {
        Bar::mem32(0x20)
    };
    let mut config = ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(0, bar);
    config.set_u32(0x10, 0x2020 | if wide { 4 } else { 0 });
    if wide {
        config.set_u32(0x14, high);
    }
    config.set_u16(4, 2);
    bridge.attach_mmio(0, 1, 0, config, 0, Box::new(Data));
    bridge
}

fn config_write(bridge: &mut PciStub, offset: u8, value: u32) {
    let address = 0x8000_0800u32 | u32::from(offset);
    for (index, byte) in address.to_le_bytes().into_iter().enumerate() {
        IoDevice::write(bridge, 0xcf8 + index as u16, byte);
    }
    for (index, byte) in value.to_le_bytes().into_iter().enumerate() {
        IoDevice::write(bridge, 0xcfc + index as u16, byte);
    }
}

#[test]
fn memory32_endpoint_and_checkpoint_remain_compatible() {
    let mut source = endpoint(0, false);
    assert_eq!(source.mmio_ranges()[0].base, 0x2020);
    let mut bytes = [0; 4];
    assert!(source.mmio_read(0x2024, &mut bytes));
    assert_eq!(bytes, [0x5a; 4]);
    let saved = source.checkpoint().unwrap();
    let mut target = endpoint(0, false);
    target.restore_checkpoint(saved.clone()).unwrap();
    assert_eq!(target.checkpoint().unwrap(), saved);
}

#[test]
fn memory64_endpoint_uses_both_dwords_and_follows_high_word_writes() {
    let mut bridge = endpoint(1, true);
    assert_eq!(bridge.mmio_ranges()[0].base, 0x1_0000_2020);
    let mut bytes = [0; 4];
    assert!(bridge.mmio_read(0x1_0000_2024, &mut bytes));
    assert_eq!(bytes, [0x5a; 4]);
    assert!(!bridge.mmio_read(0x2024, &mut bytes));
    config_write(&mut bridge, 0x14, 2);
    assert_eq!(bridge.mmio_ranges()[0].base, 0x2_0000_2020);
    assert!(!bridge.mmio_read(0x1_0000_2024, &mut bytes));
    assert!(bridge.mmio_read(0x2_0000_2024, &mut bytes));
}

#[test]
fn memory64_route_survives_the_complete_bridge_checkpoint() {
    let source = endpoint(1, true);
    let saved = source.checkpoint().unwrap();
    let base = u64::from_le_bytes(saved.state[saved.state.len() - 8..].try_into().unwrap());
    assert_eq!(base, 0x1_0000_2020);
    let mut target = endpoint(2, true);
    target.restore_checkpoint(saved.clone()).unwrap();
    assert_eq!(target.mmio_ranges()[0].base, 0x1_0000_2020);
    assert_eq!(target.checkpoint().unwrap(), saved);
}

#[test]
fn malformed_cached_route_rejects_before_any_publication() {
    let source = endpoint(0, false);
    for base in [0x3021u64, u64::MAX - 0x1f] {
        let mut bad = source.checkpoint().unwrap();
        let end = bad.state.len();
        bad.state[end - 8..].copy_from_slice(&base.to_le_bytes());
        let mut target = endpoint(0, false);
        let before = target.checkpoint().unwrap();
        assert!(target.validate_checkpoint(&bad).is_err());
        assert!(target.restore_checkpoint(bad).is_err());
        assert_eq!(target.checkpoint().unwrap(), before);
    }
}

#[test]
fn memory64_cached_route_survives_replaced_function_configuration() {
    for command in [0, 2] {
        let mut source = endpoint(1, true);
        let mut replacement =
            ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(0, Bar::mem64(0x20));
        replacement.set_u32(0x10, 0x2024);
        replacement.set_u32(0x14, 2);
        replacement.set_u16(4, command);
        source.add_function(0, 1, 0, replacement);
        assert_eq!(source.mmio_ranges()[0].base, 0x1_0000_2020);
        let saved = source.checkpoint().unwrap();
        let mut target = endpoint(2, true);
        target.restore_checkpoint(saved.clone()).unwrap();
        assert_eq!(target.mmio_ranges()[0].base, 0x1_0000_2020);
        assert_eq!(target.checkpoint().unwrap(), saved);
        let mut bytes = [0; 4];
        assert!(target.mmio_read(0x1_0000_2024, &mut bytes));
        assert_eq!(bytes, [0x5a; 4]);
        assert!(!target.mmio_read(0x2_0000_2024, &mut bytes));
        config_write(&mut target, 4, 2);
        assert_eq!(target.mmio_ranges()[0].base, 0x2_0000_2020);
    }
}

#[test]
fn legacy_truncated_memory64_cached_routes_keep_their_saved_routing() {
    let source = endpoint(1, true);
    let mut saved = source.checkpoint().unwrap();
    // Earlier writers stored the truncated live route in this existing u64
    // field. Restore retains the actual saved route independently of BAR bytes.
    let end = saved.state.len();
    saved.state[end - 8..].copy_from_slice(&0x2020u64.to_le_bytes());
    let mut target = endpoint(2, true);
    target.restore_checkpoint(saved.clone()).unwrap();
    assert_eq!(target.checkpoint().unwrap(), saved);
    assert_eq!(target.mmio_ranges()[0].base, 0x2020);
    let mut bytes = [0; 4];
    assert!(target.mmio_read(0x2024, &mut bytes));
    assert_eq!(bytes, [0x5a; 4]);
    assert!(!target.mmio_read(0x1_0000_2024, &mut bytes));
}

#[test]
fn wrapping_or_unpaired_memory64_windows_never_become_live_routes() {
    let mut wrapping = endpoint(0xffff_ffff, true);
    config_write(&mut wrapping, 0x10, 0xffff_ffe4);
    assert!(wrapping.mmio_ranges().is_empty());

    let mut config = ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(5, Bar::mem64(0x20));
    config.set_u32(0x24, 0x2024);
    config.set_u32(0x28, 1);
    config.set_u16(4, 2);
    let mut unpaired = PciStub::new();
    unpaired.attach_mmio(0, 1, 0, config, 5, Box::new(Data));
    assert!(unpaired.mmio_ranges().is_empty());
}

#[test]
fn memory64_size_probe_and_command_disable_keep_the_endpoint_unrouted() {
    let mut bridge = endpoint(1, true);
    config_write(&mut bridge, 4, 0);
    assert!(bridge.mmio_ranges().is_empty());
    config_write(&mut bridge, 0x10, u32::MAX);
    config_write(&mut bridge, 0x14, u32::MAX);
    config_write(&mut bridge, 4, 2);
    assert!(bridge.mmio_ranges().is_empty());
    let saved = bridge.checkpoint().unwrap();
    let mut target = endpoint(0, true);
    target.restore_checkpoint(saved.clone()).unwrap();
    assert!(target.mmio_ranges().is_empty());
    assert_eq!(target.checkpoint().unwrap(), saved);
}
