//! A BAR may move into reported RAM and occupy less than one native page.
use super::*;
use crate::devices::pci::{Bar, ConfigSpace, PciStub};
use std::sync::{Arc, Mutex};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[derive(Default, Debug)]
struct Seen(Vec<(u64, Vec<u8>, bool)>);
struct Device(Arc<Mutex<Seen>>);
impl MmioDevice for Device {
    fn read(&mut self, addr: u64, bytes: &mut [u8]) {
        bytes.fill(0xab);
        self.0.lock().unwrap().0.push((addr, bytes.to_vec(), false));
    }
    fn write(&mut self, addr: u64, bytes: &[u8]) {
        self.0.lock().unwrap().0.push((addr, bytes.to_vec(), true));
    }
}
fn configured() -> (
    MmioBus,
    Arc<Mutex<PciStub>>,
    Arc<Mutex<Seen>>,
    Arc<GuestMemoryMmap>,
) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    memory
        .write_slice(&vec![0x33; 0x8000], GuestAddress(0))
        .unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let mut pci = PciStub::new();
    let mut config = ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(0, Bar::mem32(0x20));
    config.set_u32(0x10, 0x2020);
    config.set_u16(4, 2);
    pci.attach_mmio(0, 1, 0, config, 0, Box::new(Device(seen.clone())));
    let pci = Arc::new(Mutex::new(pci));
    let mut bus = MmioBus::new();
    bus.set_pci(pci.clone());
    bus.set_ram_fallback(memory.clone(), 0x4000);
    (bus, pci, seen, memory)
}
fn config_write(bridge: &Arc<Mutex<PciStub>>, offset: u8, value: u32) {
    let mut bridge = bridge.lock().unwrap();
    for (i, byte) in (0x8000_0800u32 | u32::from(offset))
        .to_le_bytes()
        .iter()
        .enumerate()
    {
        IoDevice::write(&mut *bridge, 0xcf8 + i as u16, *byte);
    }
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        IoDevice::write(&mut *bridge, 0xcfc + i as u16, *byte);
    }
}

#[test]
fn pci_transactions_keep_width_and_collateral_ram_and_padding_stay_distinct() {
    let (mut bus, _, seen, memory) = configured();
    let mut bytes = [0; 0x24];
    bus.read(0x201e, &mut bytes).unwrap();
    assert_eq!(&bytes[..2], &[0x33; 2]);
    assert_eq!(&bytes[2..0x22], &[0xab; 0x20]);
    assert_eq!(&bytes[0x22..], &[0x33; 2]);
    bus.write(0x201e, &[0x55; 0x24]).unwrap();
    assert_eq!(
        seen.lock().unwrap().0,
        [(0, vec![0xab; 0x20], false), (0, vec![0x55; 0x20], true)]
    );
    let mut raw = [0; 0x24];
    memory.read_slice(&mut raw, GuestAddress(0x201e)).unwrap();
    assert_eq!(&raw[..2], &[0x55; 2]);
    assert_eq!(&raw[2..0x22], &[0x33; 0x20]);
    assert_eq!(&raw[0x22..], &[0x55; 2]);
    let mut edge = [0; 4];
    bus.read(0x3ffe, &mut edge).unwrap();
    assert_eq!(edge, [0x33, 0x33, 0xff, 0xff]);
    bus.write(0x4000, &[0x99; 4]).unwrap();
    memory.read_slice(&mut edge, GuestAddress(0x4000)).unwrap();
    assert_eq!(edge, [0x33; 4]);
}

#[test]
fn active_bar_ranges_follow_guest_config_relocation_probe_and_decode_enable() {
    let (mut bus, pci, seen, _) = configured();
    assert_eq!(pci.lock().unwrap().mmio_ranges()[0].base, 0x2020);
    config_write(&pci, 0x10, 0x3020);
    let mut bytes = [0; 4];
    bus.read(0x2020, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33; 4]);
    bus.read(0x3020, &mut bytes).unwrap();
    assert_eq!(bytes, [0xab; 4]);
    config_write(&pci, 0x10, u32::MAX);
    assert!(pci.lock().unwrap().mmio_ranges().is_empty());
    bus.read(0x3020, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33; 4]);
    config_write(&pci, 0x10, 0x2020);
    config_write(&pci, 4, 0);
    assert!(pci.lock().unwrap().mmio_ranges().is_empty());
    bus.read(0x2020, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33; 4]);
    config_write(&pci, 4, 2);
    bus.read(0x2020, &mut bytes).unwrap();
    assert_eq!(bytes, [0xab; 4]);
    assert_eq!(seen.lock().unwrap().0.len(), 2);
}

#[test]
fn fixed_devices_have_priority_over_pci_and_native_ram_fallback() {
    let (mut bus, _, pci_seen, _) = configured();
    let fixed = Arc::new(Mutex::new(Seen::default()));
    bus.register(
        MmioRange {
            base: 0x2020,
            len: 0x20,
        },
        Box::new(Device(fixed.clone())),
    )
    .unwrap();
    bus.write(0x2024, &[1, 2, 3, 4]).unwrap();
    assert!(pci_seen.lock().unwrap().0.is_empty());
    assert_eq!(fixed.lock().unwrap().0, [(0x2024, vec![1, 2, 3, 4], true)]);
}

#[test]
fn ram_and_pci_rmw_return_old_value_and_reject_cross_owner_access_before_effects() {
    let (mut bus, _, seen, memory) = configured();
    let old = bus
        .read_modify_write(0x2000, 4, MmioRmwOp::Exchange(0x88776655))
        .unwrap();
    assert_eq!(old, [0x33; 4]);
    let mut raw = [0; 4];
    memory.read_slice(&mut raw, GuestAddress(0x2000)).unwrap();
    assert_eq!(raw, [0x55, 0x66, 0x77, 0x88]);
    let old = bus
        .read_modify_write(0x2024, 4, MmioRmwOp::Exchange(0x88776655))
        .unwrap();
    assert_eq!(old, [0xab; 4]);
    assert_eq!(
        seen.lock().unwrap().0,
        [
            (4, vec![0xab; 4], false),
            (4, vec![0x55, 0x66, 0x77, 0x88], true)
        ]
    );
    let count = seen.lock().unwrap().0.len();
    for address in [0x201e, 0x203e, 0x3ffe] {
        assert!(bus.read_modify_write(address, 4, MmioRmwOp::Not).is_err());
    }
    assert_eq!(seen.lock().unwrap().0.len(), count);
}

#[test]
fn poisoned_pci_layout_stops_before_destination_or_ram_publication() {
    let (mut bus, pci, _, memory) = configured();
    assert!(
        std::thread::spawn(move || {
            let _lock = pci.lock().unwrap();
            panic!("owned poison fixture");
        })
        .join()
        .is_err()
    );
    let mut raw = [0x55; 4];
    assert!(bus.read(0x2000, &mut raw).is_err());
    assert_eq!(raw, [0x55; 4]);
    assert!(bus.write(0x2000, &[0x44; 4]).is_err());
    memory.read_slice(&mut raw, GuestAddress(0x2000)).unwrap();
    assert_eq!(raw, [0x33; 4]);
}
