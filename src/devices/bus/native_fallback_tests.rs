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
    bus.set_ram_fallback(memory.clone(), 0x4000).unwrap();
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

const LOW_RAM_END: u64 = 0xc000_0000;
const HIGH_RAM_START: u64 = 0x1_0000_0000;
const HIGH_RAM_END: u64 = HIGH_RAM_START + 0x2000;

fn large_ram() -> (MmioBus, Arc<GuestMemoryMmap>) {
    // Sparse backing keeps the boundary tests small while supplying real bytes
    // on both sides of the low/hole and high/padding boundaries.
    let memory = Arc::new(
        GuestMemoryMmap::from_ranges(&[
            (GuestAddress(LOW_RAM_END - 0x1000), 0x2000),
            (GuestAddress(HIGH_RAM_START), 0x3000),
        ])
        .unwrap(),
    );
    memory
        .write_slice(&[0x33; 0x2000], GuestAddress(LOW_RAM_END - 0x1000))
        .unwrap();
    memory
        .write_slice(&[0x33; 0x3000], GuestAddress(HIGH_RAM_START))
        .unwrap();
    let mut bus = MmioBus::new();
    bus.set_ram_fallback(memory.clone(), LOW_RAM_END + 0x2000)
        .unwrap();
    (bus, memory)
}

#[test]
fn high_ram_fallback_reads_writes_and_rmw_stop_at_configured_capacity() {
    let (mut bus, memory) = large_ram();
    let address = HIGH_RAM_END - 8;
    let mut bytes = [0; 8];
    bus.read(address, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33; 8]);
    bus.write(address, &[0x55; 8]).unwrap();
    assert_eq!(
        bus.read_modify_write(address, 4, MmioRmwOp::Exchange(0x8877_6655))
            .unwrap(),
        [0x55; 4]
    );
    memory
        .read_slice(&mut bytes, GuestAddress(address))
        .unwrap();
    assert_eq!(bytes, [0x55, 0x66, 0x77, 0x88, 0x55, 0x55, 0x55, 0x55]);
    let mut edge = [0; 4];
    bus.read(HIGH_RAM_END - 2, &mut edge).unwrap();
    assert_eq!(edge, [0x55, 0x55, 0xff, 0xff]);
    assert!(
        bus.read_modify_write(HIGH_RAM_END - 2, 4, MmioRmwOp::Exchange(0))
            .is_err()
    );
    bus.write(HIGH_RAM_END - 2, &[0x99; 4]).unwrap();
    memory
        .read_slice(&mut edge, GuestAddress(HIGH_RAM_END - 2))
        .unwrap();
    assert_eq!(edge, [0x99, 0x99, 0x33, 0x33]);
}

#[test]
fn pc_device_window_remains_open_bus_despite_retained_backing() {
    let (mut bus, memory) = large_ram();
    let mut bytes = [0; 4];
    bus.read(LOW_RAM_END, &mut bytes).unwrap();
    assert_eq!(bytes, [0xff; 4]);
    bus.read(LOW_RAM_END - 2, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33, 0x33, 0xff, 0xff]);
    bus.write(LOW_RAM_END - 2, &[0x99; 4]).unwrap();
    memory
        .read_slice(&mut bytes, GuestAddress(LOW_RAM_END - 2))
        .unwrap();
    assert_eq!(bytes, [0x99, 0x99, 0x33, 0x33]);
    assert!(
        bus.read_modify_write(LOW_RAM_END - 2, 4, MmioRmwOp::Exchange(0))
            .is_err()
    );
    assert_eq!(
        bus.read_modify_write(LOW_RAM_END, 4, MmioRmwOp::Exchange(0))
            .unwrap(),
        [0xff; 4]
    );
    bus.read(HIGH_RAM_START - 2, &mut bytes).unwrap();
    assert_eq!(bytes, [0xff, 0xff, 0x33, 0x33]);
    bus.write(HIGH_RAM_START - 2, &[0x77; 4]).unwrap();
    bus.read(HIGH_RAM_START, &mut bytes).unwrap();
    assert_eq!(bytes, [0x77, 0x77, 0x33, 0x33]);
}

#[test]
fn high_64_bit_pci_bar_preserves_collateral_ram_and_transaction_width() {
    let (mut bus, memory) = large_ram();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let mut bridge = PciStub::new();
    let mut config = ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(0, Bar::mem64(0x20));
    config.set_u32(0x10, 0x1024);
    config.set_u32(0x14, 1);
    config.set_u16(4, 2);
    bridge.attach_mmio(0, 1, 0, config, 0, Box::new(Device(seen.clone())));
    assert_eq!(bridge.mmio_ranges()[0].base, HIGH_RAM_START + 0x1020);
    bus.set_pci(Arc::new(Mutex::new(bridge)));
    let mut bytes = [0; 0x24];
    bus.read(HIGH_RAM_START + 0x101e, &mut bytes).unwrap();
    assert_eq!(&bytes[..2], &[0x33; 2]);
    assert_eq!(&bytes[2..0x22], &[0xab; 0x20]);
    assert_eq!(&bytes[0x22..], &[0x33; 2]);
    bus.write(HIGH_RAM_START + 0x101e, &[0x55; 0x24]).unwrap();
    assert_eq!(
        seen.lock().unwrap().0,
        [(0, vec![0xab; 0x20], false), (0, vec![0x55; 0x20], true)]
    );
    memory
        .read_slice(&mut bytes, GuestAddress(HIGH_RAM_START + 0x101e))
        .unwrap();
    assert_eq!(&bytes[..2], &[0x55; 2]);
    assert_eq!(&bytes[2..0x22], &[0x33; 0x20]);
    assert_eq!(&bytes[0x22..], &[0x55; 2]);
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

#[test]
fn invalid_ram_fallback_profile_retains_the_previous_binding() {
    let (mut bus, _, _, memory) = configured();
    assert!(bus.set_ram_fallback(memory, u64::MAX).is_err());
    let mut bytes = [0; 4];
    bus.read(0x1000, &mut bytes).unwrap();
    assert_eq!(bytes, [0x33; 4]);
}
