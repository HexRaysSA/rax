//! Device transaction boundaries are observable, including register side effects.
use super::{MmioBus, MmioDevice, MmioRange};
use std::sync::{Arc, Mutex};

#[derive(Debug, PartialEq, Eq)]
enum Access {
    Read(u8, u64, usize),
    Write(u8, u64, Vec<u8>),
}
struct Probe {
    id: u8,
    log: Arc<Mutex<Vec<Access>>>,
}
impl MmioDevice for Probe {
    fn read(&mut self, address: u64, data: &mut [u8]) {
        self.log
            .lock()
            .unwrap()
            .push(Access::Read(self.id, address, data.len()));
        for (offset, byte) in data.iter_mut().enumerate() {
            *byte = address.wrapping_add(offset as u64) as u8;
        }
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        self.log
            .lock()
            .unwrap()
            .push(Access::Write(self.id, address, data.to_vec()));
    }
}
fn add(bus: &mut MmioBus, log: &Arc<Mutex<Vec<Access>>>, id: u8, base: u64, len: u64) {
    bus.register(
        MmioRange { base, len },
        Box::new(Probe {
            id,
            log: log.clone(),
        }),
    )
    .unwrap();
}

#[test]
fn contiguous_device_access_keeps_each_complete_transaction_width() {
    for width in [1, 2, 4, 8, 16, 64] {
        let mut bus = MmioBus::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        add(&mut bus, &log, 1, 0x1000, 0x100);
        let mut output = vec![0; width];
        bus.read(0x1003, &mut output).unwrap();
        let expected: Vec<u8> = (0..width).map(|i| 3 + i as u8).collect();
        assert_eq!(output, expected);
        bus.write(0x1011, &output).unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            vec![
                Access::Read(1, 0x1003, width),
                Access::Write(1, 0x1011, expected)
            ]
        );
    }
}

#[test]
fn mapped_boundaries_and_holes_define_the_only_split_points() {
    let mut bus = MmioBus::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    // Deliberately register out of address order.
    add(&mut bus, &log, 2, 0x1006, 4);
    add(&mut bus, &log, 1, 0x1000, 4);
    let mut output = [0; 8];
    bus.read(0x1002, &mut output).unwrap();
    assert_eq!(output, [2, 3, 0xff, 0xff, 6, 7, 8, 9]);
    bus.write(0x1002, &[10, 11, 12, 13, 14, 15, 16, 17])
        .unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            Access::Read(1, 0x1002, 2),
            Access::Read(2, 0x1006, 4),
            Access::Write(1, 0x1002, vec![10, 11]),
            Access::Write(2, 0x1006, vec![14, 15, 16, 17])
        ]
    );
}

#[test]
fn wrapping_access_fails_before_any_device_or_destination_change() {
    let mut bus = MmioBus::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    add(&mut bus, &log, 1, u64::MAX - 3, 3);
    let mut data = [0x5a; 4];
    assert!(bus.read(u64::MAX - 2, &mut data).is_err());
    assert!(bus.write(u64::MAX - 2, &[1, 2, 3, 4]).is_err());
    assert_eq!(data, [0x5a; 4]);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn empty_and_unmapped_transactions_have_no_device_effects() {
    let mut bus = MmioBus::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    add(&mut bus, &log, 1, 0x1000, 0x100);
    bus.read(u64::MAX, &mut []).unwrap();
    bus.write(u64::MAX, &[]).unwrap();
    let mut data = [0; 7];
    bus.read(0x2000, &mut data).unwrap();
    bus.write(0x2000, &[1, 2, 3]).unwrap();
    assert_eq!(data, [0xff; 7]);
    assert!(log.lock().unwrap().is_empty());
}
