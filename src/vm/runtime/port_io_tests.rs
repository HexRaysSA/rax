use super::*;
use crate::devices::bus::IoRange;

struct RecordingPort {
    reads: Arc<Mutex<Vec<u16>>>,
}
impl IoDevice for RecordingPort {
    fn read(&mut self, port: u16) -> u8 {
        self.reads.lock().unwrap().push(port);
        port as u8
    }
    fn write(&mut self, _: u16, _: u8) {}
}

fn fixture(port: u16) -> (IoBus, Arc<Mutex<Serial16550>>, Arc<Mutex<Vec<u16>>>) {
    let mut bus = IoBus::new();
    let accesses = Arc::new(Mutex::new(Vec::new()));
    bus.register(
        IoRange { base: port, len: 8 },
        Box::new(RecordingPort {
            reads: accesses.clone(),
        }),
    )
    .unwrap();
    (
        bus,
        Arc::new(Mutex::new(Serial16550::new(SERIAL_BASE))),
        accesses,
    )
}

#[test]
fn each_generic_element_uses_its_own_scalar_byte_lanes() {
    for size in [1u8, 2, 4] {
        let (mut bus, serial, accesses) = fixture(0x2000);
        let data = read(&mut bus, &serial, 0x2000, size, 3).unwrap();
        let expected = (0..3)
            .flat_map(|_| (0..u16::from(size)).map(|lane| 0x2000 + lane))
            .collect::<Vec<_>>();
        assert_eq!(*accesses.lock().unwrap(), expected);
        assert_eq!(
            data,
            expected.iter().map(|&port| port as u8).collect::<Vec<_>>()
        );
    }
}

#[test]
fn ide_data_register_uses_the_same_fifo_port_for_every_byte() {
    for port in [0x1f0, 0x170] {
        for size in [1u8, 2, 4] {
            let (mut bus, serial, accesses) = fixture(port);
            let data = read(&mut bus, &serial, port, size, 3).unwrap();
            let length = 3 * usize::from(size);
            assert_eq!(*accesses.lock().unwrap(), vec![port; length]);
            assert_eq!(data, vec![port as u8; length]);
        }
    }
}

#[test]
fn invalid_geometry_has_no_port_side_effects() {
    let (mut bus, serial, accesses) = fixture(0x2000);
    for (size, count) in [(0, 1), (3, 1), (8, 1), (1, 0)] {
        assert!(read(&mut bus, &serial, 0x2000, size, count).is_err());
        assert!(accesses.lock().unwrap().is_empty());
    }
}
