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
        let data = read(
            &mut bus,
            &serial,
            BackendKind::Emulator,
            None,
            0x2000,
            size,
            3,
        )
        .unwrap();
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
            let data = read(
                &mut bus,
                &serial,
                BackendKind::Emulator,
                None,
                port,
                size,
                3,
            )
            .unwrap();
            let length = 3 * usize::from(size);
            assert_eq!(*accesses.lock().unwrap(), vec![port; length]);
            assert_eq!(data, vec![port as u8; length]);
        }
    }
}

#[test]
fn native_pit_uses_only_the_low_lane_in_each_io_element() {
    for port in [0x40, 0x41, 0x42, 0x61] {
        for width in [1u8, 2, 4] {
            let (mut bus, serial, accesses) = fixture(port);
            let data = read(&mut bus, &serial, BackendKind::Kvm, None, port, width, 3).unwrap();
            let mut element = vec![0; usize::from(width)];
            element[0] = port as u8;
            assert_eq!(data, element.repeat(3));
            assert_eq!(*accesses.lock().unwrap(), vec![port; 3]);
        }
    }
}

#[test]
fn invalid_geometry_has_no_port_side_effects() {
    let (mut bus, serial, accesses) = fixture(0x2000);
    for (size, count) in [(0, 1), (3, 1), (8, 1), (1, 0)] {
        assert!(
            read(
                &mut bus,
                &serial,
                BackendKind::Emulator,
                None,
                0x2000,
                size,
                count
            )
            .is_err()
        );
        assert!(accesses.lock().unwrap().is_empty());
    }
}

#[test]
fn an_i8042_irq_reedge_failure_disables_native_guest_entry() {
    use crate::devices::bus::MmioBus;
    use crate::machine::{Machine, pc::PcMachine};
    use crate::vm::vcpu::VCpu;
    use std::any::Any;
    use std::sync::atomic::{AtomicBool, Ordering};
    use vm_memory::GuestMemoryMmap;

    #[derive(Default)]
    struct FaultedIrqs {
        calls: Mutex<Vec<(u32, bool)>>,
        entry_disabled: AtomicBool,
    }

    impl Vm for FaultedIrqs {
        fn uses_native_x86_irqchip(&self) -> bool {
            true
        }

        fn create_vcpu(&self, _id: u32, _memory: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
            unreachable!("the route test does not create a CPU");
        }

        fn poison_checkpoint_restore(&self) {
            self.entry_disabled.store(true, Ordering::Release);
        }

        fn set_irq_line(&self, line: u32, level: bool) -> Result<()> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((line, level));
            if calls.len() == 3 {
                Err(Error::Emulator("injected native I/O APIC failure".into()))
            } else {
                Ok(())
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let machine = PcMachine::new();
    let mut io = IoBus::new();
    let mut mmio = MmioBus::new();
    let pc = machine
        .setup_owned_devices(&mut io, &mut mmio)
        .unwrap()
        .unwrap();
    let pic = Mutex::new(DualPic::new());
    let vm = FaultedIrqs::default();
    let keyboard = KeyboardIrqs {
        pc: &pc,
        pic: &pic,
        vm: &vm,
    };
    keyboard.write(STATUS_PORT, 0x60).unwrap();
    keyboard.write(DATA_PORT, 0x02).unwrap();
    for reply in [0xa1, 0x42] {
        keyboard.write(STATUS_PORT, 0xd3).unwrap();
        keyboard.write(DATA_PORT, reply).unwrap();
    }
    assert_eq!(vm.calls.lock().unwrap().as_slice(), &[(12, true)]);
    let error = keyboard.read_data().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected native I/O APIC failure")
    );
    assert_eq!(
        vm.calls.lock().unwrap().as_slice(),
        &[(12, true), (12, false), (12, true)]
    );
    assert_eq!(pc.i8042.lock().unwrap().output_irq(), Some(12));
    assert!(vm.entry_disabled.load(Ordering::Acquire));
}
