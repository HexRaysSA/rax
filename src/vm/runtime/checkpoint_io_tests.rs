//! Actual stopped VMM buses service native CPU frontiers without guest entry.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::{IoDevice, MmioDevice};
use crate::vm::vcpu::CheckpointIoState;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MMIO: u64 = 0xf000_0000;
const TAIL: &[u8] = &[0xc6, 0x06, 0x00, 0x20, 0xaa, 0xf4];

struct Fixture {
    vm: Vmm,
    kernel: std::path::PathBuf,
}
impl Fixture {
    fn new(count: u8) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-kvm-checkpoint-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&kernel)
            .unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Kvm),
                kernel: Some(kernel.clone()),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(2 * 1024 * 1024);
        Self {
            vm: Vmm::new_resume(config).unwrap(),
            kernel,
        }
    }

    fn prepare(&mut self, id: usize, code: &[u8]) {
        let pc = 0x1000 + id as u64 * 0x100;
        self.vm
            .guest_mem
            .memory()
            .write_slice(code, GuestAddress(pc))
            .unwrap();
        let CpuState::X86_64(mut state) = self.vm.vcpus[id].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rip = pc;
        state.regs.rflags = 3;
        state.sregs.cs.base = 0;
        state.sregs.cs.selector = 0;
        for segment in [&mut state.sregs.ds, &mut state.sregs.es] {
            segment.base = 0;
            segment.selector = 0;
            segment.limit = u32::MAX;
            segment.g = true;
        }
        state.regs.rdx = 0x3f8;
        state.regs.rdi = 0x3000 + id as u64 * 0x100;
        state.regs.rcx = 3;
        self.vm.vcpus[id]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
    }

    fn exit(&mut self, id: usize) -> VcpuExit {
        // A missing frontier is a test failure, not a successful host yield.
        for _ in 0..100 {
            if let Some(exit) = self.vm.vcpus[id]
                .run_host_slice(Duration::from_millis(10))
                .unwrap()
            {
                return exit;
            }
        }
        panic!("CPU{id} did not reach its native I/O frontier");
    }

    fn settle(&self, id: usize) -> CheckpointIoState {
        self.vm.vcpus[id]
            .settle_checkpoint_io(&mut |event| self.vm.checkpoint_io_service(id, event))
            .unwrap()
    }

    fn tail_is_stopped(&self) {
        assert_eq!(
            self.vm
                .guest_mem
                .memory()
                .read_obj::<u8>(GuestAddress(0x2000))
                .unwrap(),
            0
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.kernel).unwrap();
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn stopped_native_uart_input_services_one_two_four_actual_cpu_owners() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        let mut program = vec![0xf3, 0x66, 0x6d]; // REP INSD in a 16-bit code segment.
        program.extend_from_slice(TAIL);
        for id in 0..usize::from(count) {
            fixture.prepare(id, &program);
            assert!(matches!(
                fixture.exit(id),
                VcpuExit::IoInString {
                    port: 0x3f8,
                    size: 4,
                    count: 3
                }
            ));
        }
        let mut queued = Vec::new();
        for id in 0..count {
            queued.extend_from_slice(&[0x21 + id, 0x42 + id, 0x63 + id]);
        }
        queued.push(0x94);
        let mut serial = fixture.vm.serial.lock().unwrap();
        IoDevice::write(&mut *serial, 0x3fa, 1); // Enable the actual 16-byte RX FIFO.
        serial.queue_input(&queued);
        drop(serial);
        for id in 0..usize::from(count) {
            let input = [0x21 + id as u8, 0x42 + id as u8, 0x63 + id as u8];
            assert_eq!(fixture.settle(id), CheckpointIoState::Complete);
            let mut bytes = [0; 12];
            fixture
                .vm
                .guest_mem
                .memory()
                .read_slice(&mut bytes, GuestAddress(0x3000 + id as u64 * 0x100))
                .unwrap();
            assert_eq!(
                bytes
                    .chunks_exact(4)
                    .map(|element| element[0])
                    .collect::<Vec<_>>(),
                input
            );
            let CpuState::X86_64(state) = fixture.vm.vcpus[id].get_state().unwrap() else {
                unreachable!()
            };
            assert_eq!(state.regs.rcx, 0);
            assert_eq!(state.regs.rdi, 0x300c + id as u64 * 0x100);
            let pc = 0x1000 + id as u64 * 0x100;
            // Completion may retain a REP RIP with RCX=0. The continuation
            // below must advance without another UART transaction.
            assert!(state.regs.rip == pc || state.regs.rip == pc + 3);
            fixture.tail_is_stopped();
        }
        for id in 0..usize::from(count) {
            assert!(matches!(fixture.exit(id), VcpuExit::Hlt));
            assert!(
                fixture.vm.serial.lock().unwrap().has_input(),
                "resumption repeated a consumed UART input"
            );
        }
        assert_eq!(
            IoDevice::read(&mut *fixture.vm.serial.lock().unwrap(), 0x3f8),
            0x94
        );
        assert!(!fixture.vm.serial.lock().unwrap().has_input());
    }
}

type Calls = Arc<std::sync::Mutex<Vec<(bool, u8)>>>;
struct Register {
    value: u8,
    calls: Calls,
}
impl MmioDevice for Register {
    fn read(&mut self, address: u64, bytes: &mut [u8]) {
        assert_eq!((address, bytes.len()), (MMIO, 1));
        bytes[0] = self.value;
        self.calls.lock().unwrap().push((false, self.value));
    }
    fn write(&mut self, address: u64, bytes: &[u8]) {
        assert_eq!((address, bytes.len()), (MMIO, 1));
        self.value = bytes[0];
        self.calls.lock().unwrap().push((true, self.value));
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn stopped_native_rmw_uses_the_registered_vmm_mmio_device_once() {
    let mut fixture = Fixture::new(2);
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    fixture
        .vm
        .mmio_bus
        .register(
            MmioRange { base: MMIO, len: 1 },
            Box::new(Register {
                value: 0x7f,
                calls: calls.clone(),
            }),
        )
        .unwrap();
    let mut program = vec![0x67, 0xfe, 0x05, 0x00, 0x00, 0x00, 0xf0];
    program.extend_from_slice(TAIL);
    fixture.prepare(1, &program);
    assert!(matches!(
        fixture.exit(1),
        VcpuExit::MmioRead {
            addr: MMIO,
            size: 1
        }
    ));
    assert_eq!(fixture.settle(1), CheckpointIoState::Complete);
    assert_eq!(*calls.lock().unwrap(), [(false, 0x7f), (true, 0x80)]);
    fixture.tail_is_stopped();
    assert_eq!(fixture.settle(1), CheckpointIoState::Complete);
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert!(matches!(fixture.exit(1), VcpuExit::Hlt));
    assert_eq!(
        fixture
            .vm
            .guest_mem
            .memory()
            .read_obj::<u8>(GuestAddress(0x2000))
            .unwrap(),
        0xaa
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn stopped_native_acpi_poweroff_retains_the_unserviced_output_batch() {
    let mut fixture = Fixture::new(1);
    let mut program = vec![0xf3, 0x6f]; // REP OUTSW.
    program.extend_from_slice(TAIL);
    fixture.prepare(0, &program);
    fixture
        .vm
        .guest_mem
        .memory()
        .write_slice(&[0, 0x20, 0x34, 0x12, 0x78, 0x56], GuestAddress(0x3000))
        .unwrap();
    let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x604;
    state.regs.rsi = 0x3000;
    fixture.vm.vcpus[0]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    assert!(matches!(
        fixture.exit(0),
        VcpuExit::IoOut { port: 0x604, data } if data == [0, 0x20]
    ));
    assert_eq!(fixture.settle(0), CheckpointIoState::Deferred);
    fixture.tail_is_stopped();
    for _ in 0..2 {
        assert!(matches!(fixture.exit(0), VcpuExit::Shutdown));
        assert_eq!(fixture.settle(0), CheckpointIoState::Deferred);
        fixture.tail_is_stopped();
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn bundle_capture_settles_native_uart_before_locking_the_actual_devices() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        let mut program = vec![0xec]; // IN AL,DX.
        program.extend_from_slice(TAIL);
        for id in 0..usize::from(count) {
            fixture.prepare(id, &program);
            assert!(matches!(
                fixture.exit(id),
                VcpuExit::IoIn {
                    port: 0x3f8,
                    size: 1
                }
            ));
        }
        let mut bytes = (0..count).map(|id| 0x41 + id).collect::<Vec<_>>();
        bytes.push(0x94);
        let mut uart = fixture.vm.serial.lock().unwrap();
        IoDevice::write(&mut *uart, 0x3fa, 1);
        uart.queue_input(&bytes);
        drop(uart);
        let bundle = fixture.vm.take_snapshot_bundle(0).unwrap_or_else(|error| {
            panic!("snapshot did not service the actual native UART frontier: {error}")
        });
        fixture.tail_is_stopped();
        for (id, record) in bundle.cpus().unwrap().entries().iter().enumerate() {
            let CpuState::X86_64(state) = &record.state else {
                unreachable!()
            };
            assert_eq!(state.regs.rax & 255, u64::from(0x41 + id as u8));
            assert_eq!(state.regs.rip, 0x1001 + id as u64 * 0x100);
        }
        // This establishes I/O preparation through the public capture path.
        // Complete native private/shared production remains separate.
        assert!(bundle.backend_contexts().is_none());
        for id in 0..usize::from(count) {
            assert!(matches!(fixture.exit(id), VcpuExit::Hlt));
        }
        let mut uart = fixture.vm.serial.lock().unwrap();
        assert_eq!(IoDevice::read(&mut *uart, 0x3f8), 0x94);
        assert!(!uart.has_input());
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn snapshot_poweroff_fences_every_managed_cpu_and_leaves_peer_devices_untouched() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        let calls = Arc::new(Mutex::new(Vec::new()));
        fixture
            .vm
            .mmio_bus
            .register(
                MmioRange { base: MMIO, len: 1 },
                Box::new(Register {
                    value: 0,
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let mut poweroff = vec![0xf3, 0x6f];
        poweroff.extend_from_slice(TAIL);
        fixture.prepare(0, &poweroff);
        fixture
            .vm
            .guest_mem
            .memory()
            .write_slice(&[0, 0x20, 0x34, 0x12, 0x78, 0x56], GuestAddress(0x3000))
            .unwrap();
        let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rdx = 0x604;
        state.regs.rsi = 0x3000;
        fixture.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        assert!(matches!(
            fixture.exit(0),
            VcpuExit::IoOut { port: 0x604, .. }
        ));
        for id in 1..usize::from(count) {
            let mut program = if id % 2 == 1 {
                vec![0xec]
            } else {
                vec![0x67, 0xc6, 0x05, 0x00, 0x00, 0x00, 0xf0, 0x80]
            };
            program.extend_from_slice(TAIL);
            fixture.prepare(id, &program);
            let event = fixture.exit(id);
            assert!(matches!(
                event,
                VcpuExit::IoIn { .. } | VcpuExit::MmioWrite { .. }
            ));
        }
        fixture.vm.serial.lock().unwrap().queue_input(&[0x94]);
        // Terminal wire production is still required. The failed capture must
        // nevertheless retain power-off and stop every later device callback.
        assert!(fixture.vm.take_snapshot_bundle(0).is_err());
        for id in 0..usize::from(count) {
            assert!(
                matches!(fixture.exit(id), VcpuExit::Shutdown),
                "power-off snapshot did not fence every managed CPU"
            );
            assert_eq!(
                fixture.vm.vcpus[id].native_run_eligibility().unwrap(),
                Some(true)
            );
            assert!(matches!(
                fixture.vm.vcpus[id].run().unwrap(),
                VcpuExit::Shutdown
            ));
            assert_eq!(fixture.settle(id), CheckpointIoState::Deferred);
        }
        fixture.tail_is_stopped();
        assert!(calls.lock().unwrap().is_empty());
        assert!(fixture.vm.serial.lock().unwrap().has_input());
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn stopped_poweroff_quiesces_a_peer_already_inside_public_run() {
    use std::sync::mpsc;
    use std::time::Instant;

    let mut fixture = Fixture::new(2);
    fixture.prepare(0, &[0xef]); // OUT DX,AX in a 16-bit segment.
    let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x604;
    state.regs.rax = 0x2000;
    fixture.vm.vcpus[0]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    assert!(matches!(
        fixture.exit(0),
        VcpuExit::IoOut { port: 0x604, .. }
    ));
    fixture.prepare(
        1,
        &[
            0xc6, 0x06, 0x00, 0x41, 0x01, // Publish that native entry occurred.
            0x80, 0x3e, 0x00, 0x40, 0x00, // CMP byte [0x4000],0.
            0x74, 0xf9, // JE back to CMP.
            0xf4, // Negative-control escape: HLT.
        ],
    );
    let mut peer = fixture.vm.vcpus.pop().unwrap();
    let (finished, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        finished.send(peer.run()).unwrap();
        peer
    });
    // This independent escape also bounds an incomplete implementation whose
    // power-off writer waits forever on an unbounded public run lease.
    let (cancel, timeout) = mpsc::channel();
    let escaped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let escape_flag = escaped.clone();
    let escape_memory = fixture.vm.guest_mem.memory().clone();
    let escape = std::thread::spawn(move || {
        if timeout.recv_timeout(Duration::from_secs(5)).is_err() {
            escape_flag.store(true, Ordering::Release);
            escape_memory.write_obj(1_u8, GuestAddress(0x4000)).unwrap();
        }
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut entered = false;
    while Instant::now() < deadline {
        if fixture
            .vm
            .guest_mem
            .memory()
            .read_obj::<u8>(GuestAddress(0x4100))
            .unwrap()
            == 1
        {
            entered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let settled = fixture.vm.vcpus[0]
        .settle_checkpoint_io(&mut |event| fixture.vm.checkpoint_io_service(0, event));
    let stopped = result.recv_timeout(Duration::from_secs(2));
    if stopped.is_err() {
        escaped.store(true, Ordering::Release);
        fixture
            .vm
            .guest_mem
            .memory()
            .write_obj(1_u8, GuestAddress(0x4000))
            .unwrap();
    }
    let _ = cancel.send(());
    escape.join().unwrap();
    drop(worker.join().unwrap());
    assert!(entered, "the peer did not execute its native entry witness");
    assert_eq!(settled.unwrap(), CheckpointIoState::Deferred);
    assert!(
        !escaped.load(Ordering::Acquire),
        "power-off did not quiesce the peer already inside public run"
    );
    assert!(matches!(stopped.unwrap().unwrap(), VcpuExit::Shutdown));
    assert_eq!(
        fixture
            .vm
            .guest_mem
            .memory()
            .read_obj::<u8>(GuestAddress(0x4000))
            .unwrap(),
        0
    );
}
