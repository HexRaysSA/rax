//! Actual stopped VMM buses service native CPU frontiers without guest entry.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::{IoDevice, MmioDevice};
use crate::vm::vcpu::CheckpointIoState;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

#[path = "checkpoint_io_timer_tests.rs"]
mod timer;

static NEXT: AtomicU64 = AtomicU64::new(0);
const MMIO: u64 = 0xf000_0000;
const TAIL: &[u8] = &[0xc6, 0x06, 0x00, 0x20, 0xaa, 0xf4];

struct Fixture {
    vm: Vmm,
    kernel: std::path::PathBuf,
}
impl Fixture {
    fn new(count: u8) -> Self {
        Self::with_memory(count, 2 * 1024 * 1024)
    }

    fn with_memory(count: u8, memory: u64) -> Self {
        Self::with_construction(count, memory, ConstructionMode::RestoreTarget)
    }

    fn with_construction(count: u8, memory: u64, mode: ConstructionMode) -> Self {
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
        config.memory = MemorySize(memory);
        Self {
            vm: Vmm::build(config, mode).unwrap(),
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
#[ignore = "requires native Linux KVM with userspace interrupt ownership"]
fn stopped_native_uart_output_uses_the_userspace_irq_controller() {
    let mut fixture = Fixture::new(1);
    assert!(!fixture.vm.vm.uses_native_x86_irqchip());
    // MOV DX, 3F9h; MOV AL, 1; OUT DX, AL; HLT.
    fixture.prepare(0, &[0xba, 0xf9, 0x03, 0xb0, 0x01, 0xee, 0xf4]);
    let mut uart = fixture.vm.serial.lock().unwrap();
    IoDevice::write(&mut *uart, 0x3fc, 8); // Enable the PC UART OUT2 IRQ gate.
    uart.queue_input(&[0x9a]);
    drop(uart);
    fixture.vm.io_bus.write(0x21, &[!0x10]).unwrap(); // Unmask PIC IRQ4.

    assert!(matches!(
        fixture.exit(0),
        VcpuExit::IoOut { port: 0x3f9, data } if data == [1]
    ));
    assert_eq!(fixture.settle(0), CheckpointIoState::Complete);
    assert!(fixture.vm.serial.lock().unwrap().has_pending_interrupt());
    assert_eq!(
        fixture.vm.pic.lock().unwrap().get_pending_vector(),
        Some(0x24)
    );
    assert!(matches!(fixture.exit(0), VcpuExit::Hlt));
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
        assert!(bundle.vm_context().is_some());
        assert!(
            bundle
                .backend_contexts()
                .unwrap()
                .entries()
                .iter()
                .all(Option::is_some)
        );
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
        let memory = if count == 1 { 128 << 20 } else { 2 << 20 };
        let mut fixture = Fixture::with_memory(count, memory);
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
        let bundle = fixture.vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(bundle.saved_kvm_irqchip(), Some(false));
        let mut target = Fixture::with_memory(count, memory);
        if count == 1 {
            let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
            target.vm = Vmm::new_resume_bundle(config, &bundle).unwrap();
        } else {
            target.vm.restore_snapshot_bundle(&bundle).unwrap();
        }
        let stopped = target.vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(stopped.clock(), bundle.clock());
        assert_eq!(stopped.vm_context(), bundle.vm_context());
        for id in 0..usize::from(count) {
            assert!(matches!(
                target.vm.vcpus[id].run().unwrap(),
                VcpuExit::Shutdown
            ));
        }
        assert!(target.vm.serial.lock().unwrap().has_input());
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

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn failed_second_cpu_setter_rolls_back_first_cpu_and_preserves_target_ram() {
    use crate::backend::kvm::CheckpointImage;

    let mut source = Fixture::new(2);
    let mut target = Fixture::new(2);
    for (id, old_rax) in [0x41, 0x42].into_iter().enumerate() {
        source.prepare(id, &[0xf4]);
        target.prepare(id, &[0xf4]);
        let CpuState::X86_64(mut state) = target.vm.vcpus[id].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rax = old_rax;
        target.vm.vcpus[id]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
    }
    let address = GuestAddress(0x2000);
    target
        .vm
        .guest_mem
        .memory()
        .write_obj(0x5au8, address)
        .unwrap();

    let mut bundle = source.vm.take_snapshot_bundle(0).unwrap();
    let mut records = bundle.take_backend_contexts().unwrap().entries().to_vec();
    CheckpointImage::break_debug_setter(records[1].as_mut().unwrap(), 1);
    let bundle = bundle.with_backend_contexts(records).unwrap();
    let error = target.vm.restore_snapshot_bundle(&bundle).unwrap_err();
    assert!(
        matches!(&error, Error::Kvm(native) if native.errno() == libc::EINVAL),
        "{error}"
    );
    for (cpu, old_rax) in target.vm.vcpus.iter().zip([0x41, 0x42]) {
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        assert_eq!(state.regs.rax, old_rax);
    }
    assert_eq!(
        target
            .vm
            .guest_mem
            .memory()
            .read_obj::<u8>(address)
            .unwrap(),
        0x5a
    );
    assert!(matches!(target.exit(0), VcpuExit::Hlt));
}

#[test]
#[ignore = "requires the managed native KVM irqchip"]
fn native_rtc_irq8_acknowledgement_updates_the_restored_kernel_line() {
    use crate::backend::kvm::{CheckpointImage, KvmVm};
    use crate::vm::snapshot::SnapshotBundle;

    let mut source = Fixture::with_construction(
        1,
        128 << 20,
        ConstructionMode::Checkpoint {
            initialize_kvm_irqchip: true,
        },
    );
    source.prepare(0, &[0xe4, 0x71, 0xe6, 0x80, 0xf4]); // IN AL, 71h; OUT 80h, AL.
    source.vm.io_bus.write(0x70, &[0x0a, 0x26]).unwrap();
    source.vm.io_bus.write(0x70, &[0x0b, 0xc2]).unwrap();
    source.vm.io_bus.write(0x70, &[0x0c]).unwrap();
    let clock = source.vm.timing_context.clone();
    clock.set_resume_base(clock.elapsed_nanos() + 1_000_000);
    let snapshot = source.vm.take_snapshot_bundle(0).unwrap();
    assert_eq!(snapshot.saved_kvm_irqchip(), Some(true));
    CheckpointImage::from_checkpoint_bundle(&snapshot)
        .unwrap()
        .validate_rtc_irq_level(Some(true))
        .unwrap();
    let path = source.kernel.with_extension("rxc");
    snapshot.save(&path).unwrap();
    drop(snapshot);
    drop(source);
    let snapshot = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&snapshot, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &snapshot).unwrap();

    let io = (0..100)
        .find_map(|_| {
            target.vcpus[0]
                .run_host_slice(Duration::from_millis(10))
                .unwrap()
        })
        .expect("resumed RTC register read");
    assert!(matches!(
        io,
        VcpuExit::IoIn {
            port: 0x71,
            size: 1
        }
    ));
    assert_eq!(
        target.vcpus[0]
            .settle_checkpoint_io(&mut |exit| target.checkpoint_io_service(0, exit))
            .unwrap(),
        CheckpointIoState::Complete
    );
    assert!(
        !target
            .pc_devices
            .as_ref()
            .unwrap()
            .rtc
            .lock()
            .unwrap()
            .has_pending_interrupt()
    );
    let boundary = target.vm.checkpoint_boundary().unwrap();
    let native = target.vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let (banks, _) = native.capture_native_banks_at(&boundary).unwrap();
    banks.validate_rtc_irq_level(Some(false)).unwrap();
    drop(boundary);
    let output = (0..100)
        .find_map(|_| {
            target.vcpus[0]
                .run_host_slice(Duration::from_millis(10))
                .unwrap()
        })
        .expect("resumed RTC result");
    assert!(matches!(output, VcpuExit::IoOut { port: 0x80, data } if data == [0xc0]));
}

#[test]
#[ignore = "requires native Linux KVM with TSC deadline support"]
fn future_native_deadline_survives_a_source_free_vmm_checkpoint() {
    use crate::vm::snapshot::SnapshotBundle;

    // NASM, BITS 16. Program SVR and LVTT through the native LAPIC, arm
    // IA32_TSC_DEADLINE at guest RDTSC + 0x70000000, and save that absolute
    // deadline at 0x5000. OUT 21h is the capture marker. OUT 32h follows
    // re-entry with IF=1. HLT waits for the timer before OUT 33h.
    const GUEST: &[u8] = &[
        0x66, 0xbf, 0x00, 0x00, 0xe0, 0xfe, 0x67, 0x66, 0xc7, 0x87, 0xf0, 0x00, 0x00, 0x00, 0xff,
        0x01, 0x00, 0x00, 0x67, 0x66, 0xc7, 0x87, 0x20, 0x03, 0x00, 0x00, 0x41, 0x00, 0x04, 0x00,
        0x0f, 0x31, 0x66, 0x05, 0x00, 0x00, 0x00, 0x70, 0x66, 0x83, 0xd2, 0x00, 0x66, 0xa3, 0x00,
        0x50, 0x66, 0x89, 0x16, 0x04, 0x50, 0x66, 0xb9, 0xe0, 0x06, 0x00, 0x00, 0x0f, 0x30, 0xfb,
        0xb0, 0x21, 0xe6, 0xe9, 0xb0, 0x32, 0xe6, 0xe9, 0xf4, 0xfa, 0xb0, 0x33, 0xe6, 0xe9, 0xf4,
    ];
    // Store handler-entry TSC at 0x5008. Write EOI, output A1h, and IRET.
    const HANDLER: &[u8] = &[
        0x0f, 0x31, 0x66, 0xa3, 0x08, 0x50, 0x66, 0x89, 0x16, 0x0c, 0x50, 0x67, 0x66, 0xc7, 0x87,
        0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0xa1, 0xe6, 0xe9, 0xcf,
    ];
    fn timer_marker(event: VcpuExit, expected: u8) {
        assert!(
            matches!(&event, VcpuExit::IoOut { port: 0xe9, data } if data == &[expected]),
            "unexpected event before marker {expected:#x}: {event:?}"
        );
    }

    for count in [1, 2, 4] {
        let mut source = Fixture::with_construction(
            count,
            128 << 20,
            ConstructionMode::Checkpoint {
                initialize_kvm_irqchip: true,
            },
        );
        source.prepare(0, GUEST);
        let memory = source.vm.guest_mem.memory();
        memory.write_slice(HANDLER, GuestAddress(0x2000)).unwrap();
        memory.write_obj(0x2000u32, GuestAddress(0x41 * 4)).unwrap();
        let CpuState::X86_64(mut state) = source.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rsp = 0x9000;
        state.sregs.ss.base = 0;
        state.sregs.ss.selector = 0;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 0x3ff;
        source.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        timer_marker(source.exit(0), 0x21);
        let deadline = source
            .vm
            .guest_mem
            .memory()
            .read_obj::<u64>(GuestAddress(0x5000))
            .unwrap();
        assert_ne!(deadline, 0);
        let bundle = source
            .vm
            .take_snapshot_bundle(0)
            .expect("public VMM capture must admit the future deadline");
        assert_eq!(bundle.saved_kvm_irqchip(), Some(true));
        let path = source.kernel.with_extension("rxc");
        bundle.save(&path).unwrap();
        drop(bundle);
        let original_kernel = source.kernel.clone();
        drop(source);
        assert!(!original_kernel.exists());
        std::thread::sleep(Duration::from_secs(2));
        let bundle = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &bundle).unwrap();
        assert_eq!(
            target.take_snapshot_bundle(0).unwrap().vm_context(),
            bundle.vm_context()
        );
        let cpu = &mut target.vcpus[0];
        for expected in [0x32, 0xa1, 0x33] {
            let event = (0..300)
                .find_map(|_| cpu.run_host_slice(Duration::from_millis(10)).unwrap())
                .expect("resumed VCPU did not produce its next marker");
            timer_marker(event, expected);
            cpu.complete_io_out().unwrap();
        }
        let received = target
            .guest_mem
            .memory()
            .read_obj::<u64>(GuestAddress(0x5008))
            .unwrap();
        assert!(
            received >= deadline,
            "native IRQ entered before programmed guest TSC"
        );
    }
}

#[test]
#[ignore = "requires the managed native KVM irqchip"]
fn parallel_native_pio_continues_once_on_each_vcpu_after_detached_restore() {
    use crate::vm::snapshot::SnapshotBundle;

    // 16-bit BSP sets SVR, sends INIT assert, INIT deassert and SIPI 04h
    // to every AP, emits the startup marker, then reads one UART byte.
    const BSP: &[u8] = &[
        0xfa, 0x31, 0xc0, 0x66, 0xbf, 0x00, 0x00, 0xe0, 0xfe, 0x67, 0x66, 0xc7, 0x87, 0xf0, 0x00,
        0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x67, 0x66, 0xc7, 0x87, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x45, 0x0c, 0x00, 0xe6, 0x80, 0x67, 0x66, 0xc7, 0x87, 0x00, 0x03, 0x00, 0x00, 0x00, 0x85,
        0x0c, 0x00, 0xe6, 0x80, 0x67, 0x66, 0xc7, 0x87, 0x00, 0x03, 0x00, 0x00, 0x04, 0x46, 0x0c,
        0x00, 0xb0, 0x21, 0xe6, 0x80, 0xba, 0xf8, 0x03, 0xec, 0xe6, 0x80, 0xf4,
    ];
    // CLI; MOV DX, 3F8h; IN AL, DX; OUT 80h, AL; HLT.
    const AP: &[u8] = &[0xfa, 0xba, 0xf8, 0x03, 0xec, 0xe6, 0x80, 0xf4];

    for count in [2, 4] {
        let mut source = Fixture::with_construction(
            count,
            128 << 20,
            ConstructionMode::Checkpoint {
                initialize_kvm_irqchip: true,
            },
        );
        source.prepare(0, BSP);
        source
            .vm
            .guest_mem
            .memory()
            .write_slice(AP, GuestAddress(0x4000))
            .unwrap();
        for marker in [0, 0, 0x21] {
            assert!(
                matches!(source.exit(0), VcpuExit::IoOut { port: 0x80, data } if data == [marker])
            );
            source.vm.vcpus[0].complete_io_out().unwrap();
        }

        let mut arrived = vec![false; usize::from(count)];
        let mut turns = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..100 {
            source
                .vm
                .execute_native_round(&mut turns, &mut pending)
                .unwrap();
            assert!(pending.is_empty());
            for turn in turns.drain(..) {
                assert!(matches!(
                    turn.exit,
                    VcpuExit::IoIn {
                        port: 0x3f8,
                        size: 1
                    }
                ));
                assert!(!std::mem::replace(&mut arrived[turn.cpu_index], true));
                // A transient host yield may leave a peer behind. Hold the
                // exposed input buffers until every CPU owns a pending IN.
                source.vm.coordinator.online[turn.cpu_index] = false;
            }
            if arrived.iter().all(|&ready| ready) {
                break;
            }
        }
        assert!(arrived.iter().all(|&ready| ready));
        source.vm.coordinator.online.fill(true);
        let mut bytes = (0..count).map(|id| 0x41 + id).collect::<Vec<_>>();
        bytes.push(0x94);
        {
            let mut uart = source.vm.serial.lock().unwrap();
            IoDevice::write(&mut *uart, 0x3fa, 1);
            uart.queue_input(&bytes);
        }

        let path = source.kernel.with_extension("rxc");
        let image = source.vm.take_snapshot_bundle(0).unwrap();
        assert_eq!(image.saved_kvm_irqchip(), Some(true));
        assert!(image.execution().unwrap().online().iter().all(|&cpu| cpu));
        for (id, record) in image.cpus().unwrap().entries().iter().enumerate() {
            let CpuState::X86_64(state) = &record.state else {
                unreachable!()
            };
            assert_eq!(state.regs.rax & 0xff, u64::from(bytes[id]));
        }
        image.save(&path).unwrap();
        drop(image);
        let source_path = source.kernel.clone();
        drop(source);
        assert!(!source_path.exists());

        let image = SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&image, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &image).unwrap();
        for (id, expected) in bytes.iter().copied().take(usize::from(count)).enumerate() {
            let cpu = &mut target.vcpus[id];
            let event = (0..100)
                .find_map(|_| cpu.run_host_slice(Duration::from_millis(10)).unwrap())
                .expect("resumed vCPU did not report its saved UART byte");
            assert!(matches!(event, VcpuExit::IoOut { port: 0x80, data } if data == [expected]));
            cpu.complete_io_out().unwrap();
        }
        let mut uart = target.serial.lock().unwrap();
        assert_eq!(IoDevice::read(&mut *uart, 0x3f8), 0x94);
        assert!(!uart.has_input());
    }
}
