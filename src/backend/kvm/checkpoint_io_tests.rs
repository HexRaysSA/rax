//! Real native completion frontiers; all replies are actual service results.
use super::*;
use crate::devices::bus::{MmioBus, MmioDevice, MmioRange};
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

const MMIO: u64 = 0xf000_0000;
const TAIL: &[u8] = &[0xc6, 0x06, 0x00, 0x20, 0xaa, 0xb0, 0x5a, 0xe6, 0xe9, 0xf4];

fn fixture(program: &[u8], irqchip: bool) -> (Arc<dyn Vm>, GuestMemoryWrapper, Box<dyn VCpu>) {
    let backend = KvmBackend::new().unwrap();
    let vm: Arc<dyn Vm> = Arc::from(backend.create_vm().unwrap());
    vm.configure_cpu_topology(1, 2 * 1024 * 1024).unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    if irqchip {
        native.create_irq_chip().unwrap();
    }
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    memory
        .memory()
        .write_slice(program, GuestAddress(0x1000))
        .unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 3; // Carry set: INC must preserve it.
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.ds.base = 0;
    state.sregs.ds.selector = 0;
    state.sregs.ds.limit = u32::MAX;
    state.sregs.ds.g = true;
    state.sregs.es.base = 0;
    state.sregs.es.selector = 0;
    state.sregs.es.limit = u32::MAX;
    state.sregs.es.g = true;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    (vm, memory, cpu)
}

fn exit(cpu: &mut dyn VCpu) -> VcpuExit {
    loop {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
            return exit;
        }
    }
}

fn unchanged_tail(memory: &GuestMemoryWrapper) {
    assert_eq!(
        memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x2000))
            .unwrap(),
        0
    );
}

struct Register {
    value: u8,
    calls: Arc<Mutex<Vec<(bool, u8)>>>,
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
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn checkpoint_completion_services_both_mmio_rmw_exits_without_running_the_tail() {
    for irqchip in [false, true] {
        // Real-mode INC byte [disp32]; the following store must not execute.
        let mut program = vec![0x67, 0xfe, 0x05, 0x00, 0x00, 0x00, 0xf0];
        program.extend_from_slice(TAIL);
        let (vm, memory, mut cpu) = fixture(&program, irqchip);
        assert!(matches!(
            exit(&mut *cpu),
            VcpuExit::MmioRead {
                addr: MMIO,
                size: 1
            }
        ));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut bus = MmioBus::new();
        bus.register(
            MmioRange { base: MMIO, len: 1 },
            Box::new(Register {
                value: 0x7f,
                calls: calls.clone(),
            }),
        )
        .unwrap();
        let state = cpu
            .settle_checkpoint_io(&mut |event| {
                // These actual owner operations would deadlock if service retained
                // either the CPU mutex or a checkpoint writer lease.
                cpu.get_state()?;
                if irqchip {
                    vm.set_irq_line(4, true)?;
                }
                match event {
                    VcpuExit::MmioRead { addr, size: 1 } => {
                        let mut bytes = [0];
                        bus.read(addr, &mut bytes)?;
                        Ok(CheckpointIoReply::Input(bytes.to_vec()))
                    }
                    VcpuExit::MmioWrite { addr, data } => {
                        bus.write(addr, &data)?;
                        Ok(CheckpointIoReply::Output)
                    }
                    event => panic!("unexpected completion event: {event:?}"),
                }
            })
            .unwrap();
        assert_eq!(state, CheckpointIoState::Complete);
        assert_eq!(*calls.lock().unwrap(), [(false, 0x7f), (true, 0x80)]);
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        assert_eq!(state.regs.rip, 0x1007);
        assert_eq!(state.regs.rflags & 0x8d5, 0x891);
        unchanged_tail(&memory);
        assert!(matches!(exit(&mut *cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x5a]));
        assert_eq!(
            memory
                .memory()
                .read_obj::<u8>(GuestAddress(0x2000))
                .unwrap(),
            0xaa
        );
    }
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn checkpoint_completion_preserves_every_output_batch_element_in_order() {
    let mut program = vec![0xf3, 0x6e]; // REP OUTSB.
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    memory
        .memory()
        .write_slice(&[0x11, 0x22, 0x33], GuestAddress(0x3000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x1234;
    state.regs.rsi = 0x3000;
    state.regs.rcx = 3;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let mut values = Vec::new();
    for _ in 0..3 {
        let VcpuExit::IoOut { port, data } = exit(&mut *cpu) else {
            panic!("REP OUTSB did not retain its next output frontier")
        };
        assert_eq!(
            (port, data.as_slice()),
            (0x1234, &[[0x11, 0x22, 0x33][values.len()]][..])
        );
        let before = values.len();
        assert_eq!(
            cpu.settle_checkpoint_io(&mut |event| {
                let VcpuExit::IoOut { port, data } = event else {
                    panic!("unexpected event")
                };
                assert_eq!(port, 0x1234);
                values.extend(data);
                Ok(CheckpointIoReply::Output)
            })
            .unwrap(),
            CheckpointIoState::Complete
        );
        assert!(values.len() > before && values.len() <= 3);
        assert_eq!(values.as_slice(), &[0x11, 0x22, 0x33][..values.len()]);
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        // KVM can expose one OUTS iteration per exit. Once that native I/O
        // completes, RCX/RSI and a retained REP RIP represent the remaining
        // guest iterations; settling must not enter them to finish the REP.
        assert_eq!(state.regs.rsi, 0x3000 + values.len() as u64);
        assert_eq!(state.regs.rcx, 3 - values.len() as u64);
        if values.len() == 3 {
            assert!(matches!(state.regs.rip, 0x1000 | 0x1002));
        } else {
            assert_eq!(state.regs.rip, 0x1000);
        }
        unchanged_tail(&memory);
        if values.len() == 3 {
            break;
        }
    }
    assert_eq!(values, [0x11, 0x22, 0x33]);
    // A zero-count REP frontier must resume directly into the following code,
    // without another device output from the completed string instruction.
    assert!(matches!(exit(&mut *cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x5a]));
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn checkpoint_completion_installs_the_actual_batched_input_once() {
    let mut program = vec![0xf3, 0x6c]; // REP INSB.
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    memory
        .memory()
        .write_slice(&[0xee; 3], GuestAddress(0x3000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x1234;
    state.regs.rdi = 0x3000;
    state.regs.rcx = 3;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(
        exit(&mut *cpu),
        VcpuExit::IoInString {
            port: 0x1234,
            size: 1,
            count: 3
        }
    ));
    let mut calls = 0;
    assert_eq!(
        cpu.settle_checkpoint_io(&mut |event| {
            assert!(matches!(
                event,
                VcpuExit::IoInString {
                    port: 0x1234,
                    size: 1,
                    count: 3
                }
            ));
            calls += 1;
            Ok(CheckpointIoReply::Input(vec![0x31, 0x42, 0x53]))
        })
        .unwrap(),
        CheckpointIoState::Complete
    );
    assert_eq!(calls, 1);
    let mut bytes = [0; 3];
    memory
        .memory()
        .read_slice(&mut bytes, GuestAddress(0x3000))
        .unwrap();
    assert_eq!(bytes, [0x31, 0x42, 0x53]);
    unchanged_tail(&memory);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn powered_off_output_retains_the_unapplied_tail_and_forbids_native_entry() {
    let mut program = vec![0xf3, 0x6f]; // REP OUTSW.
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    memory
        .memory()
        .write_slice(&[0, 0x20, 0x11, 0x11, 0x22, 0x22], GuestAddress(0x3000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x604;
    state.regs.rsi = 0x3000;
    state.regs.rcx = 3;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(exit(&mut *cpu), VcpuExit::IoOut { port: 0x604, data } if data == [0, 0x20]));
    let mut calls = 0;
    assert_eq!(
        cpu.settle_checkpoint_io(&mut |event| {
            assert!(matches!(event, VcpuExit::IoOut { port: 0x604, data } if data == [0, 0x20]));
            calls += 1;
            Ok(CheckpointIoReply::PowerOff)
        })
        .unwrap(),
        CheckpointIoState::Deferred
    );
    assert_eq!(calls, 1);
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
    unchanged_tail(&memory);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn failed_input_service_never_supplies_a_replacement_value_or_enters_the_guest() {
    let mut program = vec![0xe4, 0x80]; // IN AL,0x80.
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    assert!(matches!(
        exit(&mut *cpu),
        VcpuExit::IoIn {
            port: 0x80,
            size: 1
        }
    ));
    assert!(
        cpu.settle_checkpoint_io(&mut |_| Err(Error::Emulator("actual service failure".into())))
            .is_err()
    );
    assert!(cpu.run().is_err());
    unchanged_tail(&memory);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn short_input_reply_retains_destination_bytes_and_disables_further_entry() {
    let mut program = vec![0xf3, 0x6c];
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    memory
        .memory()
        .write_slice(&[0xee; 3], GuestAddress(0x3000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rdx = 0x1234;
    state.regs.rdi = 0x3000;
    state.regs.rcx = 3;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(
        exit(&mut *cpu),
        VcpuExit::IoInString {
            port: 0x1234,
            size: 1,
            count: 3
        }
    ));
    assert!(
        cpu.settle_checkpoint_io(&mut |_| Ok(CheckpointIoReply::Input(vec![0x31, 0x42])))
            .is_err()
    );
    assert!(cpu.run().is_err());
    let mut bytes = [0; 3];
    memory
        .memory()
        .read_slice(&mut bytes, GuestAddress(0x3000))
        .unwrap();
    assert_eq!(bytes, [0xee; 3]);
    unchanged_tail(&memory);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn reentrant_checkpoint_service_rejects_before_redispatching_the_device() {
    let mut program = vec![0xe6, 0x80];
    program.extend_from_slice(TAIL);
    let (_vm, memory, mut cpu) = fixture(&program, false);
    assert!(matches!(
        exit(&mut *cpu),
        VcpuExit::IoOut { port: 0x80, .. }
    ));
    let mut outer_calls = 0;
    let mut nested_calls = 0;
    assert_eq!(
        cpu.settle_checkpoint_io(&mut |_| {
            outer_calls += 1;
            let nested = cpu.settle_checkpoint_io(&mut |_| {
                nested_calls += 1;
                Ok(CheckpointIoReply::Output)
            });
            assert!(
                nested.is_err(),
                "reentrant checkpoint redispatched the device"
            );
            Ok(CheckpointIoReply::Output)
        })
        .unwrap(),
        CheckpointIoState::Complete
    );
    assert_eq!((outer_calls, nested_calls), (1, 0));
    unchanged_tail(&memory);
}
