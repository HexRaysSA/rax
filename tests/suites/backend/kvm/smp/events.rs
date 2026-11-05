//! Native userspace-controller events through the managed CPU interface.
use rax::backend::Backend;
use rax::backend::kvm::{KvmBackend, KvmVm};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::vcpu::{CheckpointIoReply, CheckpointIoState, CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use std::time::Duration;

fn next(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            return exit;
        }
    }
    panic!("native event did not reach an architectural exit");
}

fn settle(cpu: &dyn VCpu) {
    let state = cpu
        .settle_checkpoint_io(&mut |exit| match exit {
            VcpuExit::IoOut {
                port: 0xe8 | 0xe9, ..
            } => Ok(CheckpointIoReply::Output),
            other => panic!("unexpected native event service: {other:?}"),
        })
        .unwrap();
    assert!(matches!(state, CheckpointIoState::Complete));
}

fn fixture(count: u8, kernel_irqchip: bool, interrupts: bool) -> Vec<Box<dyn VCpu>> {
    let backend = KvmBackend::new().expect("native event tests require /dev/kvm");
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    if kernel_irqchip {
        native.create_irq_chip().unwrap();
    }
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.configure_cpu_topology(count, memory.size()).unwrap();
    native.register_memory(&memory).unwrap();
    memory
        .memory()
        .write_slice(&[0x00, 0x20, 0, 0], GuestAddress(2 * 4))
        .unwrap();
    memory
        .memory()
        .write_slice(
            &[
                0x88, 0xe0, // MOV AL,AH: each CPU's retained identity.
                0x04, 0xa0, // ADD AL,0xa0.
                0xe6, 0xe9, // OUT 0xe9,AL.
                0xcf, // IRET, clearing NMI blocking.
            ],
            GuestAddress(0x2000),
        )
        .unwrap();
    let mut cpus = Vec::new();
    for id in 0..count {
        let vector = 0x40 + id;
        let handler = 0x3000 + u16::from(id) * 0x20;
        let [low, high] = handler.to_le_bytes();
        memory
            .memory()
            .write_slice(&[low, high, 0, 0], GuestAddress(u64::from(vector) * 4))
            .unwrap();
        memory
            .memory()
            .write_slice(
                &[0xb0, 0x80 + id, 0xe6, 0xe9, 0xcf],
                GuestAddress(u64::from(handler)),
            )
            .unwrap();
        let entry = 0x1000 + u64::from(id) * 0x20;
        let mut program = Vec::new();
        if kernel_irqchip {
            // Enable the LAPIC before unmasking a local vector entry.
            program.extend_from_slice(&[
                0x67, 0x66, 0xc7, 0x05, 0xf0, 0x00, 0xe0, 0xfe, 0xff, 1, 0, 0,
            ]);
            // MOV dword [0xfee00360],0x400: external LINT1 selects NMI.
            program
                .extend_from_slice(&[0x67, 0x66, 0xc7, 0x05, 0x60, 0x03, 0xe0, 0xfe, 0, 4, 0, 0]);
        }
        program.extend_from_slice(&[0xe6, 0xe8]); // OUT 0xe8,AL.
        if kernel_irqchip {
            // Mask LINT1 after the handler returns to the original stream.
            program
                .extend_from_slice(&[0x67, 0x66, 0xc7, 0x05, 0x60, 0x03, 0xe0, 0xfe, 0, 4, 1, 0]);
        }
        program.extend_from_slice(&[0xf4, 0xeb, 0xfd]); // HLT; JMP to HLT.
        memory
            .memory()
            .write_slice(&program, GuestAddress(entry))
            .unwrap();
        let mut cpu = vm
            .create_vcpu(u32::from(id), Arc::new(memory.memory().clone()))
            .unwrap();
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.rip = entry;
        state.regs.rsp = 0x8000 + u64::from(id) * 0x1000;
        state.regs.rax = u64::from(id) * 0x101;
        state.regs.rflags = 2 | if interrupts { 1 << 9 } else { 0 };
        state.sregs.cs.base = 0;
        state.sregs.cs.selector = 0;
        state.sregs.ds.base = 0;
        state.sregs.ds.selector = 0;
        state.sregs.ds.limit = u32::MAX;
        state.sregs.ds.g = true;
        state.sregs.ss.base = 0;
        state.sregs.ss.selector = 0;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 0x3ff;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
        assert!(matches!(
            next(&mut *cpu),
            VcpuExit::IoOut { port: 0xe8, .. }
        ));
        assert!(!cpu.can_inject_interrupt());
        assert!(!cpu.inject_interrupt(vector).unwrap());
        assert!(!cpu.inject_nmi().unwrap());
        settle(&*cpu);
        cpus.push(cpu);
    }
    // CPU ownership must retain VM, native descriptors and RAM after return.
    cpus
}

#[test]
fn userspace_irq_targets_one_two_four_managed_cpus_without_overwriting_a_pending_vector() {
    for count in [1, 2, 4] {
        let mut cpus = fixture(count, false, true);
        for id in 0..usize::from(count) {
            let vector = 0x40 + id as u8;
            for _ in 0..2 {
                assert!(
                    cpus[id].can_inject_interrupt(),
                    "CPU {id} has no IRQ admission"
                );
                assert!(cpus[id].inject_interrupt(vector).unwrap());
                assert!(!cpus[id].can_inject_interrupt());
                assert!(!cpus[id].inject_interrupt(vector + 16).unwrap());
                match next(&mut *cpus[id]) {
                    VcpuExit::IoOut { port: 0xe9, data } => {
                        assert_eq!(data, [0x80 + id as u8]);
                    }
                    other => panic!("IRQ did not execute its native handler: {other:?}"),
                }
                assert!(!cpus[id].can_inject_interrupt());
                settle(&*cpus[id]);
                assert!(matches!(next(&mut *cpus[id]), VcpuExit::Hlt));
            }
            for (peer, cpu) in cpus.iter().enumerate().skip(id + 1) {
                assert_eq!(cpu.current_pc(), 0x1002 + peer as u64 * 0x20);
            }
        }
    }
}

#[test]
fn managed_nmi_ignores_if_and_retains_pending_and_handler_blocking_on_every_cpu() {
    for count in [1, 2, 4] {
        let mut cpus = fixture(count, false, false);
        for (id, cpu) in cpus.iter_mut().enumerate() {
            for _ in 0..2 {
                assert!(!cpu.can_inject_interrupt());
                assert!(!cpu.inject_interrupt(0x40 + id as u8).unwrap());
                assert!(cpu.inject_nmi().unwrap(), "CPU {id} has no NMI admission");
                assert!(!cpu.inject_nmi().unwrap());
                match next(&mut **cpu) {
                    VcpuExit::IoOut { port: 0xe9, data } => {
                        assert_eq!(data, [0xa0 + id as u8]);
                    }
                    other => panic!("NMI did not execute its native handler: {other:?}"),
                }
                assert!(!cpu.inject_nmi().unwrap());
                settle(&**cpu);
                assert!(
                    !cpu.inject_nmi().unwrap(),
                    "settled handler remains NMI-blocked until IRET"
                );
                assert!(matches!(next(&mut **cpu), VcpuExit::Hlt));
            }
        }
    }
}

#[test]
fn kernel_irqchip_keeps_fixed_irq_ownership_and_accepts_managed_nmi() {
    let mut cpus = fixture(1, true, false);
    let cpu = &mut cpus[0];
    assert!(!cpu.can_inject_interrupt());
    assert!(!cpu.inject_interrupt(0x41).unwrap());
    assert!(cpu.inject_nmi().unwrap());
    match next(&mut **cpu) {
        VcpuExit::IoOut { port: 0xe9, data } => assert_eq!(data, [0xa0]),
        other => panic!("kernel-LAPIC NMI did not reach the handler: {other:?}"),
    }
    settle(&**cpu);
    // The in-kernel controller owns HLT and blocks KVM_RUN until an event or
    // host deadline. Require the executed HLT frontier rather than an exit
    // that is provided only by the userspace-controller profile.
    let mut parked = false;
    for _ in 0..100 {
        assert!(
            cpu.run_host_slice(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        if cpu.current_pc() == 0x1027 {
            parked = true;
            break;
        }
    }
    assert!(
        parked,
        "native handler did not IRET into the masked HLT loop"
    );
    for _ in 0..2 {
        assert!(
            cpu.run_host_slice(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        assert_eq!(cpu.current_pc(), 0x1027);
    }
    assert!(!cpu.inject_nmi().unwrap(), "guest masked its native LINT1");
}

#[test]
fn sticky_io_failure_fences_managed_irq_and_nmi_before_native_event_access() {
    let mut cpus = fixture(1, false, true);
    let cpu = &mut cpus[0];
    let pc = cpu.current_pc();
    cpu.complete_io_in(&[0x55]); // No matching native input request.
    assert!(!cpu.can_inject_interrupt());
    assert!(cpu.inject_interrupt(0x41).is_err());
    assert!(cpu.inject_nmi().is_err());
    assert_eq!(cpu.current_pc(), pc);
}
