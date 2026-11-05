//! A userspace-controller HLT remains parked until an actual wake event.
use rax::backend::Backend;
use rax::backend::kvm::{KvmBackend, KvmVm};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Wake {
    Explicit,
    Irq,
    IrqWithOverlay,
    Nmi,
}

fn next(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            return exit;
        }
    }
    panic!("native halt control did not reach an exit");
}

fn exercise(wake: Wake) {
    let backend = KvmBackend::new().expect("native halt controls require /dev/kvm");
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    memory
        .memory()
        .write_slice(
            &[
                0xf4, // HLT: no subsequent byte may execute without a wake.
                0xc6, 0x06, 0x00, 0x50, 0xa5, // MOV byte [0x5000],0xa5.
                0xb0, 0x5a, 0xe6, 0xe9, // MOV AL,0x5a; OUT 0xe9,AL.
                0xf4,
            ],
            GuestAddress(0x1000),
        )
        .unwrap();
    memory
        .memory()
        .write_slice(&[0xcf], GuestAddress(0x2000)) // IRET.
        .unwrap();
    for vector in [2, 0x40] {
        memory
            .memory()
            .write_slice(&[0, 0x20, 0, 0], GuestAddress(vector * 4))
            .unwrap();
    }
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rip = 0x1000;
    if matches!(wake, Wake::Explicit) {
        state.sregs.cr8 = 3;
    }
    state.regs.rsp = 0x8000;
    state.regs.rflags = 2 | if matches!(wake, Wake::Irq) { 1 << 9 } else { 0 };
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.ds.base = 0;
    state.sregs.ds.selector = 0;
    state.sregs.ss.base = 0;
    state.sregs.ss.selector = 0;
    state.sregs.idt.base = 0;
    state.sregs.idt.limit = 0x3ff;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(next(&mut *cpu), VcpuExit::Hlt));
    assert_eq!(cpu.current_pc(), 0x1001);
    if matches!(wake, Wake::Explicit) {
        let CpuState::X86_64(observed) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(observed.sregs.cr8, 3);
    }
    for interval in [Duration::ZERO, Duration::MAX] {
        assert!(cpu.run_host_slice(interval).is_err());
    }
    for _ in 0..3 {
        let exit = cpu.run_host_slice(Duration::from_millis(10)).unwrap();
        let canary = memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x5000))
            .unwrap();
        assert_eq!(
            canary, 0,
            "code after HLT ran without a wake: {wake:?}, {exit:?}"
        );
        assert!(matches!(exit, Some(VcpuExit::Hlt)));
        assert_eq!(cpu.current_pc(), 0x1001);
    }
    if matches!(wake, Wake::Explicit | Wake::IrqWithOverlay) {
        let CpuState::X86_64(mut overlay) = cpu.get_state().unwrap() else {
            panic!()
        };
        overlay.regs.rbx = 0x1234;
        if matches!(wake, Wake::IrqWithOverlay) {
            overlay.regs.rflags |= 1 << 9;
            overlay.sregs.cr8 = 3;
        }
        cpu.set_state(&CpuState::X86_64(overlay)).unwrap();
        assert!(matches!(next(&mut *cpu), VcpuExit::Hlt));
        assert_eq!(cpu.current_pc(), 0x1001);
    }
    match wake {
        Wake::Explicit => cpu.wake(),
        Wake::Irq | Wake::IrqWithOverlay => {
            let before = serde_json::to_value(cpu.get_state().unwrap()).unwrap();
            assert!(cpu.inject_interrupt(0x40).unwrap());
            assert_eq!(
                serde_json::to_value(cpu.get_state().unwrap()).unwrap(),
                before
            );
            assert_eq!(cpu.current_pc(), 0x1001);
            assert_eq!(
                memory
                    .memory()
                    .read_obj::<u8>(GuestAddress(0x5000))
                    .unwrap(),
                0
            );
        }
        Wake::Nmi => {
            assert!(!cpu.inject_interrupt(0x40).unwrap());
            assert!(matches!(next(&mut *cpu), VcpuExit::Hlt));
            assert!(cpu.inject_nmi().unwrap());
        }
    }
    match next(&mut *cpu) {
        VcpuExit::IoOut { port: 0xe9, data } => assert_eq!(data, [0x5a]),
        other => panic!("accepted wake did not resume the native guest: {wake:?}, {other:?}"),
    }
    assert_eq!(
        memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x5000))
            .unwrap(),
        0xa5
    );
}

#[test]
fn userspace_hlt_requires_an_explicit_wake_and_survives_a_public_overlay() {
    exercise(Wake::Explicit);
}

#[test]
fn userspace_hlt_wakes_only_after_a_maskable_interrupt_is_accepted() {
    exercise(Wake::Irq);
}

#[test]
fn userspace_hlt_with_if_clear_retains_a_refused_irq_and_wakes_for_nmi() {
    exercise(Wake::Nmi);
}

#[test]
fn userspace_hlt_irq_admission_refreshes_an_if_overlay_without_executing_or_losing_cr8() {
    exercise(Wake::IrqWithOverlay);
}
