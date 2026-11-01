//! Forward clock rebasing and exact destination rollback are different operations.
use super::*;
use rax::vm::snapshot::{BackendContext, CpuSnapshot};
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};

fn capture(vm: &dyn rax::backend::Vm, cpu: &dyn VCpu) -> (CpuSnapshot, Option<BackendContext>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    cpu.capture_checkpoint_record(&boundary, None).unwrap()
}
fn read_tsc(cpu: &mut dyn VCpu, id: u32) -> u64 {
    cpu.wake();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&id).unwrap();
        native.registers.insert(3, 0x10); // RCX = IA32_TIME_STAMP_COUNTER
        native.vmcs.insert(0x440c, 3);
        native.exits = [31, 12].into_iter().collect();
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    state.regs.rax | (state.regs.rdx << 32)
}

#[test]
fn failed_raw_restore_keeps_running_and_not_yet_resumed_clock_domains() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for suspended in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
        if suspended {
            cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
                .unwrap();
        }
        let initial = SDK.lock().unwrap().tsc;
        {
            let mut sdk = SDK.lock().unwrap();
            sdk.failure_clock_advance = 1000;
            sdk.fault = Some(Fault {
                operation: "fp-write",
                remaining: 1,
                persistent: false,
            });
        }
        let error = cpu
            .restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
            .unwrap_err();
        assert!(!error.to_string().contains("rollback failed"), "{error}");
        let expected = if suspended { initial } else { initial + 1000 };
        assert_eq!(read_tsc(cpu.as_mut(), 0), expected, "suspended={suspended}");
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn coordinated_rollback_keeps_the_original_epoch_for_running_and_pending_owners() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpus = (0..2)
        .map(|id| {
            vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                .unwrap()
        })
        .collect::<Vec<_>>();
    SDK.lock().unwrap().tsc = 1000;
    let boundary = vm.checkpoint_boundary().unwrap();
    let source = cpus
        .iter()
        .map(|cpu| cpu.capture_checkpoint_record(&boundary, None).unwrap())
        .collect::<Vec<_>>();
    let shared = vm.capture_checkpoint_vm_context(&boundary).unwrap();
    for (cpu, (public, context)) in cpus.iter_mut().zip(&source) {
        cpu.restore_checkpoint_record(&boundary, &public.state, &public.emulator, context.as_ref())
            .unwrap();
    }
    vm.restore_checkpoint_vm_context(&boundary, shared.as_ref())
        .unwrap();
    for (cpu, (_, context)) in cpus.iter_mut().zip(&source) {
        cpu.finish_checkpoint_restore(&boundary, context.as_ref())
            .unwrap();
    }
    drop(boundary);
    SDK.lock().unwrap().tsc = 9000;
    assert_eq!(read_tsc(cpus[0].as_mut(), 0), 1000);
    // CPU 1 has not entered and must remain joined to CPU 0's original epoch.
    SDK.lock().unwrap().tsc = 9050;
    let boundary = vm.checkpoint_boundary().unwrap();
    let backup = cpus
        .iter()
        .map(|cpu| cpu.capture_checkpoint_record(&boundary, None).unwrap())
        .collect::<Vec<_>>();
    let shared_backup = vm.capture_checkpoint_vm_context(&boundary).unwrap();
    for (cpu, (public, context)) in cpus.iter_mut().zip(&source) {
        cpu.restore_checkpoint_record(&boundary, &public.state, &public.emulator, context.as_ref())
            .unwrap();
    }
    vm.restore_checkpoint_vm_context(&boundary, shared.as_ref())
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        sdk.failure_clock_advance = 1000;
        sdk.fault = Some(Fault {
            operation: "invalidate",
            remaining: 1,
            persistent: false,
        });
    }
    assert!(
        cpus[0]
            .finish_checkpoint_restore(&boundary, source[0].1.as_ref())
            .is_err()
    );
    for (cpu, (public, context)) in cpus.iter_mut().zip(&backup) {
        cpu.rollback_checkpoint_record(
            &boundary,
            &public.state,
            &public.emulator,
            context.as_ref(),
        )
        .unwrap();
    }
    vm.rollback_checkpoint_vm_context(&boundary, shared_backup.as_ref())
        .unwrap();
    for (cpu, (_, context)) in cpus.iter_mut().zip(&backup) {
        cpu.finish_checkpoint_restore(&boundary, context.as_ref())
            .unwrap();
    }
    drop(boundary);
    assert_eq!(read_tsc(cpus[0].as_mut(), 0), 2050);
    SDK.lock().unwrap().tsc += 25;
    assert_eq!(read_tsc(cpus[1].as_mut(), 1), 2075);
    drop(cpus);
    drop(vm);
}

#[test]
fn sdk_clock_failure_during_rollback_fences_all_peers() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let mut peer = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
    {
        let mut sdk = SDK.lock().unwrap();
        sdk.fault = Some(Fault {
            operation: "fp-write",
            remaining: 1,
            persistent: false,
        });
        sdk.next_fault = Some(Fault {
            operation: "set-tsc-relative",
            remaining: 1,
            persistent: true,
        });
    }
    let error = cpu
        .restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
        .unwrap_err();
    assert!(error.to_string().contains("rollback failed"), "{error}");
    let calls = SDK.lock().unwrap().trace.len();
    assert!(peer.run().is_err());
    assert!(peer.capture_backend_context().is_err());
    assert!(cpu.get_state().is_err());
    assert_eq!(SDK.lock().unwrap().trace.len(), calls);
    drop(peer);
    drop(cpu);
    drop(vm);
}
