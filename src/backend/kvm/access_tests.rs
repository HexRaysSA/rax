//! Actual native ownership/exclusion tests. No model of the locks or SDK.
use super::*;
use std::sync::mpsc;
use std::time::Duration;

fn graph(count: u8) -> (Arc<dyn Vm>, GuestMemoryWrapper, Vec<Box<dyn VCpu>>) {
    let backend = KvmBackend::new().unwrap();
    let vm: Arc<dyn Vm> = Arc::from(backend.create_vm().unwrap());
    vm.configure_cpu_topology(count, 2 * 1024 * 1024).unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    let cpus = (0..count)
        .map(|id| {
            vm.create_vcpu(u32::from(id), Arc::new(memory.memory().clone()))
                .unwrap()
        })
        .collect();
    (vm, memory, cpus)
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn stopped_boundary_blocks_public_native_observation_until_release() {
    let (vm, _memory, mut cpus) = graph(1);
    let boundary = vm.checkpoint_boundary().unwrap();
    let cpu = cpus.remove(0);
    let (started, waiting) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(cpu.get_state().map(|_| ())).unwrap();
        cpu
    });
    waiting.recv().unwrap();
    assert!(matches!(
        result.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(boundary);
    result
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap();
    drop(worker.join().unwrap());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn boundary_keeps_native_cpu_and_registered_ram_alive_after_wrapper_drop() {
    use std::os::fd::AsRawFd;
    let (vm, memory, cpus) = graph(1);
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let core = native.memory.managed_cpus.lock().unwrap()[&0]
        .upgrade()
        .unwrap();
    let fd = core.lock().unwrap().vcpu_fd.as_raw_fd();
    drop(core);
    let boundary = vm.checkpoint_boundary().unwrap();
    drop(cpus);
    drop(memory);
    // SAFETY: F_GETFD observes the borrowed live descriptor without retaining
    // it or touching native guest state. The boundary pins its native owner.
    assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    drop(boundary);
    // SAFETY: numeric descriptor observation only; this test creates no other
    // file descriptors between lease destruction and this check.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    assert!(vm.checkpoint_boundary().is_err());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn externally_created_cpu_identity_remains_ineligible_after_sdk_wrapper_drop() {
    let (vm, _memory, _cpus) = graph(1);
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let raw = native.create_vcpu_fd(99).unwrap();
    assert!(vm.checkpoint_boundary().is_err());
    drop(raw);
    assert!(vm.checkpoint_boundary().is_err());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn incomplete_configured_membership_is_rejected_without_native_mutation() {
    let (vm, _memory, mut cpus) = graph(2);
    let before = cpus[0].current_pc();
    drop(cpus.remove(1));
    assert!(vm.checkpoint_boundary().is_err());
    assert_eq!(cpus[0].current_pc(), before);
    assert!(cpus[0].get_state().is_ok());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn poisoned_restore_owner_rejects_all_further_managed_entry_and_state() {
    let (vm, _memory, mut cpus) = graph(1);
    vm.poison_checkpoint_restore();
    assert!(cpus[0].get_state().is_err());
    assert!(cpus[0].run().is_err());
    assert!(cpus[0].run_host_slice(Duration::from_millis(1)).is_err());
    assert!(vm.checkpoint_boundary().is_err());
    assert!(vm.set_irq_line(4, true).is_err());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn scoped_capture_restore_and_rollback_use_the_existing_writer_boundary() {
    let (vm, _memory, mut cpus) = graph(1);
    let boundary = vm.checkpoint_boundary().unwrap();
    let (before, private) = cpus[0].capture_checkpoint_record(&boundary, None).unwrap();
    assert!(private.is_none()); // Complete private producer remains separate.
    let CpuState::X86_64(mut changed) = before.state.clone() else {
        unreachable!()
    };
    changed.regs.rax = 0x4567;
    cpus[0]
        .restore_checkpoint_record(
            &boundary,
            &CpuState::X86_64(changed),
            &before.emulator,
            None,
        )
        .unwrap();
    let (after, _) = cpus[0].capture_checkpoint_record(&boundary, None).unwrap();
    let CpuState::X86_64(after) = after.state else {
        unreachable!()
    };
    assert_eq!(after.regs.rax, 0x4567);
    cpus[0]
        .rollback_checkpoint_record(&boundary, &before.state, &before.emulator, None)
        .unwrap();
    let (restored, _) = cpus[0].capture_checkpoint_record(&boundary, None).unwrap();
    let CpuState::X86_64(restored) = restored.state else {
        unreachable!()
    };
    let CpuState::X86_64(before) = before.state else {
        unreachable!()
    };
    assert_eq!(restored.regs.rax, before.regs.rax);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn foreign_boundary_rejects_before_native_cpu_state_is_accessed() {
    let (source, _source_memory, _source_cpus) = graph(1);
    let (_target, _target_memory, mut target_cpus) = graph(1);
    let before = target_cpus[0].get_state().unwrap();
    let boundary = source.checkpoint_boundary().unwrap();
    assert!(
        target_cpus[0]
            .capture_checkpoint_record(&boundary, None)
            .is_err()
    );
    assert!(
        target_cpus[0]
            .restore_checkpoint_record(&boundary, &before, &Default::default(), None)
            .is_err()
    );
    assert!(target_cpus[0].get_state().is_ok());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn scoped_capture_rejects_pending_input_without_losing_its_native_buffer() {
    use vm_memory::{Bytes, GuestAddress};
    let (vm, memory, mut cpus) = graph(1);
    memory
        .memory()
        .write_slice(&[0xe4, 0x80, 0xf4], GuestAddress(0x1000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 2;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    cpus[0].set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(
        cpus[0].run().unwrap(),
        VcpuExit::IoIn {
            port: 0x80,
            size: 1
        }
    ));
    let boundary = vm.checkpoint_boundary().unwrap();
    assert!(cpus[0].capture_checkpoint_record(&boundary, None).is_err());
    drop(boundary);
    cpus[0].complete_io_in(&[0x6b]);
    cpus[0].io_completion_result().unwrap();
    assert!(matches!(cpus[0].run().unwrap(), VcpuExit::Hlt));
    assert_eq!(cpus[0].get_regs().unwrap().rax & 255, 0x6b);
}
