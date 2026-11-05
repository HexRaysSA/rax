//! Public register overlays preserve queued native results before guest entry.
use super::*;
use crate::vm::memory::vm::{Bytes, GuestAddress};
use std::time::Duration;

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn managed_public_overlays_preserve_deferred_results_before_every_cpus_canary() {
    for irqchip in [false, true] {
        for count in [1, 2, 4] {
            for expected in [
                VcpuExit::Hlt,
                VcpuExit::Shutdown,
                VcpuExit::SystemEvent {
                    type_: 7,
                    flags: 0x1234,
                },
                VcpuExit::FailEntry { reason: 0x9876 },
                VcpuExit::InternalError,
                VcpuExit::Unknown("retained completion exit".into()),
            ] {
                let backend = KvmBackend::new().unwrap();
                let vm = backend.create_vm().unwrap();
                vm.configure_cpu_topology(count, 2 * 1024 * 1024).unwrap();
                let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
                if irqchip {
                    native.create_irq_chip().unwrap();
                }
                let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
                native.register_memory(&memory).unwrap();
                // MOV byte [0x2000],0xa5; OUT 0xe9,AL; HLT, in16-bit code.
                memory
                    .memory()
                    .write_slice(
                        &[0xc6, 0x06, 0x00, 0x20, 0xa5, 0xe6, 0xe9, 0xf4],
                        GuestAddress(0x1000),
                    )
                    .unwrap();
                let mut cpus = Vec::new();
                for id in 0..u32::from(count) {
                    let mut cpu = vm
                        .create_vcpu(id, Arc::new(memory.memory().clone()))
                        .unwrap();
                    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                        unreachable!()
                    };
                    state.regs.rip = 0x1000;
                    state.regs.rflags = 2;
                    state.regs.rax = 0x21 + u64::from(id);
                    state.sregs.cs.base = 0;
                    state.sregs.cs.selector = 0;
                    cpu.set_state(&CpuState::X86_64(state)).unwrap();
                    cpus.push(cpu);
                }
                let boundary = vm.checkpoint_boundary().unwrap();
                let handles: Vec<_> = native
                    .memory
                    .managed_cpus
                    .lock()
                    .unwrap()
                    .values()
                    .map(|core| core.upgrade().unwrap())
                    .collect();
                for handle in &handles {
                    let mut core = handle.lock().unwrap();
                    // Directly prepared APs isolate deferred-result behavior
                    // from the independently tested INIT/SIPI startup path.
                    core.vcpu_fd
                        .set_mp_state(kvm_bindings::kvm_mp_state {
                            mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
                        })
                        .unwrap();
                    core.deferred_exit = Some(expected.clone());
                    core.userspace_halted = !irqchip && matches!(expected, VcpuExit::Hlt);
                }
                drop(boundary);
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    memory
                        .memory()
                        .write_slice(&[0], GuestAddress(0x2000))
                        .unwrap();
                    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                        unreachable!()
                    };
                    state.regs.rbx = 0xa55a_1234_0000 + id as u64;
                    cpu.set_state(&CpuState::X86_64(state)).unwrap();
                    assert_eq!(
                        handles[id]
                            .lock()
                            .unwrap()
                            .deferred_exit
                            .as_ref()
                            .map(|exit| format!("{exit:?}")),
                        Some(format!("{expected:?}")),
                        "count={count},irqchip={irqchip},id={id}",
                    );
                    // A wake must not acknowledge an undelivered result.
                    cpu.wake();
                    for _ in
                        0..if matches!(expected, VcpuExit::Shutdown | VcpuExit::SystemEvent { .. })
                        {
                            2
                        } else {
                            1
                        }
                    {
                        let exit = cpu
                            .run_host_slice(Duration::from_millis(10))
                            .unwrap()
                            .unwrap();
                        assert_eq!(format!("{exit:?}"), format!("{expected:?}"));
                        assert_eq!(cpu.current_pc(), 0x1000);
                        let mut marker = [0];
                        memory
                            .memory()
                            .read_slice(&mut marker, GuestAddress(0x2000))
                            .unwrap();
                        assert_eq!(marker, [0]);
                    }
                    if !matches!(expected, VcpuExit::Shutdown | VcpuExit::SystemEvent { .. }) {
                        assert!(handles[id].lock().unwrap().deferred_exit.is_none());
                        cpu.wake();
                        let exit = loop {
                            if let Some(exit) =
                                cpu.run_host_slice(Duration::from_millis(10)).unwrap()
                            {
                                break exit;
                            }
                        };
                        assert!(
                            matches!(exit, VcpuExit::IoOut { port:0xe9, data } if data == [0x21 + id as u8])
                        );
                        let mut marker = [0];
                        memory
                            .memory()
                            .read_slice(&mut marker, GuestAddress(0x2000))
                            .unwrap();
                        assert_eq!(marker, [0xa5]);
                    }
                }
            }
        }
    }
}
