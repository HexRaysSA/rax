//! Kernel completion provenance must outlive replacement of terminal records.
use super::*;
use crate::vm::vcpu::CheckpointIoState;

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn successive_terminal_imports_cannot_hide_a_native_input_completion_from_active_admission() {
    for irqchip in [false, true] {
        for count in [1, 2, 4] {
            let (source, memory, mut cpus) = graph(count, irqchip);
            let boundary = source.checkpoint_boundary().unwrap();
            let active = native(&*source).capture_native_banks(&boundary).unwrap();
            drop(boundary);
            for (id, cpu) in cpus.iter_mut().enumerate() {
                let pc = 0x1000 + id as u64 * 0x100;
                memory
                    .memory()
                    .write_slice(&[0xec, 0xf4], GuestAddress(pc))
                    .unwrap();
                let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                    unreachable!()
                };
                state.regs.rip = pc;
                state.regs.rdx = 0x1234;
                cpu.set_state(&CpuState::X86_64(state)).unwrap();
                assert!(matches!(
                    exit(&mut **cpu),
                    VcpuExit::IoIn {
                        port: 0x1234,
                        size: 1
                    }
                ));
            }
            native(&*source).memory.power_off().unwrap();
            let boundary = source.checkpoint_boundary().unwrap();
            let terminal = native(&*source).capture_native_banks(&boundary).unwrap();
            let json = serde_json::to_vec(&terminal).unwrap();
            let binary = crate::codec::serialize(&terminal).unwrap();
            let mut idle = active.clone();
            idle.powered_off = true;
            idle.restore_stored(native(&*source), &boundary).unwrap();
            idle.restore_stored(native(&*source), &boundary).unwrap();
            let handles = native(&*source).checkpoint_cpu_handles(&boundary).unwrap();
            let before: Vec<_> = handles
                .iter()
                .map(|core| {
                    let core = core.lock().unwrap();
                    assert!(core.native_io_unsettled);
                    assert!(!core.io.has_native_completion());
                    core.vcpu_fd.get_regs().unwrap()
                })
                .collect();
            assert!(
                active
                    .restore_stored(native(&*source), &boundary)
                    .unwrap_err()
                    .to_string()
                    .contains("fresh native owner")
            );
            assert!(native(&*source).memory.powered_off.load(Ordering::Acquire));
            for (core, before) in handles.iter().zip(before) {
                assert_eq!(core.lock().unwrap().vcpu_fd.get_regs().unwrap(), before);
            }
            drop(boundary);
            drop(handles);
            drop(cpus);
            drop(source);
            drop(memory);

            for terminal in [
                serde_json::from_slice::<Image>(&json).unwrap(),
                crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
            ] {
                let (target, memory, mut cpus) = graph(count, irqchip);
                let boundary = target.checkpoint_boundary().unwrap();
                terminal
                    .restore_stored(native(&*target), &boundary)
                    .unwrap();
                let handles = native(&*target).checkpoint_cpu_handles(&boundary).unwrap();
                for core in lock_cpus(native(&*target), &handles).unwrap() {
                    assert!(!core.native_io_unsettled);
                    assert!(core.io.has_native_completion());
                }
                idle.restore_stored(native(&*target), &boundary).unwrap();
                active.restore_stored(native(&*target), &boundary).unwrap();
                for core in &handles {
                    let mut core = core.lock().unwrap();
                    let before = core.vcpu_fd.get_regs().unwrap();
                    core.vcpu_fd.set_kvm_immediate_exit(1);
                    let result = core.vcpu_fd.run().map(|_| ());
                    core.vcpu_fd.set_kvm_immediate_exit(0);
                    assert!(matches!(result, Err(error) if error.errno() == libc::EINTR));
                    assert_eq!(
                        core.vcpu_fd.get_regs().unwrap(),
                        before,
                        "fresh native owner completed an operation it never issued"
                    );
                }
                drop(boundary);
                memory
                    .memory()
                    .write_slice(
                        &[0xc6, 0x06, 0, 0x50, 0xa5, 0xe6, 0xe9, 0xf4],
                        GuestAddress(0x1000),
                    )
                    .unwrap();
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    memory
                        .memory()
                        .write_obj(0u8, GuestAddress(0x5000))
                        .unwrap();
                    assert!(
                        matches!(exit(&mut **cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8])
                    );
                    assert_eq!(
                        memory
                            .memory()
                            .read_obj::<u8>(GuestAddress(0x5000))
                            .unwrap(),
                        0xa5
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn observed_native_completion_clears_provenance_and_the_next_exit_reestablishes_it() {
    for irqchip in [false, true] {
        let (vm, memory, mut cpus) = graph(1, irqchip);
        memory
            .memory()
            .write_slice(&[0xec, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
            .unwrap();
        let CpuState::X86_64(mut state) = cpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rdx = 0x1234;
        cpus[0].set_state(&CpuState::X86_64(state)).unwrap();
        assert!(matches!(exit(&mut *cpus[0]), VcpuExit::IoIn { .. }));
        let handles = {
            let boundary = vm.checkpoint_boundary().unwrap();
            native(&*vm).checkpoint_cpu_handles(&boundary).unwrap()
        };
        assert!(handles[0].lock().unwrap().native_io_unsettled);
        cpus[0].complete_io_in(&[0x7c]);
        assert!(handles[0].lock().unwrap().native_io_unsettled);
        assert_eq!(
            cpus[0]
                .settle_checkpoint_io(&mut |_| panic!(
                    "completed input required another device callback"
                ))
                .unwrap(),
            CheckpointIoState::Complete
        );
        assert!(!handles[0].lock().unwrap().native_io_unsettled);
        assert!(
            matches!(exit(&mut *cpus[0]), VcpuExit::IoOut { port: 0xe9, data } if data == [0x7c])
        );
        assert!(handles[0].lock().unwrap().native_io_unsettled);
        cpus[0].complete_io_out().unwrap();
        assert!(handles[0].lock().unwrap().native_io_unsettled);
        assert_eq!(
            cpus[0]
                .settle_checkpoint_io(&mut |_| panic!("acknowledged output replayed its callback"))
                .unwrap(),
            CheckpointIoState::Complete
        );
        assert!(!handles[0].lock().unwrap().native_io_unsettled);
    }
}
