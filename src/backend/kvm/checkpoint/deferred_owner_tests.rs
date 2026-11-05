//! Source-free queued-result restoration through the managed native owner.
use super::*;

fn queued_results() -> [Option<VcpuExit>; 7] {
    [
        None,
        Some(VcpuExit::Hlt),
        Some(VcpuExit::Shutdown),
        Some(VcpuExit::SystemEvent {
            type_: 7,
            flags: 0x1234,
        }),
        Some(VcpuExit::FailEntry { reason: 0x9876 }),
        Some(VcpuExit::InternalError),
        Some(VcpuExit::Unknown("retained native completion".into())),
    ]
}

fn prepare_canaries(memory: &GuestMemoryWrapper, cpus: &mut [Box<dyn VCpu>]) {
    // MOV byte [BX],AL; OUT 0xe9,AL; HLT, in 16-bit real mode.
    memory
        .memory()
        .write_slice(&[0x88, 0x07, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap();
    for (id, cpu) in cpus.iter_mut().enumerate() {
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rbx = 0x2000 + id as u64;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
    }
}

fn seed(vm: &dyn Vm, boundary: &CheckpointBoundary<'_>, result: Option<&VcpuExit>) {
    let vm = native(vm);
    let handles = vm.checkpoint_cpu_handles(boundary).unwrap();
    let irqchip = vm.memory.irqchip_created.load(Ordering::Acquire);
    for mut core in lock_cpus(vm, &handles).unwrap() {
        core.deferred_exit = result.cloned();
        core.userspace_halted = !irqchip && matches!(result, Some(VcpuExit::Hlt));
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn source_free_deferred_results_replace_destination_queues_before_each_cpu_canary() {
    for irqchip in [false, true] {
        for count in [1, 2, 4] {
            for expected in queued_results() {
                let (source, memory, mut cpus) = graph(count, irqchip);
                prepare_canaries(&memory, &mut cpus);
                let boundary = source.checkpoint_boundary().unwrap();
                seed(&*source, &boundary, expected.as_ref());
                let saved = native(&*source).capture_native_banks(&boundary).unwrap();
                let json = serde_json::to_vec(&saved).unwrap();
                let binary = crate::codec::serialize(&saved).unwrap();
                drop(boundary);
                drop(cpus);
                drop(source);
                drop(memory);
                for image in [
                    serde_json::from_slice::<Image>(&json).unwrap(),
                    crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
                ] {
                    let (target, memory, mut cpus) = graph(count, irqchip);
                    prepare_canaries(&memory, &mut cpus);
                    let boundary = target.checkpoint_boundary().unwrap();
                    seed(
                        &*target,
                        &boundary,
                        Some(&VcpuExit::Unknown(
                            "destination result must disappear".into(),
                        )),
                    );
                    image.restore_stored(native(&*target), &boundary).unwrap();
                    let recaptured = native(&*target).capture_native_banks(&boundary).unwrap();
                    assert_eq!(recaptured.deferred, image.deferred);
                    image
                        .stage_resume_clock(native(&*target), &boundary)
                        .unwrap();
                    drop(boundary);
                    // Deliver all queued results before entering any CPU. An
                    // earlier CPU's OUT would otherwise leave a native I/O
                    // continuation, which this test deliberately does not own.
                    for (id, cpu) in cpus.iter_mut().enumerate() {
                        if let Some(expected) = &expected {
                            let repeats = if matches!(
                                expected,
                                VcpuExit::Shutdown | VcpuExit::SystemEvent { .. }
                            ) {
                                2
                            } else {
                                1
                            };
                            for _ in 0..repeats {
                                let delivered = cpu
                                    .run_host_slice(Duration::from_millis(10))
                                    .unwrap()
                                    .unwrap();
                                assert_eq!(format!("{delivered:?}"), format!("{expected:?}"));
                                assert_eq!(cpu.current_pc(), 0x1000);
                                assert_eq!(
                                    memory
                                        .memory()
                                        .read_obj::<u8>(GuestAddress(0x2000 + id as u64))
                                        .unwrap(),
                                    0
                                );
                            }
                        }
                    }
                    if matches!(
                        expected,
                        Some(VcpuExit::Shutdown | VcpuExit::SystemEvent { .. })
                    ) {
                        continue;
                    }
                    for (id, cpu) in cpus.iter_mut().enumerate() {
                        cpu.wake();
                        assert!(
                            matches!(exit(&mut **cpu), VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8])
                        );
                        assert_eq!(
                            memory
                                .memory()
                                .read_obj::<u8>(GuestAddress(0x2000 + id as u64))
                                .unwrap(),
                            0x21 + id as u8
                        );
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn first_entry_keeps_a_peers_queued_result_until_that_peers_delivery() {
    let (vm, memory, mut cpus) = graph(2, false);
    prepare_canaries(&memory, &mut cpus);
    let boundary = vm.checkpoint_boundary().unwrap();
    let handles = native(&*vm).checkpoint_cpu_handles(&boundary).unwrap();
    handles[1].lock().unwrap().deferred_exit = Some(VcpuExit::FailEntry { reason: 0x9876 });
    let image = native(&*vm).capture_native_banks(&boundary).unwrap();
    image.stage_resume_clock(native(&*vm), &boundary).unwrap();
    drop(boundary);
    assert!(matches!(
        exit(&mut *cpus[0]),
        VcpuExit::IoOut { port: 0xe9, .. }
    ));
    assert!(matches!(
        exit(&mut *cpus[1]),
        VcpuExit::FailEntry { reason: 0x9876 }
    ));
    assert_eq!(
        memory
            .memory()
            .read_obj::<u8>(GuestAddress(0x2001))
            .unwrap(),
        0
    );
    assert!(native(&*vm).memory.resume_clock.lock().unwrap().is_none());
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn malformed_deferred_records_reject_before_native_banks_or_destination_queues_change() {
    let (vm, _memory, _cpus) = graph(2, true);
    let boundary = vm.checkpoint_boundary().unwrap();
    seed(&*vm, &boundary, Some(&VcpuExit::FailEntry { reason: 42 }));
    let vm = native(&*vm);
    let before = vm.capture_native_banks(&boundary).unwrap();
    let mut invalid = Vec::new();
    let mut legacy = before.clone();
    legacy.version = 2;
    invalid.push(legacy);
    let mut short = before.clone();
    short.deferred.pop();
    invalid.push(short);
    let mut long = before.clone();
    long.deferred.push(None);
    invalid.push(long);
    let mut text = before.clone();
    text.deferred[1] = Some(super::super::deferred::Image::Unknown(vec![0xff]));
    invalid.push(text);
    for image in invalid {
        assert!(image.restore_stored(vm, &boundary).is_err());
        let after = vm.capture_native_banks(&boundary).unwrap();
        assert_eq!(stored_cpu_banks(&before), stored_cpu_banks(&after));
        assert_eq!(after.deferred, before.deferred);
    }
}

#[test]
#[ignore = "requires physical Linux KVM; selected by KVM CI"]
fn unsupported_deferred_peer_rejects_before_accepting_another_cpus_init() {
    let (vm, _memory, _cpus) = graph(2, true);
    let boundary = vm.checkpoint_boundary().unwrap();
    let vm = native(&*vm);
    let handles = vm.checkpoint_cpu_handles(&boundary).unwrap();
    handles[1].lock().unwrap().deferred_exit = Some(VcpuExit::IoIn { port: 1, size: 1 });
    let before = handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap();
    assert_eq!(
        vm.memory
            .vm_fd
            .signal_msi(kvm_bindings::kvm_msi {
                address_lo: 0xfee0_0000,
                data: 0x4500,
                ..Default::default()
            })
            .unwrap(),
        1
    );
    let result = vm.capture_native_banks(&boundary);
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("native deferred result")
    );
    assert_eq!(
        handles[0].lock().unwrap().vcpu_fd.get_regs().unwrap(),
        before
    );
    assert!(matches!(
        handles[1].lock().unwrap().deferred_exit,
        Some(VcpuExit::IoIn { port: 1, size: 1 })
    ));
}
