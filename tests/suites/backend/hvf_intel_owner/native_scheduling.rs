//! Actual owner/SDK bridge with modeled kernel timer ownership; no guest runs.
use super::*;
use rax::vm::snapshot::{BackendContext, CpuSnapshot};
use rax::vm::vcpu::{VCpu, VcpuExit};
use std::time::Duration;

fn capture(vm: &dyn rax::backend::Vm, cpu: &dyn VCpu) -> (CpuSnapshot, Option<BackendContext>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    cpu.capture_checkpoint_record(&boundary, None).unwrap()
}

fn entry_count(id: u32) -> usize {
    SDK.lock().unwrap().cpus[&id].deadlines.len()
}

fn queue_io(read: bool) {
    let mut sdk = SDK.lock().unwrap();
    let cpu = sdk.cpus.get_mut(&0).unwrap();
    cpu.vmcs
        .insert(0x6400, (0x3f8 << 16) | if read { 8 } else { 0 });
    cpu.vmcs.insert(0x440c, 3);
    cpu.exits.push_back(30);
}

fn queue_vectoring(cpu: &mut Cpu, vectoring: u64, qualification: u64) {
    cpu.exits.push_back(48);
    cpu.vmcs.insert(0x6400, qualification);
    cpu.vmcs.insert(0x2400, 0x2400);
    cpu.vmcs.insert(0x4408, vectoring);
}

#[test]
fn posted_host_slices_overlap_on_two_and_four_permanent_owners() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let timeout = Duration::from_secs(5);
    for count in [2, 4] {
        let (vm, memory) = fixture();
        let mut cpus = (0..count)
            .map(|id| {
                vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let (entered, arrivals) = mpsc::channel();
        let mut releases = Vec::new();
        {
            let mut sdk = SDK.lock().unwrap();
            for id in 0..count {
                let (release, gate) = mpsc::channel();
                sdk.cpus.get_mut(&id).unwrap().run_gate = Some((entered.clone(), gate));
                releases.push(release);
            }
        }
        for cpu in &mut cpus {
            cpu.post_host_slice(timeout).expect("post Intel host slice");
        }
        let mut active = BTreeSet::new();
        for _ in 0..count {
            let id = arrivals
                .recv_timeout(timeout)
                .expect("concurrent SDK entry");
            assert!(active.insert(id), "an SDK owner entered twice");
        }
        assert_eq!(active, (0..count).collect());
        let (attempted, rejection) = mpsc::channel();
        let result = std::thread::scope(|scope| {
            let vm = vm.as_ref();
            scope.spawn(move || {
                attempted.send(vm.checkpoint_boundary().map(drop)).unwrap();
            });
            let result = rejection.recv_timeout(Duration::from_secs(2));
            // Release the owners even when capture is waiting for the write lock.
            for release in releases {
                release.send(()).unwrap();
            }
            result
        });
        let error = result
            .expect("checkpoint waited for the posted SDK owners")
            .expect_err("checkpoint admitted with posted SDK owners");
        assert!(
            error
                .to_string()
                .contains("requires collecting all posted host slices")
        );
        for (index, cpu) in cpus.iter_mut().enumerate() {
            assert!(vm.checkpoint_boundary().is_err());
            assert!(cpu.get_state().is_err());
            assert!(cpu.post_host_slice(timeout).is_err());
            assert!(cpu.collect_host_slice().unwrap().is_none());
            assert!(cpu.collect_host_slice().is_err());
            assert!(cpu.get_state().is_ok(), "CPU {index} remained reserved");
        }
        assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
        for cpu in &cpus {
            assert!(capture(vm.as_ref(), cpu.as_ref()).1.is_some());
        }
    }
}

#[test]
fn finite_entries_yield_without_halt_and_keep_each_permanent_owner() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for visible in [false, true] {
        for count in [2, 4] {
            let (vm, memory) = fixture();
            SDK.lock().unwrap().timer_visible = visible;
            let mut cpus = (0..count)
                .map(|id| {
                    vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                        .unwrap()
                })
                .collect::<Vec<_>>();
            for _ in 0..8 {
                for (id, cpu) in cpus.iter_mut().enumerate() {
                    assert!(cpu.supports_host_slices());
                    let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
                    assert!(
                        cpu.run_host_slice(Duration::from_secs(1))
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(
                        rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                        before
                    );
                    assert_eq!(cpu.instruction_count(), 0);
                    assert_eq!(
                        SDK.lock().unwrap().cpus[&(id as u32)]
                            .vmcs
                            .get(&0x4826)
                            .copied()
                            .unwrap_or(0),
                        0,
                        "host yield must not publish HLT activity"
                    );
                }
            }
            let sdk = SDK.lock().unwrap();
            assert_eq!(sdk.wrong_owner, 0);
            for cpu in sdk.cpus.values() {
                assert_eq!(cpu.raw_entries, 0);
                assert_eq!(cpu.deadlines.len(), 8);
                assert!(cpu.deadlines.iter().all(|&end| end != u64::MAX));
            }
            drop(sdk);
            drop(cpus);
            drop(vm);
        }
    }
}

#[test]
fn sdk_timer_is_excluded_from_records_and_restore_accepts_owned_readback() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for client_timer_control in [false, true] {
        let (vm, memory) = fixture();
        {
            let mut sdk = SDK.lock().unwrap();
            sdk.initial_timer = true;
            sdk.client_timer_control = client_timer_control;
        }
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
        assert!(
            cpu.run_host_slice(Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        assert_ne!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4000] & 64, 0);
        // Context validation rejects pin values that differ from its producer
        // policy. Success here requires copied-state normalization, including
        // the construction profile when the SDK exposes its bit from creation.
        assert!(capture(vm.as_ref(), cpu.as_ref()).1.is_some());
        let pin_writes = SDK.lock().unwrap().cpus[&0].pin_writes;
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
            .unwrap();
        assert_eq!(
            SDK.lock().unwrap().cpus[&0].pin_writes,
            pin_writes,
            "restore must validate fixed pin controls without writing SDK timer state"
        );
        assert_ne!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4000] & 64, 0);
        assert!(capture(vm.as_ref(), cpu.as_ref()).1.is_some());
        assert!(
            cpu.run_host_slice(Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4000] & 64, 0);
        cpu.wake();
        assert!(
            cpu.run_host_slice(Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        let sdk = SDK.lock().unwrap();
        assert_eq!(sdk.cpus[&0].raw_entries, 0);
        let deadlines = &sdk.cpus[&0].deadlines;
        assert_eq!(deadlines.len(), 4);
        assert!(deadlines[0] != u64::MAX && deadlines[1] != u64::MAX);
        assert_eq!(deadlines[2], u64::MAX);
        assert_ne!(deadlines[3], u64::MAX);
        drop(sdk);
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn real_io_after_expiry_and_prepared_input_keep_the_original_frontier() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    queue_io(true);
    SDK.lock().unwrap().cpus.get_mut(&0).unwrap().delay_return = true;
    let mut observed = false;
    for _ in 0..8 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            assert!(matches!(
                exit,
                VcpuExit::IoIn {
                    port: 0x3f8,
                    size: 1
                }
            ));
            observed = true;
            break;
        }
    }
    assert!(observed, "model never reached the real input exit");
    let entered = entry_count(0);
    assert_eq!(entered, 1);
    assert!(matches!(
        cpu.run_host_slice(Duration::from_nanos(1)).unwrap(),
        Some(VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        })
    ));
    assert_eq!(entry_count(0), entered);
    cpu.complete_io_in(&[0x5a]);
    assert!(cpu.io_completion_result().is_ok());
    let rax::vm::vcpu::CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!((state.regs.rax & 0xff, state.regs.rip), (0x5a, 3));
    drop(cpu);
    drop(vm);
}

#[test]
fn ept_interrupted_irq_remains_owned_by_the_saved_cpu_until_retry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let limit = Duration::from_secs(1);
    for sliced in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let rax::vm::vcpu::CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            panic!();
        };
        state.regs.rflags = 0x202;
        state.regs.rip = 0x1000;
        state.regs.rsp = 0x3000;
        cpu.set_state(&rax::vm::vcpu::CpuState::X86_64(state))
            .unwrap();
        assert!(cpu.inject_interrupt(0x40).unwrap());
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            // Section 29.2.4 leaves bit 12 undefined in the output field.
            queue_vectoring(native, 0x8000_1040, 0x581);
        }
        let error = if sliced {
            cpu.run_host_slice(limit).unwrap_err()
        } else {
            cpu.run().unwrap_err()
        };
        let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
        assert!(error.to_string().contains("EPT GPA 0x2400"), "{error}");
        assert_eq!(entry_count(0), 1);
        assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4016], 0x8000_0040);
        let rax::vm::vcpu::CpuState::X86_64(stopped) = saved.state else {
            panic!();
        };
        assert_eq!((stopped.regs.rip, stopped.regs.rsp), (0x1000, 0x3000));
        assert!(!cpu.inject_interrupt(0x41).unwrap());
        drop(cpu);
        drop(vm);

        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        cpu.restore_checkpoint_context(
            &rax::vm::vcpu::CpuState::X86_64(stopped),
            &saved.emulator,
            context.as_ref(),
        )
        .unwrap();
        assert!(!cpu.inject_interrupt(0x41).unwrap());
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            assert_eq!(native.vmcs[&0x4016], 0x8000_0040);
            native.exits.push_back(12);
            native.vmcs.insert(0x440c, 1);
        }
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        assert_eq!(entry_count(0), 1);
        assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4016], 0x40);
    }
}

#[test]
fn interrupted_events_preserve_type_specific_entry_fields() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // NMI, #DE, #PF, INT 0x80, INT1, and INT3. Each entry field starts with
    // a different value so spurious writes to unused fields are observable.
    for (info, length, expected_error, expected_length, expected_blocking) in [
        (0x8000_0202, 2, 0x1111, 7, 0),
        (0x8000_0300, 2, 0x1111, 7, 8),
        (0x8000_0b0e, 2, 0x23, 7, 8),
        (0x8000_0480, 2, 0x1111, 2, 8),
        (0x8000_0501, 2, 0x1111, 2, 8),
        (0x8000_0603, 2, 0x1111, 2, 8),
        (0x8000_0480, 0, 0x1111, 0, 8),
    ] {
        let (vm, memory) = fixture();
        SDK.lock().unwrap().zero_length_event = length == 0;
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            queue_vectoring(native, info, 0x582); // A delivery stack write.
            native.vmcs.extend([
                (0x6800, 1), // CR0.PE
                (0x4824, 8), // NMI blocking after a delivery attempt
                (0x440a, 0x23),
                (0x440c, length),
                (0x4018, 0x1111),
                (0x401a, 7),
            ]);
        }
        let error = cpu.run().unwrap_err().to_string();
        assert!(error.contains("event retained for retry"), "{error}");
        let sdk = SDK.lock().unwrap();
        let vmcs = &sdk.cpus[&0].vmcs;
        assert_eq!(vmcs[&0x4016], info);
        assert_eq!(vmcs[&0x4018], expected_error);
        assert_eq!(vmcs[&0x401a], expected_length);
        assert_eq!(vmcs[&0x4824], expected_blocking);
        drop(sdk);
        assert!(!cpu.inject_nmi().unwrap());
    }
}

#[test]
fn invalid_vectoring_data_and_sdk_publication_failures_fence_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (info, qualification, length, fail_write) in [
        (0x8000_0040, 0x584, 2, false),    // EPTE execute access
        (0x8000_0040, 0x1_0581, 2, false), // Asynchronous access
        (0x8000_0100, 0x581, 2, false),    // Reserved event type
        (0x8000_0203, 0x581, 2, false),    // Wrong NMI vector
        (0x8000_0c80, 0x581, 2, false),    // Software event with an error code
        (0x8000_0480, 0x581, 0, false),    // No zero-length injection capability
        (0x8000_0480, 0x581, 16, false),   // Illegal software instruction length
        (0x8000_0480, 0x581, 2, true),     // Fails after partially writing a field
    ] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            queue_vectoring(native, info, qualification);
            native.vmcs.insert(0x440c, length);
            if fail_write {
                sdk.fault = Some(Fault {
                    operation: "write-vmcs",
                    remaining: 1,
                    persistent: false,
                });
            }
        }
        let error = cpu.run().unwrap_err().to_string();
        assert!(error.contains("guest entry prohibited"), "{error}");
        assert_eq!(entry_count(0), 1);
        assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4016] >> 31, 0);
        assert!(cpu.run().is_err());
        assert_eq!(entry_count(0), 1);
    }
}

#[test]
fn unsupported_timer_and_interrupted_delivery_fence_later_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for unsupported in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            native.finite_unsupported = unsupported;
            if !unsupported {
                native.vmcs.insert(0x4408, 0x8000_000e);
                native.vmcs.insert(0x440a, 0x40);
                native.vmcs.insert(0x4016, 0x8000_0b0d);
            }
        }
        assert!(cpu.run_host_slice(Duration::from_secs(1)).is_err());
        let entered = entry_count(0);
        assert_eq!(entered, 1);
        assert!(cpu.run_host_slice(Duration::from_secs(1)).is_err());
        assert!(cpu.run().is_err());
        assert_eq!(entry_count(0), entered);
        if !unsupported {
            // Normal VM exit cleared valid before the backend rejected the
            // unsupported interrupted delivery. No entry is permitted again.
            assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4016], 0x0000_0b0d);
        }
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn failed_entry_is_not_hidden_by_stale_vectoring_or_timer_basic_reason() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.exits.push_back(0x8000_0034);
        native.vmcs.insert(0x4408, u64::MAX);
    }
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(1)).unwrap(),
        Some(VcpuExit::FailEntry {
            reason: 0x8000_0034
        })
    ));
    drop(cpu);
    drop(vm);
}

#[test]
fn prepared_clock_rebase_is_submitted_even_if_preparation_exhausts_the_slice() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let (saved, context) = capture(vm.as_ref(), cpu.as_ref());
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
        .unwrap();
    SDK.lock().unwrap().cpus.get_mut(&0).unwrap().delay_tpr_read = true;
    let mut submitted = false;
    for _ in 0..8 {
        let before = SDK.lock().unwrap().trace.len();
        let entries = entry_count(0);
        assert!(
            cpu.run_host_slice(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        let rebased = SDK.lock().unwrap().trace[before..]
            .iter()
            .any(|item| item.starts_with("set-tsc-relative:"));
        let entered = entry_count(0) != entries;
        assert!(
            !rebased || entered,
            "clock rebase consumed without submitting SDK entry"
        );
        if entered {
            assert!(rebased);
            submitted = true;
            break;
        }
    }
    assert!(submitted, "model never reached native preparation");
    drop(cpu);
    drop(vm);
}

#[cfg(feature = "debug")]
#[test]
fn prepared_debug_completion_precedes_a_new_expired_entry_deadline() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    cpu.set_single_step(true);
    queue_io(false);
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(1)).unwrap(),
        Some(VcpuExit::IoOut { .. })
    ));
    cpu.complete_io_out().unwrap();
    let entered = entry_count(0);
    assert!(matches!(
        cpu.run_host_slice(Duration::from_nanos(1)).unwrap(),
        Some(VcpuExit::GdbStep)
    ));
    assert_eq!(entry_count(0), entered);
    drop(cpu);
    drop(vm);
}

#[test]
fn invalid_host_intervals_reject_without_entry_or_poisoning() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
    for interval in [Duration::ZERO, Duration::MAX] {
        assert!(matches!(
            cpu.run_host_slice(interval),
            Err(rax::error::Error::InvalidConfig(_))
        ));
    }
    assert_eq!(entry_count(0), 0);
    assert_eq!(
        rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
        before
    );
    assert!(
        cpu.run_host_slice(Duration::from_secs(1))
            .unwrap()
            .is_none()
    );
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    drop(cpu);
    drop(vm);
}

#[test]
fn changed_fixed_client_pin_controls_reject_before_entry_and_fence_retries() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    *SDK.lock()
        .unwrap()
        .cpus
        .get_mut(&0)
        .unwrap()
        .vmcs
        .entry(0x4000)
        .or_default() ^= 1 << 5;
    let error = cpu.run_host_slice(Duration::from_secs(1)).unwrap_err();
    assert!(
        error.to_string().contains("native SDK timer policy"),
        "{error}"
    );
    assert_eq!(entry_count(0), 0);
    assert!(cpu.run_host_slice(Duration::from_secs(1)).is_err());
    assert!(cpu.run().is_err());
    assert_eq!(entry_count(0), 0);
    drop(cpu);
    drop(vm);
}
