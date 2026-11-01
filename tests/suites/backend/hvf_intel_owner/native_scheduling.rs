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
