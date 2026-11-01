//! Actual owner/SDK window continuation; no Hypervisor VM or guest executes.
use super::{SDK, SERIAL, WindowFault, fixture};
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use std::time::Duration;

const PRIMARY: u32 = 0x4002;
const WINDOW: u64 = 1 << 2;
#[cfg(feature = "debug")]
const MTF: u64 = 1 << 27;

fn enable_interrupts(cpu: &mut dyn VCpu) {
    let mut public = cpu.get_state().unwrap();
    let CpuState::X86_64(state) = &mut public else {
        panic!("Intel fixture returned a different architecture");
    };
    state.regs.rflags |= 0x200;
    cpu.set_state(&public).unwrap();
}

fn arm_window() -> u64 {
    let mut sdk = SDK.lock().unwrap();
    let native = sdk.cpus.get_mut(&0).unwrap();
    let controls = native.vmcs.entry(PRIMARY).or_default();
    *controls |= WINDOW;
    *controls
}

fn entry_count() -> usize {
    SDK.lock().unwrap().cpus[&0].deadlines.len()
}

#[test]
fn restored_window_control_allows_the_queued_guest_exit_to_progress() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for bounded in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        enable_interrupts(cpu.as_mut());
        let original = arm_window();
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        drop(boundary);
        *SDK.lock()
            .unwrap()
            .cpus
            .get_mut(&0)
            .unwrap()
            .vmcs
            .get_mut(&PRIMARY)
            .unwrap() &= !WINDOW;
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, context.as_ref())
            .unwrap();
        {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            assert_eq!(native.vmcs[&PRIMARY], original);
            native.exits.push_back(12);
        }
        let result = if bounded {
            cpu.run_host_slice(Duration::from_secs(10))
        } else {
            cpu.run().map(Some)
        };
        assert!(
            matches!(result, Ok(Some(VcpuExit::Hlt))),
            "restored window stalled bounded={bounded}: {result:?}"
        );
        let sdk = SDK.lock().unwrap();
        let native = &sdk.cpus[&0];
        assert_eq!(native.window_exits, 1);
        assert_eq!(native.deadlines.len(), 2);
        assert_eq!(native.vmcs[&PRIMARY], original & !WINDOW);
        assert!(native.exits.is_empty());
        assert_eq!(sdk.wrong_owner, 0);
        drop(sdk);
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn repeated_independent_windows_yield_without_retirement_or_other_control_changes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    enable_interrupts(cpu.as_mut());
    let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
    for round in 0..8 {
        let original = arm_window();
        assert!(
            cpu.run_host_slice(Duration::from_secs(10))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            before
        );
        assert_eq!(cpu.instruction_count(), 0);
        let sdk = SDK.lock().unwrap();
        let native = &sdk.cpus[&0];
        assert_eq!(native.window_exits, round + 1);
        assert_eq!(native.consecutive_windows, 0);
        assert_eq!(native.vmcs[&PRIMARY], original & !WINDOW);
        assert_eq!(native.deadlines.len(), 2 * (round + 1));
    }
    drop(cpu);
    drop(vm);
}

#[test]
fn every_window_acknowledgement_host_failure_fences_later_guest_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for fault in [
        WindowFault::ReadBefore,
        WindowFault::WriteBefore,
        WindowFault::WriteAfter,
        WindowFault::ReadAfter,
        WindowFault::IgnoreWrite,
        WindowFault::ChangeOtherBit,
    ] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        enable_interrupts(cpu.as_mut());
        arm_window();
        SDK.lock().unwrap().cpus.get_mut(&0).unwrap().window_fault = Some(fault);
        let error = cpu.run_host_slice(Duration::from_secs(10)).unwrap_err();
        assert!(error.to_string().contains("guest entry prohibited"));
        assert_eq!(entry_count(), 1, "fault={fault:?}, error={error}");
        assert!(cpu.run().is_err(), "fault={fault:?}");
        assert!(cpu.run_host_slice(Duration::from_secs(10)).is_err());
        assert_eq!(entry_count(), 1, "failed acknowledgement was retried");
        let sdk = SDK.lock().unwrap();
        let native = &sdk.cpus[&0];
        assert_eq!(native.window_exits, 1);
        assert_eq!(
            native.window_control_writes.len(),
            usize::from(fault != WindowFault::ReadBefore)
        );
        assert_eq!(sdk.wrong_owner, 0);
        drop(sdk);
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn window_continuation_preserves_the_real_pending_input_frontier() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    enable_interrupts(cpu.as_mut());
    arm_window();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.vmcs.insert(0x6400, (0x3f8 << 16) | 8);
        native.vmcs.insert(0x440c, 3);
        native.exits.push_back(30);
    }
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(10)).unwrap(),
        Some(VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        })
    ));
    let entered = entry_count();
    assert_eq!(entered, 2);
    let boundary = vm.checkpoint_boundary().unwrap();
    let (pending, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    drop(boundary);
    assert!(
        context.is_some(),
        "pending input needs its private continuation"
    );
    let CpuState::X86_64(state) = pending.state else {
        panic!("wrong architecture");
    };
    assert_eq!(state.regs.rip, 0);
    assert!(matches!(
        cpu.run_host_slice(Duration::from_nanos(1)).unwrap(),
        Some(VcpuExit::IoIn {
            port: 0x3f8,
            size: 1
        })
    ));
    assert_eq!(entry_count(), entered);
    cpu.complete_io_in(&[0x5a]);
    assert!(cpu.io_completion_result().is_ok());
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture");
    };
    assert_eq!((state.regs.rip, state.regs.rax & 0xff), (3, 0x5a));
    drop(cpu);
    drop(vm);
}

#[cfg(feature = "debug")]
#[test]
fn window_acknowledgement_preserves_monitor_trap_and_waits_for_its_actual_exit() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    enable_interrupts(cpu.as_mut());
    cpu.set_single_step(true);
    let original = arm_window();
    assert_ne!(original & MTF, 0);
    assert!(
        cpu.run_host_slice(Duration::from_secs(10))
            .unwrap()
            .is_none(),
        "an interrupt-window exit must not synthesize a debugger completion"
    );
    assert!(cpu.is_single_step());
    assert_eq!(
        SDK.lock().unwrap().cpus[&0].vmcs[&PRIMARY],
        original & !WINDOW
    );
    SDK.lock()
        .unwrap()
        .cpus
        .get_mut(&0)
        .unwrap()
        .exits
        .push_back(37);
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(10)).unwrap(),
        Some(VcpuExit::GdbStep)
    ));
    assert_eq!(entry_count(), 3);
    drop(cpu);
    drop(vm);
}

#[test]
fn normal_exit_and_failed_entry_retain_distinct_event_slot_ownership() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for failed in [false, true] {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        enable_interrupts(cpu.as_mut());
        assert!(cpu.inject_interrupt(0x41).unwrap());
        assert!(!cpu.can_inject_interrupt());
        if failed {
            SDK.lock()
                .unwrap()
                .cpus
                .get_mut(&0)
                .unwrap()
                .exits
                .push_back(0x8000_0021);
        }
        let exit = cpu.run_host_slice(Duration::from_secs(10)).unwrap();
        assert!(
            matches!(
                (&exit, failed),
                (None, false) | (Some(VcpuExit::FailEntry { .. }), true)
            ),
            "exit={exit:?}, failed={failed}"
        );
        assert_eq!(cpu.can_inject_interrupt(), !failed);
        assert_eq!(
            SDK.lock().unwrap().cpus[&0].vmcs[&0x4016],
            if failed { 0x8000_0041 } else { 0x41 }
        );
        drop(cpu);
        drop(vm);
    }
}

#[test]
fn sdk_acknowledged_window_avoids_an_additional_primary_control_write() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    enable_interrupts(cpu.as_mut());
    let original = arm_window();
    SDK.lock()
        .unwrap()
        .cpus
        .get_mut(&0)
        .unwrap()
        .auto_ack_window = true;
    assert!(
        cpu.run_host_slice(Duration::from_secs(10))
            .unwrap()
            .is_none()
    );
    let sdk = SDK.lock().unwrap();
    let native = &sdk.cpus[&0];
    assert_eq!(native.window_exits, 1);
    assert_eq!(native.deadlines.len(), 2);
    assert_eq!(native.vmcs[&PRIMARY], original & !WINDOW);
    assert!(native.window_control_writes.is_empty());
    drop(sdk);
    drop(cpu);
    drop(vm);
}
