//! The SDK model retains native MSRs independently of public register state.
use super::*;
use rax::vm::vcpu::{CpuState, VcpuExit};

const SYSCALL: [u32; 4] = [0xc000_0081, 0xc000_0082, 0xc000_0083, 0xc000_0084];
pub(super) const NATIVE: [u32; 6] = [
    0xc000_0081,
    0xc000_0082,
    0xc000_0083,
    0xc000_0084,
    0xc000_0102,
    0xc000_0103,
];

#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_enable_native_msr(id: u32, msr: u32, enabled: bool) -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    let fail = sdk.fail_msr_enable == Some(msr);
    let Ok(cpu) = sdk.cpu(id, "enable-native-msr") else {
        return -1;
    };
    if fail {
        return -1;
    }
    if enabled {
        cpu.native_msrs.insert(msr);
    } else {
        cpu.native_msrs.remove(&msr);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vcpu_read_msr(id: u32, msr: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    let fail = sdk.fail_msr_read == Some(msr);
    let xor = sdk.msr_read_xor;
    let Ok(cpu) = sdk.cpu(id, "read-msr") else {
        return -1;
    };
    if fail || !cpu.native_msrs.contains(&msr) {
        return -1;
    }
    // SAFETY: checked SDK output word, written synchronously without retaining it.
    unsafe { output.write(cpu.msrs.get(&msr).copied().unwrap_or(0) ^ xor) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_write_msr(id: u32, msr: u32, value: u64) -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    let fail = sdk.fail_msr_write == Some(msr);
    let Ok(cpu) = sdk.cpu(id, "write-msr") else {
        return -1;
    };
    if !cpu.native_msrs.contains(&msr) {
        return -1;
    }
    // A failing SDK operation may already have changed state. The product
    // must fence execution rather than assume that an error means no write.
    cpu.msrs.insert(msr, value);
    if fail || sdk.fail_after("write-msr") {
        -1
    } else {
        0
    }
}

#[test]
fn syscall_and_swapgs_registers_are_bound_to_each_native_owner() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let first = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let second = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    let bindings: Vec<_> = SDK
        .lock()
        .unwrap()
        .cpus
        .values()
        .map(|cpu| cpu.native_msrs.clone())
        .collect();
    assert_eq!(
        bindings,
        vec![NATIVE.into_iter().collect(), NATIVE.into_iter().collect()]
    );
    drop(first);
    drop(second);
    drop(vm);
}

#[test]
fn syscall_public_projection_round_trips_independent_cpu_values() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    for id in 0..2 {
        let mut cpu = vm
            .create_vcpu(id, Arc::new(memory.memory().clone()))
            .unwrap();
        let mut state = cpu.get_state().unwrap();
        let CpuState::X86_64(public) = &mut state else {
            panic!("wrong architecture")
        };
        let values = [
            0x0023_0010_0000_0000,
            0xffff_8000_0000_1234 + u64::from(id),
            0xffff_8000_0000_5678 + u64::from(id),
            0x0004_7700,
        ];
        public.sregs.star = values[0];
        public.sregs.lstar = values[1];
        public.sregs.cstar = values[2];
        public.sregs.fmask = values[3];
        cpu.set_state(&state).unwrap();
        let CpuState::X86_64(restored) = cpu.get_state().unwrap() else {
            panic!("wrong architecture")
        };
        assert_eq!(
            [
                restored.sregs.star,
                restored.sregs.lstar,
                restored.sregs.cstar,
                restored.sregs.fmask
            ],
            values
        );
        let actual: Vec<_> = SDK
            .lock()
            .unwrap()
            .cpus
            .values()
            .next()
            .unwrap()
            .msrs
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        for (msr, value) in SYSCALL.into_iter().zip(values) {
            assert!(actual.contains(&(msr, value)));
        }
        drop(cpu);
    }
    drop(vm);
}

fn instruction(cpu: &mut dyn rax::vm::vcpu::VCpu, msr: u32, value: u64, reason: u32) {
    let mut state = cpu.get_state().unwrap();
    let CpuState::X86_64(public) = &mut state else {
        panic!("wrong architecture")
    };
    public.regs.rip = 0x100;
    public.regs.rflags = 2;
    // Only ECX and EDX:EAX are instruction inputs; high halves are ignored.
    public.regs.rcx = 0x1234_5678_0000_0000 | u64::from(msr);
    public.regs.rax = 0x8765_4321_0000_0000 | u64::from(value as u32);
    public.regs.rdx = 0x5678_1234_0000_0000 | (value >> 32);
    cpu.set_state(&state).unwrap();
    let mut sdk = SDK.lock().unwrap();
    let native = sdk.cpus.values_mut().next().unwrap();
    native.vmcs.insert(0x440c, 3);
    native.exits = [reason, 12].into_iter().collect();
}

#[test]
fn handled_native_msr_writes_and_reads_use_the_sdk_execution_bank() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    for (msr, value) in NATIVE.into_iter().zip([
        0x0023_0010_0000_0000,
        0xffff_8000_0000_1234,
        0xffff_8000_0000_5678,
        0x0004_7700,
        0xffff_8000_1234_0000,
        0x89ab_cdef,
    ]) {
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        instruction(cpu.as_mut(), msr, value, 32);
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        let actual = SDK.lock().unwrap().cpus.values().next().unwrap().msrs[&msr];
        assert_eq!(actual, value, "WRMSR {msr:#x}");
        cpu.wake();
        instruction(cpu.as_mut(), msr, 0, 31);
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture")
        };
        assert_eq!(state.regs.rax, value & 0xffff_ffff, "RDMSR {msr:#x}");
        assert_eq!(state.regs.rdx, value >> 32, "RDMSR {msr:#x}");
        assert_eq!(state.regs.rip, 0x106);
        drop(cpu);
    }
    assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
    drop(vm);
}

#[test]
fn syscall_projection_reads_changes_made_by_native_execution() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let values = [
        0x0023_0010_0000_0000,
        0xffff_8000_0000_1234,
        0xffff_8000_0000_5678,
        0x0004_7700,
    ];
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        for (msr, value) in SYSCALL.into_iter().zip(values) {
            native.msrs.insert(msr, value);
        }
    }
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    assert_eq!(
        [
            state.sregs.star,
            state.sregs.lstar,
            state.sregs.cstar,
            state.sregs.fmask
        ],
        values
    );
    drop(cpu);
    drop(vm);
}

#[test]
fn every_native_msr_initialization_stage_fails_closed_and_releases_the_cpu() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    for msr in NATIVE {
        for phase in 0..3 {
            {
                let mut sdk = SDK.lock().unwrap();
                sdk.fail_msr_enable = (phase == 0).then_some(msr);
                sdk.fail_msr_write = (phase == 1).then_some(msr);
                sdk.fail_msr_read = (phase == 2).then_some(msr);
            }
            let error = vm
                .create_vcpu(0, Arc::new(memory.memory().clone()))
                .err()
                .expect("failed native MSR initialization was admitted");
            assert!(
                error.to_string().contains(&format!("{msr:#010x}")),
                "{error}"
            );
            {
                let mut sdk = SDK.lock().unwrap();
                assert!(sdk.cpus.is_empty());
                assert_eq!(sdk.wrong_owner, 0);
                sdk.fail_msr_enable = None;
                sdk.fail_msr_write = None;
                sdk.fail_msr_read = None;
            }
            let cpu = vm
                .create_vcpu(0, Arc::new(memory.memory().clone()))
                .unwrap();
            drop(cpu);
        }
    }
    drop(vm);
}

#[test]
fn sdk_failure_during_handled_msr_write_prevents_retirement_and_future_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    instruction(cpu.as_mut(), SYSCALL[1], 0xffff_8000_0000_1234, 32);
    SDK.lock().unwrap().fail_msr_write = Some(SYSCALL[1]);
    assert!(cpu.run().is_err());
    let (rip, changed, calls) = {
        let sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values().next().unwrap();
        (
            native.registers[&0],
            native.msrs[&SYSCALL[1]],
            sdk.trace.len(),
        )
    };
    assert_eq!(rip, 0x100);
    assert_eq!(changed, 0xffff_8000_0000_1234);
    assert!(cpu.run().is_err());
    assert!(cpu.get_state().is_err());
    assert_eq!(SDK.lock().unwrap().trace.len(), calls);
    drop(cpu);
    drop(vm);
}

#[test]
fn failed_public_syscall_state_write_fences_execution_and_capture() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let mut state = cpu.get_state().unwrap();
    let CpuState::X86_64(public) = &mut state else {
        panic!("wrong architecture")
    };
    public.sregs.lstar = 0xffff_8000_0000_1234;
    SDK.lock().unwrap().fail_msr_write = Some(SYSCALL[1]);
    assert!(cpu.set_state(&state).is_err());
    SDK.lock().unwrap().fail_msr_write = None;
    let calls = SDK.lock().unwrap().trace.len();
    assert!(cpu.run().is_err());
    assert!(cpu.get_state().is_err());
    assert_eq!(SDK.lock().unwrap().trace.len(), calls);
    drop(cpu);
    drop(vm);
}

#[test]
fn syscall_sdk_read_errors_propagate_without_replacing_state_with_zero() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    for msr in SYSCALL {
        SDK.lock().unwrap().fail_msr_read = Some(msr);
        assert!(cpu.get_state().is_err());
        SDK.lock().unwrap().fail_msr_read = None;
        assert!(cpu.get_state().is_ok());
    }
    drop(cpu);
    drop(vm);
}

#[test]
fn incorrect_successful_initial_readback_rejects_the_cpu_before_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    SDK.lock().unwrap().msr_read_xor = 1;
    let error = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .err()
        .expect("incorrect initial MSR state was admitted");
    assert!(error.to_string().contains("readback differs from zero"));
    {
        let mut sdk = SDK.lock().unwrap();
        assert!(sdk.cpus.is_empty());
        assert!(
            !sdk.trace
                .iter()
                .any(|operation| operation.starts_with("run:"))
        );
        sdk.msr_read_xor = 0;
    }
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let all_zero = SDK
        .lock()
        .unwrap()
        .cpus
        .values()
        .all(|native| native.msrs.values().all(|&value| value == 0));
    assert!(all_zero, "fresh CPU inherited stale native MSR values");
    drop(cpu);
    drop(vm);
}
