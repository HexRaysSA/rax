//! The SDK model retains native MSRs independently of public register state.
use super::*;
use rax::vm::vcpu::{CpuState, VcpuExit};

fn deadline_msr(cpu: &mut dyn rax::vm::vcpu::VCpu, id: u32, write: Option<u64>) -> u64 {
    use std::time::Duration;
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&id).unwrap();
        let value = write.unwrap_or(0x1234_5678_8765_4321);
        native.registers.insert(0, 0x1000);
        native.registers.insert(1, 2);
        native.registers.insert(2, value & 0xffff_ffff);
        native.registers.insert(3, 0x6e0);
        native.registers.insert(4, value >> 32);
        native.registers.insert(36, 1);
        native.vmcs.insert(0x802, 0);
        native.vmcs.insert(0x440c, 2);
        native.vmcs.insert(0x4016, 0);
        native.exits = [if write.is_some() { 32 } else { 31 }, 0x8000_0021]
            .into_iter()
            .collect();
    }
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(1)).unwrap(),
        Some(VcpuExit::FailEntry {
            reason: 0x8000_0021
        })
    ));
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture")
    };
    assert_eq!(state.regs.rip, 0x1002);
    state.regs.rax | (state.regs.rdx << 32)
}

#[test]
fn deadline_msr_round_trips_through_the_attached_local_controller() {
    use rax::devices::bus::MmioDevice;
    use rax::devices::lapic::{LapicDevice, LocalApic};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());
    device.write(0xfee0_0320, &0x0004_0051u32.to_le_bytes());
    cpu.attach_local_apic(lapic);
    for expected in [u64::MAX, 0x1234_5678_8765_4321, 0] {
        deadline_msr(cpu.as_mut(), 0, Some(expected));
        assert_eq!(deadline_msr(cpu.as_mut(), 0, None), expected);
    }
}

#[test]
fn deadline_private_restore_retains_each_cpu_arm_and_untransferred_expiry() {
    use rax::devices::bus::MmioDevice;
    use rax::devices::lapic::{LapicDevice, LocalApic};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for count in [1, 2, 4] {
        let (vm, memory) = fixture();
        let mut cpus = Vec::new();
        let mut controllers = Vec::new();
        for id in 0..count {
            let mut cpu = vm
                .create_vcpu(id, Arc::new(memory.memory().clone()))
                .unwrap();
            let lapic = Arc::new(Mutex::new(LocalApic::new(id)));
            LapicDevice::new(lapic.clone()).write(0xfee0_0320, &(0x40051 + id).to_le_bytes());
            cpu.attach_local_apic(lapic.clone());
            deadline_msr(cpu.as_mut(), id, Some(u64::MAX - u64::from(id)));
            cpus.push(cpu);
            controllers.push(lapic);
        }
        let boundary = vm.checkpoint_boundary().unwrap();
        let saved: Vec<_> = cpus
            .iter()
            .map(|cpu| cpu.capture_checkpoint_record(&boundary, None).unwrap())
            .collect();
        drop(boundary);
        for (id, (cpu, (public, private))) in cpus.iter_mut().zip(&saved).enumerate() {
            deadline_msr(cpu.as_mut(), id as u32, Some(0));
            cpu.restore_checkpoint_context(&public.state, &public.emulator, private.as_ref())
                .unwrap();
        }
        SDK.lock().unwrap().tsc = u64::MAX;
        for (id, cpu) in cpus.iter_mut().enumerate() {
            cpu.poll_vm_clock().unwrap();
            assert_eq!(
                controllers[id].lock().unwrap().get_pending_vector(),
                None,
                "polling before first entry must use the saved TSC"
            );
            assert_eq!(
                deadline_msr(cpu.as_mut(), id as u32, None),
                u64::MAX - id as u64
            );
            deadline_msr(cpu.as_mut(), id as u32, Some(1));
            assert_eq!(deadline_msr(cpu.as_mut(), id as u32, None), 0);
            let boundary = vm.checkpoint_boundary().unwrap();
            let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
            drop(boundary);
            cpu.poll_vm_clock().unwrap();
            let vector = 0x51 + id as u8;
            assert_eq!(
                controllers[id].lock().unwrap().get_pending_vector(),
                Some(vector)
            );
            controllers[id].lock().unwrap().ack_interrupt(vector);
            LapicDevice::new(controllers[id].clone()).write(0xfee0_00b0, &0u32.to_le_bytes());
            cpu.restore_checkpoint_context(&public.state, &public.emulator, private.as_ref())
                .unwrap();
            cpu.poll_vm_clock().unwrap();
            assert_eq!(
                controllers[id].lock().unwrap().get_pending_vector(),
                Some(vector)
            );
            controllers[id].lock().unwrap().ack_interrupt(vector);
            LapicDevice::new(controllers[id].clone()).write(0xfee0_00b0, &0u32.to_le_bytes());
            cpu.poll_vm_clock().unwrap();
            assert_eq!(
                controllers[id].lock().unwrap().get_pending_vector(),
                None,
                "expiry transfers only once after each restore"
            );
        }
        drop(cpus);
        drop(vm);
    }
}

#[test]
fn deadline_expiry_authorizes_a_halted_cpus_next_native_entry() {
    use rax::devices::bus::MmioDevice;
    use rax::devices::lapic::{LapicDevice, LocalApic};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    LapicDevice::new(lapic.clone()).write(0xfee0_0320, &0x40051u32.to_le_bytes());
    cpu.attach_local_apic(lapic.clone());
    deadline_msr(cpu.as_mut(), 0, Some(1));
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.registers.insert(1, 0x202);
        native.vmcs.insert(0x4824, 0);
        native.exits = [12].into_iter().collect();
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    assert!(cpu.get_emulator_state().unwrap().halted);
    cpu.poll_vm_clock().unwrap();
    let vector = lapic.lock().unwrap().get_pending_vector().unwrap();
    assert_eq!(vector, 0x51);
    assert!(cpu.inject_interrupt(vector).unwrap());
    assert!(!cpu.get_emulator_state().unwrap().halted);
    let entries = {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        // SDM086 Vol.3C28.7.2: a vectoring VM entry starts in the active state.
        // Merely accepting the request need not change the activity field.
        assert_eq!(native.vmcs[&0x4826], 1);
        assert_eq!(native.vmcs[&0x4016], 0x8000_0051);
        native.exits = [0x8000_0021].into_iter().collect();
        native.deadlines.len()
    };
    assert!(matches!(
        cpu.run_host_slice(std::time::Duration::from_secs(1))
            .unwrap(),
        Some(VcpuExit::FailEntry {
            reason: 0x8000_0021
        })
    ));
    assert_eq!(SDK.lock().unwrap().cpus[&0].deadlines.len(), entries + 1);
}

#[test]
fn public_state_import_refreshes_native_control_read_shadows() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    // SDK-only run 41989606547 reaches the RAM marker with complete shadows;
    // native MSR bindings with initializer shadows retain failed-entry reason 33.
    // Repeated imports must replace the previous mode, including cleared bits.
    for (cr0, cr4, efer) in [
        (0x6000_0010, 0, 0),
        (0x8001_0033, 0x220, 0x500),
        (0x11, 0, 0),
        (0x8001_0033, 0x220, 0x500),
    ] {
        let mut public = cpu.get_state().unwrap();
        let CpuState::X86_64(state) = &mut public else {
            panic!("wrong architecture")
        };
        state.sregs.cr0 = cr0;
        state.sregs.cr4 = cr4;
        state.sregs.efer = efer;
        cpu.set_state(&public).unwrap();
        let sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values().next().unwrap();
        assert_eq!(native.vmcs[&0x6004], cr0, "stale CR0 read shadow");
        assert_eq!(native.vmcs[&0x6006], cr4, "stale CR4 read shadow");
    }
    drop(cpu);
    drop(vm);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vmx_vcpu_get_cap_write_vmcs(
    id: u32,
    field: u32,
    required: *mut u64,
    allowed: *mut u64,
) -> i32 {
    if required.is_null() || allowed.is_null() {
        return -1;
    }
    let must_one = match field {
        0x6000 => 0x6000_0020,
        0x6002 => 0x40,
        _ => return -1,
    };
    access(id, "mask-capability", |_| {
        // SAFETY: the SDK caller supplies two exclusive initialized u64 output
        // words. Null pointers reject above; neither pointer is retained.
        unsafe {
            required.write(must_one);
            allowed.write(u64::MAX);
        }
    })
}

#[test]
fn sdk_required_masks_are_initialized_before_profile_capture() {
    // The SDK bridge discovers this symbol with dlsym. Retain the executable's
    // mock, as the owner fixture already does for its late-bound clock APIs.
    std::hint::black_box(
        hv_vmx_vcpu_get_cap_write_vmcs as unsafe extern "C" fn(u32, u32, *mut u64, *mut u64) -> i32,
    );
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        native.vmcs.insert(0x440c, 1);
        native.exits.push_back(12);
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.values_mut().next().unwrap();
        // Native SDK run 41989606547 adds exactly these required mask bits at
        // entry; run 41992554080 then rejects the stale producer policy.
        *native.vmcs.entry(0x6000).or_default() |= 0x6000_0020;
        *native.vmcs.entry(0x6002).or_default() |= 0x40;
    }
    let boundary = vm.checkpoint_boundary().unwrap();
    let (_, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    assert!(context.is_some());
    drop(boundary);
    drop(cpu);
    drop(vm);
}

#[test]
fn missing_mask_constraints_destroy_the_unpublished_cpu() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for remaining in [1, 2] {
        let (vm, memory) = fixture();
        SDK.lock().unwrap().fault = Some(Fault {
            operation: "mask-capability",
            remaining,
            persistent: false,
        });
        assert!(
            vm.create_vcpu(0, Arc::new(memory.memory().clone()))
                .is_err()
        );
        assert!(SDK.lock().unwrap().cpus.is_empty());
        drop(vm);
    }
}

const SYSCALL: [u32; 4] = [0xc000_0081, 0xc000_0082, 0xc000_0083, 0xc000_0084];

#[test]
fn controller_attachment_wait_does_not_exclude_a_checkpoint_boundary() {
    use rax::devices::lapic::LocalApic;
    use std::sync::mpsc;
    use std::time::Duration;

    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let attached = lapic.clone();
    let controller = lapic.lock().unwrap();
    let (started, receive_started) = mpsc::channel();
    let (captured, receive_captured) = mpsc::channel();
    let (available, cpu) = thread::scope(|scope| {
        let attach = scope.spawn(move || {
            started.send(()).unwrap();
            cpu.attach_local_apic(attached);
            cpu
        });
        receive_started.recv().unwrap();
        // Allow the uncontended owner request to start while its model lock is
        // deliberately held. The bounded check below always releases that lock
        // and joins both workers before asserting, including under old behavior.
        thread::sleep(Duration::from_millis(50));
        let vm = vm.as_ref();
        let checkpoint = scope.spawn(move || {
            let boundary = vm.checkpoint_boundary().unwrap();
            captured.send(()).unwrap();
            drop(boundary);
        });
        let available = receive_captured
            .recv_timeout(Duration::from_secs(1))
            .is_ok();
        drop(controller);
        let cpu = attach.join().unwrap();
        checkpoint.join().unwrap();
        (available, cpu)
    });
    // A blocked attachment must not retain the native reader while capture
    // follows the controller -> native-writer lock order.
    assert!(
        available,
        "attachment held native exclusion while waiting for LAPIC"
    );
    assert!(cpu.get_state().is_ok());
    drop(cpu);
    drop(vm);
    assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
}
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

fn reserved_msr_accesses_fault_before_retirement_or_register_effects(reason: u32) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    // Intel SDM086 RDMSR/WRMSR #GP(0), corroborated by the independent
    // CPL0 KVM guest. The SDK model stops at the next failed entry so that
    // it retains the injection slot without simulating an exception handler.
    for msr in [0xffff_ffff, 0xffff_fffe, 0xdead_beef, 0x2000_0000] {
        instruction(cpu.as_mut(), msr, 0x8877_6655_4433_2211, reason);
        let native_bank = {
            let mut sdk = SDK.lock().unwrap();
            let native = sdk.cpus.get_mut(&0).unwrap();
            native.registers.insert(36, 1); // CR0.PE, CPL0.
            native.vmcs.insert(0x802, 8); // CS selector, RPL0.
            native.vmcs.insert(0x4016, 0);
            native.exits = [reason, 0x8000_0021].into_iter().collect();
            native.msrs.clone()
        };
        let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
        assert!(matches!(
            cpu.run_host_slice(std::time::Duration::from_secs(1))
                .unwrap(),
            Some(VcpuExit::FailEntry {
                reason: 0x8000_0021
            })
        ));
        let sdk = SDK.lock().unwrap();
        let native = &sdk.cpus[&0];
        assert_eq!(
            native.vmcs[&0x4016], 0x8000_0b0d,
            "MSR {msr:#x}, reason {reason}"
        );
        assert_eq!(native.vmcs[&0x4018], 0);
        assert_eq!(native.msrs, native_bank);
        drop(sdk);
        assert_eq!(
            rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            before
        );
    }
}

#[test]
fn reserved_msr_reads_fault_before_retirement_or_register_effects() {
    reserved_msr_accesses_fault_before_retirement_or_register_effects(31);
}

#[test]
fn reserved_msr_writes_fault_before_retirement_or_register_effects() {
    reserved_msr_accesses_fault_before_retirement_or_register_effects(32);
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
