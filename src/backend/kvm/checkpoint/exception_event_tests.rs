use super::*;
use kvm_bindings::{
    KVM_CAP_X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_UNKNOWN, KVM_VCPUEVENT_VALID_PAYLOAD,
    KVM_VCPUEVENT_VALID_TRIPLE_FAULT, kvm_enable_cap, kvm_vcpu_events,
};

fn install_handler(memory: &GuestMemoryWrapper, cpus: &mut [Box<dyn VCpu>]) {
    const GP_VECTOR: u64 = 13;
    let ram = memory.memory();
    ram.write_slice(&[0x00, 0x20, 0x00, 0x00], GuestAddress(GP_VECTOR * 4))
        .unwrap();
    // PUSH AX; MOV AL,0x95; OUT 0xe9,AL; POP AX; IRET.
    ram.write_slice(
        &[0x50, 0xb0, 0x95, 0xe6, 0xe9, 0x58, 0xcf],
        GuestAddress(0x2000),
    )
    .unwrap();
    for (id, cpu) in cpus.iter_mut().enumerate() {
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 0x3ff;
        state.regs.rsp = 0x8000 + id as u64 * 0x1000;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
    }
}

#[test]
#[ignore = "requires Linux x86-64 /dev/kvm"]
fn pending_and_injected_gp_survive_source_free_native_restore() {
    for count in [1, 2, 4] {
        for pending in [false, true] {
            let (source, memory, mut cpus) = graph(count, false);
            install_handler(&memory, &mut cpus);
            let boundary = source.checkpoint_boundary().unwrap();
            let source_vm = native(&*source);
            let handles = source_vm.checkpoint_cpu_handles(&boundary).unwrap();
            for core in lock_cpus(source_vm, &handles).unwrap() {
                let mut events = core.vcpu_fd.get_vcpu_events().unwrap();
                assert_ne!(events.flags & KVM_VCPUEVENT_VALID_PAYLOAD, 0);
                events.exception.nr = 13;
                events.exception.pending = u8::from(pending);
                events.exception.injected = u8::from(!pending);
                core.vcpu_fd.set_vcpu_events(&events).unwrap();
            }
            let saved = source_vm.capture_native_banks(&boundary).unwrap();
            let bytes = crate::codec::serialize(&saved).unwrap();
            drop(handles);
            drop(boundary);
            drop(cpus);
            drop(source);
            drop(memory);

            let image: Image = crate::codec::deserialize_strict(&bytes).unwrap();
            let (target, memory, mut cpus) = graph(count, false);
            install_handler(&memory, &mut cpus);
            let boundary = target.checkpoint_boundary().unwrap();
            let target_vm = native(&*target);
            image.restore_stored(target_vm, &boundary).unwrap();
            let handles = target_vm.checkpoint_cpu_handles(&boundary).unwrap();
            for core in lock_cpus(target_vm, &handles).unwrap() {
                let events = core.vcpu_fd.get_vcpu_events().unwrap();
                assert_eq!(events.exception.nr, 13);
                assert_eq!(events.exception.pending, u8::from(pending));
                assert_eq!(events.exception.injected, u8::from(!pending));
            }
            drop(boundary);
            for (id, cpu) in cpus.iter_mut().enumerate() {
                assert!(matches!(
                    exit(&mut **cpu),
                    VcpuExit::IoOut { port: 0xe9, data } if data == [0x95]
                ));
                cpu.complete_io_out().unwrap();
                assert!(matches!(
                    exit(&mut **cpu),
                    VcpuExit::IoOut { port: 0xe9, data } if data == [0x21 + id as u8]
                ));
                cpu.complete_io_out().unwrap();
                assert!(matches!(exit(&mut **cpu), VcpuExit::Hlt));
            }
        }
    }
}

#[test]
#[ignore = "requires Linux x86-64 /dev/kvm"]
fn pending_page_fault_retains_payload_and_rejects_ambiguous_cpu_records() {
    let (vm, _memory, mut cpus) = graph(1, false);
    let mut cpu = cpus.pop().unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.sregs.cr2 = 0x1234;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let owner = native(&*vm);
    let boundary = vm.checkpoint_boundary().unwrap();
    let idle = owner.capture_native_banks(&boundary).unwrap();
    let handles = owner.checkpoint_cpu_handles(&boundary).unwrap();
    {
        let cores = lock_cpus(owner, &handles).unwrap();
        let mut events = cores[0].vcpu_fd.get_vcpu_events().unwrap();
        assert_ne!(events.flags & KVM_VCPUEVENT_VALID_PAYLOAD, 0);
        events.exception.nr = 14;
        events.exception.pending = 1;
        events.exception.has_error_code = 1;
        events.exception_has_payload = 1;
        events.exception_payload = 0xfeed_a000;
        cores[0].vcpu_fd.set_vcpu_events(&events).unwrap();
    }
    let pending = owner.capture_native_banks(&boundary).unwrap();
    assert_ne!(stored_cpu_banks(&pending), stored_cpu_banks(&idle));
    let legacy = |image: &Image, version: u16| {
        let mut json = serde_json::to_value(image).unwrap();
        let cpu = &mut json["cpus"][0];
        cpu["version"] = version.into();
        let flags = &mut cpu["events"]["bytes"][std::mem::offset_of!(kvm_vcpu_events, flags)];
        let omitted = if version == 2 {
            KVM_VCPUEVENT_VALID_PAYLOAD | KVM_VCPUEVENT_VALID_TRIPLE_FAULT
        } else {
            KVM_VCPUEVENT_VALID_TRIPLE_FAULT
        };
        *flags = (flags.as_u64().unwrap() & !u64::from(omitted)).into();
        serde_json::from_value::<Image>(json).unwrap()
    };
    for version in [2, 3, 4] {
        for image in [&idle, &pending] {
            assert!(
                legacy(image, version)
                    .restore_stored(owner, &boundary)
                    .is_err()
            );
        }
    }
    assert_eq!(
        stored_cpu_banks(&owner.capture_native_banks(&boundary).unwrap()),
        stored_cpu_banks(&pending)
    );
    idle.restore_stored(owner, &boundary).unwrap();
    pending.restore_stored(owner, &boundary).unwrap();
    {
        let cores = lock_cpus(owner, &handles).unwrap();
        let events = cores[0].vcpu_fd.get_vcpu_events().unwrap();
        assert_eq!(events.exception.pending, 1);
        assert_eq!(events.exception.injected, 0);
        assert_eq!(events.exception_has_payload, 1);
        assert_eq!(events.exception_payload, 0xfeed_a000);
        assert_eq!(cores[0].vcpu_fd.get_sregs().unwrap().cr2, 0x1234);
    }
    drop(boundary);
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.sregs.cr2, 0x1234);
    state.regs.rbx ^= 1;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let cores = lock_cpus(owner, &handles).unwrap();
    let events = cores[0].vcpu_fd.get_vcpu_events().unwrap();
    assert_eq!(events.exception.pending, 1);
    assert_eq!(events.exception_payload, 0xfeed_a000);
    assert_eq!(cores[0].vcpu_fd.get_sregs().unwrap().cr2, 0x1234);
    drop(cores);
    drop(boundary);
}

#[test]
#[ignore = "requires Linux x86-64 /dev/kvm"]
fn pending_triple_fault_shuts_down_source_and_restored_cpus_without_retirement() {
    const UNKNOWN_MSR: u32 = 0xdead_beef;
    const RDMSR: u64 = 0x1006;
    // MOV ECX,0xdeadbeef; RDMSR; OUT 0xe9,AL; HLT.
    const CODE: [u8; 11] = [
        0x66, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0x0f, 0x32, 0xe6, 0xe9, 0xf4,
    ];
    for count in [1, 2, 4] {
        let (source, memory, mut cpus) = graph(count, false);
        memory
            .memory()
            .write_slice(&CODE, GuestAddress(0x1000))
            .unwrap();
        let source_vm = native(&*source);
        let boundary = source.checkpoint_boundary().unwrap();
        source_vm
            .memory
            .vm_fd
            .enable_cap(&kvm_enable_cap {
                cap: KVM_CAP_X86_USER_SPACE_MSR,
                args: [u64::from(KVM_MSR_EXIT_REASON_UNKNOWN), 0, 0, 0],
                ..Default::default()
            })
            .unwrap();
        let handles = source_vm.checkpoint_cpu_handles(&boundary).unwrap();
        for mut core in lock_cpus(source_vm, &handles).unwrap() {
            let kvm_ioctls::VcpuExit::X86Rdmsr(read) = core.vcpu_fd.run().unwrap() else {
                panic!("the test MSR read must exit before queuing the double fault");
            };
            assert_eq!(read.index, UNKNOWN_MSR);
            *read.error = 1;
            let before = core.vcpu_fd.get_regs().unwrap();
            assert_eq!(before.rip, RDMSR);
            let mut events = core.vcpu_fd.get_vcpu_events().unwrap();
            assert_ne!(events.flags & KVM_VCPUEVENT_VALID_TRIPLE_FAULT, 0);
            assert_eq!(events.triple_fault.pending, 0);
            events.exception.nr = 8;
            events.exception.pending = 1;
            events.exception.has_error_code = 1;
            events.exception.error_code = 0;
            core.vcpu_fd.set_vcpu_events(&events).unwrap();
            // Complete only the failing RDMSR. KVM queues #GP during #DF,
            // leaving a separate triple-fault request for the next entry.
            core.vcpu_fd.set_kvm_immediate_exit(1);
            let result = core.vcpu_fd.run().map(|_| ());
            core.vcpu_fd.set_kvm_immediate_exit(0);
            assert_eq!(result.unwrap_err().errno(), libc::EINTR);
            assert_eq!(core.vcpu_fd.get_regs().unwrap(), before);
            assert_eq!(
                core.vcpu_fd.get_vcpu_events().unwrap().triple_fault.pending,
                1
            );
        }
        let captured = source_vm.capture_native_banks(&boundary).unwrap();
        let bytes = crate::codec::serialize(&captured).unwrap();
        drop(captured);
        drop(handles);
        drop(boundary);
        for cpu in &mut cpus {
            assert!(matches!(exit(&mut **cpu), VcpuExit::Shutdown));
        }
        drop(cpus);
        drop(source);
        drop(memory);

        let (target, memory, mut cpus) = graph(count, false);
        memory
            .memory()
            .write_slice(&CODE, GuestAddress(0x1000))
            .unwrap();
        let image: Image = crate::codec::deserialize_strict(&bytes).unwrap();
        let target_vm = native(&*target);
        let boundary = target.checkpoint_boundary().unwrap();
        image.restore_stored(target_vm, &boundary).unwrap();
        let handles = target_vm.checkpoint_cpu_handles(&boundary).unwrap();
        for core in lock_cpus(target_vm, &handles).unwrap() {
            let events = core.vcpu_fd.get_vcpu_events().unwrap();
            assert_ne!(events.flags & KVM_VCPUEVENT_VALID_TRIPLE_FAULT, 0);
            assert_eq!(events.triple_fault.pending, 1);
            assert_eq!(core.vcpu_fd.get_regs().unwrap().rip, RDMSR);
        }
        drop(boundary);
        for cpu in &mut cpus {
            assert!(matches!(exit(&mut **cpu), VcpuExit::Shutdown));
        }
        let boundary = target.checkpoint_boundary().unwrap();
        for core in lock_cpus(target_vm, &handles).unwrap() {
            assert_eq!(core.vcpu_fd.get_regs().unwrap().rip, RDMSR);
            assert_eq!(
                core.vcpu_fd.get_vcpu_events().unwrap().triple_fault.pending,
                0
            );
        }
    }
}
