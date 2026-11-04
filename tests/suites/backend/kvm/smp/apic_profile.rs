//! Native guest observation of VM-specific APIC feature dependencies.
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::vcpu::{CpuState, VcpuExit};
use std::sync::Arc;
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

fn assert_profile(irqchip: bool, configured: bool) {
    let backend = KvmBackend::new().unwrap();
    let deadline = backend
        .kvm()
        .check_extension(kvm_ioctls::Cap::TscDeadlineTimer);
    let supported = backend
        .kvm()
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    let async_page_faults = supported
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x4000_0001)
        .is_some_and(|entry| entry.eax & (1 << 4) != 0);
    let async_vmexits = supported
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x4000_0001)
        .is_some_and(|entry| entry.eax & (1 << 10) != 0);
    let async_interrupts = supported
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x4000_0001)
        .is_some_and(|entry| entry.eax & (1 << 14) != 0);
    let paravirtual_ipis = supported
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x4000_0001)
        .is_some_and(|entry| entry.eax & (1 << 11) != 0);
    let vm = backend.create_vm().unwrap();
    if configured {
        vm.configure_cpu_topology(1, 2 * 1024 * 1024).unwrap();
    }
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    if irqchip {
        native.create_irq_chip().unwrap();
    }
    native.set_tss_address(0xc0001000).unwrap();
    native.set_identity_map_address(0xc0000000).unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    // Real-mode 32-bit CPUID operands, store leaf1.ECX and KVM features.EAX.
    let code = [
        0x66, 0xb8, 1, 0, 0, 0, 0x66, 0x31, 0xc9, 0x0f, 0xa2, 0x66, 0x89, 0x0e, 0, 0x20, 0x66,
        0xb8, 1, 0, 0, 0x40, 0x66, 0x31, 0xc9, 0x0f, 0xa2, 0x66, 0xa3, 4, 0x20, 0xe6, 0x80, 0xf4,
    ];
    memory
        .memory()
        .write_slice(&code, GuestAddress(0x1000))
        .unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 2;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.ds.base = 0;
    state.sregs.ds.selector = 0;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let mut reached = false;
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
            assert!(
                matches!(exit, VcpuExit::IoOut { port: 0x80, .. }),
                "{exit:?}"
            );
            reached = true;
            break;
        }
    }
    assert!(reached, "guest did not reach its bounded result exit");
    let ecx: u32 = memory.memory().read_obj(GuestAddress(0x2000)).unwrap();
    let features: u32 = memory.memory().read_obj(GuestAddress(0x2004)).unwrap();
    println!(
        "native_apic_profile configured={configured} irqchip={irqchip} deadline_capability={deadline} leaf1_ecx={ecx:#x} kvm_features_eax={features:#x}"
    );
    assert_eq!(
        ecx & (1 << 24) != 0,
        irqchip && deadline,
        "TSC-deadline admission must match the native capability and LAPIC"
    );
    assert_eq!(
        features & (1 << 4) != 0,
        irqchip && async_page_faults,
        "asynchronous page-fault enable requires the kernel LAPIC"
    );
    assert_eq!(
        features & (1 << 10) != 0,
        irqchip && async_vmexits,
        "asynchronous page-fault VM exits require the kernel LAPIC"
    );
    assert_eq!(
        features & (1 << 14) != 0,
        irqchip && async_interrupts,
        "asynchronous page-fault interrupts require the kernel LAPIC"
    );
    assert_eq!(
        features & (1 << 11) != 0,
        irqchip && paravirtual_ipis,
        "paravirtual IPI delivery requires the kernel APIC map"
    );
    if !irqchip {
        assert_eq!(ecx & (1 << 21), 0, "x2APIC requires the kernel LAPIC");
        assert_eq!(
            features & (1 << 7),
            0,
            "PV unhalt requires the kernel LAPIC"
        );
        assert!(
            native.create_irq_chip().is_err(),
            "KVM rejects changing the native controller after CPU allocation"
        );
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn configured_cpu_without_lapic() {
    assert_profile(false, true);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn configured_cpu_with_lapic() {
    assert_profile(true, true);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn sdk_cpu_without_lapic() {
    assert_profile(false, false);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn sdk_cpu_with_lapic() {
    assert_profile(true, false);
}
