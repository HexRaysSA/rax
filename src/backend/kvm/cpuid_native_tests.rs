use super::*;
use vm_memory::GuestAddress;

fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap())
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn topology_rejections_do_not_consume_cpu_ids_or_change_the_configured_count() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    assert!(vm.configure_cpu_topology(0, 4096).is_err());
    vm.configure_cpu_topology(4, 4096).unwrap();
    assert!(vm.configure_cpu_topology(2, 4096).is_err());
    assert!(vm.create_vcpu(4, memory()).is_err());
    // The rejected managed ID never reached KVM_CREATE_VCPU. The explicit
    // native SDK may still claim that ID with its own CPU configuration.
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let raw = native.create_vcpu_fd(4).unwrap();
    let managed = vm.create_vcpu(3, memory()).unwrap();
    assert_eq!(native.profile.lock().unwrap().count, Some(4));
    assert!(vm.configure_cpu_topology(4, 4096).is_err());
    drop((raw, managed));
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn unconfigured_managed_sdk_retains_native_ids_and_closes_late_configuration() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let cpus: Vec<_> = [0, 1, 7]
        .into_iter()
        .map(|id| vm.create_vcpu(id, memory()).unwrap())
        .collect();
    assert!(vm.configure_cpu_topology(8, 4096).is_err());
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    assert_eq!(native.profile.lock().unwrap().count, None);
    assert!(native.profile.lock().unwrap().created);
    drop(cpus);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn explicit_native_sdk_cpu_creation_also_closes_topology_configuration() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let raw = native.create_vcpu_fd(7).unwrap();
    assert!(vm.configure_cpu_topology(8, 4096).is_err());
    let profile = native.profile.lock().unwrap();
    assert!(profile.created);
    assert_eq!(profile.count, None);
    drop(profile);
    drop(raw);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn oversized_profile_rejects_before_native_allocation_and_topology_binding() {
    let kvm = Kvm::new().unwrap();
    let vm_fd = kvm.create_vm().unwrap();
    // This valid maximum-sized FAM cannot admit the required additional
    // topology records. Admission must reject before KVM_CREATE_VCPU,
    // without inventing a mocked CPU or ioctl result.
    let base = kvm_bindings::kvm_cpuid_entry2 {
        function: 0,
        eax: 0xf,
        ebx: 0x756e6547,
        edx: 0x49656e69,
        ecx: 0x6c65746e,
        ..Default::default()
    };
    let entries = vec![base; kvm_bindings::KVM_MAX_CPUID_ENTRIES];
    let vm = KvmVm {
        memory: Arc::new(MemoryOwner {
            vm_fd,
            checkpoint_kvm: Kvm::new().unwrap(),
            registered: Mutex::new(Vec::new()),
            irqchip_created: AtomicBool::new(false),
            irq_lines: Mutex::new(irq::Lines::default()),
            external_vm_access: AtomicBool::new(false),
            powered_off: AtomicBool::new(false),
            exclusion: RwLock::new(()),
            waiting_writers: Mutex::new(0),
            entry_ready: Condvar::new(),
            poisoned: AtomicBool::new(false),
            managed_cpus: Mutex::new(BTreeMap::new()),
            sdk_cpus: AtomicUsize::new(0),
            resume_clock: Mutex::new(None),
        }),
        kvm,
        cpuid: kvm_bindings::CpuId::from_entries(&entries).unwrap(),
        profile: Mutex::new(cpuid::Configuration::default()),
    };
    vm.configure_cpu_topology(1, 4096).unwrap();
    assert!(vm.create_vcpu(0, memory()).is_err());
    assert_eq!(vm.profile.lock().unwrap().count, Some(1));
    assert!(!vm.profile.lock().unwrap().created);
    assert!(vm.configure_cpu_topology(2, 4096).is_err());
    let raw = vm.create_vcpu_fd(0).unwrap();
    assert_eq!(vm.profile.lock().unwrap().count, Some(1));
    assert!(vm.profile.lock().unwrap().created);
    drop(raw);
}
