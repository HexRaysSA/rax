//! Raw native handle lifecycle, checked before any guest memory access.
use super::*;

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn raw_fd_retains_registered_ram_after_public_vm_handles_drop() {
    in_child(
        "raw_owner::raw_fd_retains_registered_ram_after_public_vm_handles_drop",
        || {
            let backend = KvmBackend::new().unwrap();
            let vm = backend.create_vm().unwrap();
            let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
            let region = memory
                .memory()
                .remove_region(GuestAddress(0), memory.actual_size())
                .unwrap()
                .1;
            let backing = Arc::downgrade(&region);
            drop(region);
            memory
                .memory()
                .write_slice(&[0xa0, 0x00, 0x20, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
                .unwrap();
            memory
                .memory()
                .write_obj(0x5au8, GuestAddress(0x2000))
                .unwrap();
            let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
            native.register_memory(&memory).unwrap();
            let mut cpu = native.create_vcpu_fd(0).unwrap();
            let _diagnostic = format!("{cpu:?}");
            let mut special = cpu.get_sregs().unwrap();
            special.cs.base = 0;
            special.cs.selector = 0;
            cpu.set_sregs(&special).unwrap();
            cpu.set_regs(&kvm_bindings::kvm_regs {
                rip: 0x1000,
                rflags: 2,
                ..Default::default()
            })
            .unwrap();
            drop(memory);
            drop(vm);
            drop(backend);
            // The baseline fails here. It never enters a guest with released RAM.
            assert!(
                backing.upgrade().is_some(),
                "raw native CPU lost its registered RAM owner"
            );
            match cpu.run().unwrap() {
                kvm_ioctls::VcpuExit::IoOut(0xe9, data) => assert_eq!(data, [0x5a]),
                exit => panic!("unexpected raw native guest exit {exit:?}"),
            }
            assert!(matches!(cpu.run().unwrap(), kvm_ioctls::VcpuExit::Hlt));
            drop(cpu);
            assert!(
                backing.upgrade().is_none(),
                "native backing owner leaked after CPU destruction"
            );
        },
    );
}
