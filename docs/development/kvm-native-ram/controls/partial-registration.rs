use rax::backend::Backend;
use rax::backend::kvm::{KvmBackend, KvmVm};
use rax::vm::memory::GuestMemoryWrapper;
use std::sync::Arc;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[test]
fn a_failed_high_slot_keeps_the_successful_low_slot_backing_owned() {
    let backend = KvmBackend::new().unwrap();
    let occupied = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let memory = GuestMemoryWrapper::new(5 << 30).unwrap();
    let (empty, region) = memory
        .memory()
        .remove_region(GuestAddress(0), memory.actual_size())
        .unwrap();
    let witness = Arc::downgrade(&region);
    drop(region);
    drop(empty);
    assert_eq!(witness.strong_count(), 1);
    let descriptor = kvm_bindings::kvm_userspace_memory_region {
        slot: 7,
        guest_phys_addr: 0x1_0000_0000,
        memory_size: 4096,
        userspace_addr: occupied.get_host_address(GuestAddress(0)).unwrap() as u64,
        flags: 0,
    };
    // SAFETY: occupied is a page-aligned, readable/writable live mmap. This
    // fresh VM has no CPUs, so entry and concurrent slot changes are excluded.
    // The VM is explicitly destroyed before occupied is released below.
    unsafe {
        native.vm_fd().set_user_memory_region(descriptor).unwrap();
    }
    let error = native.register_memory(&memory).unwrap_err();
    assert!(matches!(error, rax::error::Error::Kvm(error) if error.errno() == libc::EEXIST));
    // Prove this was a real partial registration: the first low slot is live
    // even though the overlapping high slot failed. Do not execute a CPU.
    let probe = kvm_bindings::kvm_userspace_memory_region {
        slot: 8,
        guest_phys_addr: 0,
        ..descriptor
    };
    // SAFETY: same retained backing, stopped VM and explicit destruction order.
    let prefix = unsafe { native.vm_fd().set_user_memory_region(probe) };
    assert_eq!(prefix.unwrap_err().errno(), libc::EEXIST);
    let retained = witness.strong_count();
    println!("region owners after actual partial registration failure: {retained}");
    // Close every native slot before releasing either original backing, even
    // when testing the defective version. No stale mapping is ever executed.
    drop(vm);
    assert_eq!(witness.strong_count(), 1);
    drop(memory);
    assert!(witness.upgrade().is_none());
    assert!(
        retained >= 2,
        "successful native prefix lost its backing owner"
    );
}
