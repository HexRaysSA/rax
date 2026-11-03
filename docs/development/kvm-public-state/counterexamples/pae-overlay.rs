use rax::backend::{Backend, kvm::{KvmBackend, KvmVm}};
use rax::vm::{memory::GuestMemoryWrapper, vcpu::CpuState};
use std::sync::Arc;

fn special(fd: i32) -> kvm_bindings::kvm_sregs2 {
    let mut value = kvm_bindings::kvm_sregs2::default();
    assert_eq!(unsafe { libc::ioctl(fd, libc::_IOR::<kvm_bindings::kvm_sregs2>(kvm_bindings::KVMIO, 0xcc), &mut value) }, 0);
    value
}

fn main() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any().downcast_ref::<KvmVm>().unwrap().register_memory(&memory).unwrap();
    let mut cpu = vm.create_vcpu(0, Arc::new(memory.memory().clone())).unwrap();
    // The production public trait does not expose a downcast. Locate this
    // process's sole live vCPU FD only to seed/observe independent kernel state.
    let fds: Vec<_> = std::fs::read_dir("/proc/self/fd").unwrap().filter_map(|entry| {
        let entry = entry.unwrap();
        let target = std::fs::read_link(entry.path()).ok()?;
        target.to_string_lossy().contains("kvm-vcpu").then(|| entry.file_name().to_string_lossy().parse::<i32>().unwrap())
    }).collect();
    assert_eq!(fds.len(), 1, "{fds:?}");
    let fd = fds[0];
    let mut original = special(fd);
    original.cr0 |= (1 << 31) | 1;
    original.cr4 |= 1 << 5;
    original.cr3 = 0x2000;
    original.flags = u64::from(kvm_bindings::KVM_SREGS2_FLAGS_PDPTRS_VALID);
    original.pdptrs = [0x3001, 0, 0, 0];
    assert_eq!(unsafe { libc::ioctl(fd, libc::_IOW::<kvm_bindings::kvm_sregs2>(kvm_bindings::KVMIO, 0xcd), &original) }, 0);
    let original = special(fd);
    assert_eq!(original.pdptrs[0], 0x3001);
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else { panic!() };
    state.sregs.cr8 = 1;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let after = special(fd);
    println!("before_pdptrs={:?} after_pdptrs={:?} cr8={}", original.pdptrs, after.pdptrs, after.cr8);
    assert_eq!(after.cr8, 1);
    assert_eq!(after.pdptrs, original.pdptrs, "public CR8 overlay changed cached PAE pointers");
}
