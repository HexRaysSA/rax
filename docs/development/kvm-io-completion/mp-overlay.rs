//! Independent kernel MP-state observation around real managed RAX overlays.
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::{memory::GuestMemoryWrapper, vcpu::CpuState};
use std::sync::Arc;
fn mp(fd: i32) -> u32 {
    let mut value = kvm_bindings::kvm_mp_state::default();
    // SAFETY: sole process-owned stopped CPU FD; exclusive initialized UAPI
    // output lives for the synchronous kernel copy and no guest entry occurs.
    assert_eq!(
        unsafe {
            libc::ioctl(
                fd,
                libc::_IOR::<kvm_bindings::kvm_mp_state>(kvm_bindings::KVMIO, 0x98),
                &mut value,
            )
        },
        0
    );
    value.mp_state
}
fn main() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    native.create_irq_chip().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let fds = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            std::fs::read_link(entry.path())
                .ok()?
                .to_string_lossy()
                .contains("kvm-vcpu")
                .then(|| entry.file_name().to_string_lossy().parse::<i32>().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(fds.len(), 1);
    let fd = fds[0];
    for wanted in [
        kvm_bindings::KVM_MP_STATE_RUNNABLE,
        kvm_bindings::KVM_MP_STATE_UNINITIALIZED,
        kvm_bindings::KVM_MP_STATE_INIT_RECEIVED,
        kvm_bindings::KVM_MP_STATE_HALTED,
    ] {
        let value = kvm_bindings::kvm_mp_state { mp_state: wanted };
        // SAFETY: this process owns the sole stopped CPU, with no concurrent
        // run or mutation. Initialized input is copied synchronously by KVM.
        assert_eq!(
            unsafe {
                libc::ioctl(
                    fd,
                    libc::_IOW::<kvm_bindings::kvm_mp_state>(kvm_bindings::KVMIO, 0x99),
                    &value,
                )
            },
            0
        );
        assert_eq!(mp(fd), wanted);
        let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
            panic!()
        };
        let before = desired.regs.clone();
        desired.sregs.cr8 = (desired.sregs.cr8 + 1) & 15;
        let expected = desired.sregs.cr8;
        cpu.set_state(&CpuState::X86_64(desired)).unwrap();
        let after = mp(fd);
        println!("wanted_mp={wanted} actual_mp={after}");
        assert_eq!(after, wanted, "public overlay changed native MP state");
        let CpuState::X86_64(observed) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            serde_json::to_vec(&observed.regs).unwrap(),
            serde_json::to_vec(&before).unwrap()
        );
        assert_eq!(observed.sregs.cr8, expected);
    }
}
