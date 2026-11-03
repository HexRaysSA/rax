//! A public observation must not consume INIT during native input completion.
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::{
    memory::{
        GuestMemoryWrapper,
        vm::{Bytes, GuestAddress},
    },
    vcpu::{CpuState, VCpu, VcpuExit},
};
use std::{sync::Arc, time::Duration};
fn regs(fd: i32) -> kvm_bindings::kvm_regs {
    let mut value = kvm_bindings::kvm_regs::default();
    // SAFETY: the caller retains the sole process-owned stopped CPU. This
    // initialized output is exclusively borrowed for the synchronous ioctl.
    assert_eq!(
        unsafe {
            libc::ioctl(
                fd,
                libc::_IOR::<kvm_bindings::kvm_regs>(kvm_bindings::KVMIO, 0x81),
                &mut value,
            )
        },
        0
    );
    value
}
fn native_mp(fd: i32) -> u32 {
    let mut value = kvm_bindings::kvm_mp_state::default();
    // SAFETY: the caller retains the sole stopped AP; exclusive initialized
    // output lives for the synchronous query, after native IO completion.
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
fn setup(cpu: &mut dyn VCpu, pc: u64, unreal: bool) {
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rip = pc;
    state.regs.rflags = 2;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.ds.base = 0;
    state.sregs.ds.selector = 0;
    if unreal {
        state.sregs.ds.limit = u32::MAX;
        state.sregs.ds.g = true;
    }
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
}
fn next(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..10 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
            return exit;
        }
    }
    panic!("fixture did not reach its bounded PIO exit");
}
fn main() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    native.create_irq_chip().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    memory
        .memory()
        .write_slice(&[0xe4, 0x80, 0xf4], GuestAddress(0x1000))
        .unwrap();
    let sender = [
        0xfa, 0x66, 0xbf, 0, 0, 0xe0, 0xfe, 0x67, 0x66, 0xc7, 0x87, 0xf0, 0, 0, 0, 0xff, 1, 0, 0,
        0x67, 0x66, 0xc7, 0x87, 0x10, 3, 0, 0, 0, 0, 0, 1, 0x67, 0x66, 0xc7, 0x87, 0, 3, 0, 0, 0,
        0x45, 0, 0, 0xe6, 0x80, 0xf4,
    ];
    memory
        .memory()
        .write_slice(&sender, GuestAddress(0x2000))
        .unwrap();
    let mut ap = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    let fds = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            std::fs::read_link(e.path())
                .ok()?
                .to_string_lossy()
                .contains("kvm-vcpu")
                .then(|| e.file_name().to_string_lossy().parse::<i32>().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(fds.len(), 1);
    let apfd = fds[0];
    setup(&mut *ap, 0x1000, false);
    let mp = kvm_bindings::kvm_mp_state {
        mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
    };
    // SAFETY: this process owns the sole stopped AP and no concurrent entry
    // occurs; initialized input remains live for the synchronous kernel copy.
    assert_eq!(
        unsafe {
            libc::ioctl(
                apfd,
                libc::_IOW::<kvm_bindings::kvm_mp_state>(kvm_bindings::KVMIO, 0x99),
                &mp,
            )
        },
        0
    );
    let mut bsp = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    setup(&mut *bsp, 0x2000, true);
    assert!(matches!(
        next(&mut *ap),
        VcpuExit::IoIn {
            port: 0x80,
            size: 1
        }
    ));
    assert!(matches!(
        next(&mut *bsp),
        VcpuExit::IoOut { port: 0x80, .. }
    ));
    bsp.complete_io_out().unwrap();
    let before = regs(apfd);
    let _public = ap.get_state().unwrap();
    let after = regs(apfd);
    println!(
        "public_observation_before_rip={:#x} after_rip={:#x}",
        before.rip, after.rip
    );
    assert_eq!(
        before, after,
        "public observation consumed pending INIT before owned input completion"
    );
    ap.complete_io_in(&[0x5a]);
    ap.io_completion_result().unwrap();
    for _ in 0..10 {
        assert!(
            ap.run_host_slice(Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        if native_mp(apfd) == kvm_bindings::KVM_MP_STATE_INIT_RECEIVED {
            println!("native_input_completed_then_init_wait=true");
            return;
        }
    }
    panic!("completed input did not reach native INIT wait");
}
