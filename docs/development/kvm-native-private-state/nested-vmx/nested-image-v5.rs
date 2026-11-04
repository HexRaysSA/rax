pub mod error {
    pub use rax::error::{Error, Result};
}
#[path = "nested.rs"]
mod nested;
use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::memory::GuestMemoryWrapper;
use std::os::fd::AsRawFd;
use vm_memory::{Bytes, GuestAddress, GuestMemory};
unsafe extern "C" {
    fn enter_vmx_for_rust(kvm: i32, cpu: i32, ram: *mut u8) -> i32;
    fn setup_vmx_for_rust(kvm: i32, cpu: i32, ram: *mut u8);
}
fn main() {
    let output = std::path::PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("explicit fresh artifact directory"),
    );
    assert!(output.is_dir());
    let (image, regs, sregs, events, mp, ram, capacity) = {
        let backend = KvmBackend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
        let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
        native.register_memory(&memory).unwrap();
        let cpu = native.create_vcpu_fd(0).unwrap();
        let address = memory.memory().get_host_address(GuestAddress(0)).unwrap();
        // SAFETY: the synchronous helper exclusively operates this stopped,
        // fully owned CPU and its private low RAM. No native-run references or
        // concurrent writers exist; borrowed FDs and RAM remain owned here.
        // Its temporary run mapping is unmapped before return, with no unwind.
        assert_eq!(
            unsafe { enter_vmx_for_rust(native.kvm().as_raw_fd(), cpu.as_raw_fd(), address) },
            0
        );
        let capacity = native
            .kvm()
            .check_extension_int(kvm_ioctls::Cap::NestedState) as usize;
        let image = nested::Image::capture(&cpu, capacity).unwrap().unwrap();
        assert_eq!(image.bytes().len(), 4224);
        assert!(!output.join("active-vmcs.bin").exists());
        std::fs::write(output.join("active-vmcs.bin"), image.bytes()).unwrap();
        let mut ram = vec![0; 2 * 1024 * 1024];
        memory
            .memory()
            .read_slice(&mut ram, GuestAddress(0))
            .unwrap();
        let wire = rax::codec::serialize(&image).unwrap();
        let decoded: nested::Image = rax::codec::deserialize(&wire).unwrap();
        assert_eq!(decoded, image);
        (
            decoded,
            cpu.get_regs().unwrap(),
            cpu.get_sregs().unwrap(),
            cpu.get_vcpu_events().unwrap(),
            cpu.get_mp_state().unwrap(),
            ram,
            capacity,
        )
    }; // Source CPU, VM, memory mappings and all backing owners are destroyed.
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    native.register_memory(&memory).unwrap();
    let mut cpu = native.create_vcpu_fd(0).unwrap();
    let address = memory.memory().get_host_address(GuestAddress(0)).unwrap();
    // SAFETY: this fresh CPU is stopped and exclusively owned. The helper
    // configures controls and private RAM without guest entry or VMXON; it
    // retains no pointer/FD and no Rust memory or run-buffer references are live.
    unsafe { setup_vmx_for_rust(native.kvm().as_raw_fd(), cpu.as_raw_fd(), address) };
    memory.memory().write_slice(&ram, GuestAddress(0)).unwrap();
    cpu.set_sregs(&sregs).unwrap();
    cpu.set_regs(&regs).unwrap();
    cpu.set_vcpu_events(&events).unwrap();
    cpu.set_mp_state(mp).unwrap();
    let before = nested::Image::capture(&cpu, capacity).unwrap().unwrap();
    assert!(!output.join("inactive.bin").exists());
    std::fs::write(output.join("inactive.bin"), before.bytes()).unwrap();
    let mut invalid = vec![vec![], vec![0; 127]];
    for (format, declared, length) in [(2, 128, 128), (0, 0, 128), (0, 129, 128), (0, 8321, 8321)] {
        let mut bytes = vec![0; length];
        bytes[2..4].copy_from_slice(&(format as u16).to_le_bytes());
        bytes[4..8].copy_from_slice(&(declared as u32).to_le_bytes());
        invalid.push(bytes);
    }
    for bytes in &invalid {
        assert!(nested::Image::from_bytes(bytes.clone(), capacity).is_err());
        // Deserialize through the actual file codec surface, bypassing the
        // constructor, to verify restore performs its own envelope preflight.
        let rejected: nested::Image =
            serde_json::from_value(serde_json::json!({"bytes":bytes})).unwrap();
        assert!(rejected.restore(&cpu, capacity).is_err());
        assert_eq!(
            nested::Image::capture(&cpu, capacity).unwrap().unwrap(),
            before
        );
        assert_eq!(cpu.get_regs().unwrap(), regs);
    }
    assert!(image.restore(&cpu, 0).is_err());
    image.restore(&cpu, capacity).unwrap();
    assert_eq!(
        nested::Image::capture(&cpu, capacity).unwrap().unwrap(),
        image
    );
    before.restore(&cpu, capacity).unwrap();
    assert_eq!(
        nested::Image::capture(&cpu, capacity).unwrap().unwrap(),
        before
    );
    image.restore(&cpu, capacity).unwrap();
    assert_eq!(
        nested::Image::capture(&cpu, capacity).unwrap().unwrap(),
        image
    );

    match cpu.run().unwrap() {
        kvm_ioctls::VcpuExit::IoOut(0x81, bytes) => assert_eq!(bytes, &[2]),
        other => panic!("{other:?}"),
    }
    assert_eq!(cpu.get_regs().unwrap().rax & 0x41, 0);
    assert_eq!(
        memory
            .memory()
            .read_obj::<u64>(GuestAddress(0x6010))
            .unwrap(),
        0x9000
    );
    assert_eq!(
        memory
            .memory()
            .read_obj::<u64>(GuestAddress(0x6020))
            .unwrap(),
        0x4142434445464748
    );
    cpu.set_kvm_immediate_exit(1);
    assert_eq!(cpu.run().unwrap_err().errno(), libc::EINTR);
    cpu.set_kvm_immediate_exit(0);
    assert!(matches!(cpu.run().unwrap(), kvm_ioctls::VcpuExit::Hlt));
    println!(
        "{}",
        serde_json::json!({"source_free_private_restore":true,"record_bytes":image.bytes().len(),"capacity":capacity,"invalid_envelopes_rejected_before_mutation":invalid.len(),"missing_target_capacity_rejected":true,"actual_codec_roundtrip":true,"inactive_record_clears_active_nested_state":true})
    );
}
