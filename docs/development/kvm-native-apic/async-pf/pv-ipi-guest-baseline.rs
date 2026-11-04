use rax::backend::{
    Backend,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::vcpu::{CpuState, VcpuExit};
use std::sync::Arc;
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};
fn main() {
    for irqchip in [false, true] {
        let backend = KvmBackend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        vm.configure_cpu_topology(1, 2 * 1024 * 1024).unwrap();
        let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
        if irqchip {
            native.create_irq_chip().unwrap();
        }
        native.set_tss_address(0xc0001000).unwrap();
        native.set_identity_map_address(0xc0000000).unwrap();
        let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
        native.register_memory(&memory).unwrap();
        let code = [
            0x66, 0xb8, 1, 0, 0, 0x40, 0x0f, 0xa2, 0x66, 0xa3, 0, 0x20, 0x66, 0xb8, 10, 0, 0, 0,
            0x66, 0xbb, 1, 0, 0, 0, 0x66, 0x31, 0xc9, 0x66, 0x31, 0xd2, 0x66, 0xbe, 0x40, 0x40, 0,
            0, 0x0f, 0x01, 0xc1, 0x66, 0xa3, 4, 0x20, 0xe6, 0x80, 0xf4,
        ];
        memory
            .memory()
            .write_slice(&code, GuestAddress(0x1000))
            .unwrap();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            panic!("x86 fixture")
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
        assert!(reached);
        let features: u32 = memory.memory().read_obj(GuestAddress(0x2000)).unwrap();
        let result: u32 = memory.memory().read_obj(GuestAddress(0x2004)).unwrap();
        println!(
            "{}",
            serde_json::json!({"irqchip":irqchip,"guest_features":features,"pv_send_ipi_advertised":features&(1<<11)!=0,"hypercall_result":result as i32})
        );
        assert!(features & (1 << 11) != 0);
        if irqchip {
            assert_eq!(result, 0);
        } else {
            assert_eq!(result as i32, -libc::EOPNOTSUPP);
        }
    }
}
