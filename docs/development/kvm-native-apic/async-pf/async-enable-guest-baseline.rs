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
        for flags in [1u8, 5] {
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
            // Observe CPUID, then enable ASYNC_PF with a real registered page.
            let code = [
                0x66, 0xb8, 1, 0, 0, 0x40, 0x0f, 0xa2, 0x66, 0xa3, 0, 0x20, 0x66, 0xb9, 2, 0x4d,
                0x56, 0x4b, 0x66, 0xb8, flags, 0x30, 0, 0, 0x66, 0x31, 0xd2, 0x0f, 0x30, 0xb0,
                0x5a, 0xe6, 0x80, 0xf4,
            ];
            memory
                .memory()
                .write_slice(&code, GuestAddress(0x1000))
                .unwrap();
            memory
                .memory()
                .write_slice(&[0xb0, 0xed, 0xe6, 0x81, 0xf4], GuestAddress(0x1100))
                .unwrap();
            // Real-mode #GP vector points to an independent result marker.
            memory
                .memory()
                .write_slice(&[0, 0x11, 0, 0], GuestAddress(13 * 4))
                .unwrap();
            let mut cpu = vm
                .create_vcpu(0, Arc::new(memory.memory().clone()))
                .unwrap();
            let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.rip = 0x1000;
            state.regs.rsp = 0x8000;
            state.regs.rflags = 2;
            state.sregs.cs.base = 0;
            state.sregs.cs.selector = 0;
            state.sregs.ds.base = 0;
            state.sregs.ds.selector = 0;
            state.sregs.ss.base = 0;
            state.sregs.ss.selector = 0;
            state.sregs.idt.base = 0;
            state.sregs.idt.limit = 0x3ff;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
            let mut observed = None;
            for _ in 0..100 {
                if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
                    let VcpuExit::IoOut { port, .. } = exit else {
                        panic!("{exit:?}")
                    };
                    assert!(matches!(port, 0x80 | 0x81));
                    observed = Some(port);
                    break;
                }
            }
            let port = observed.expect("guest did not reach its bounded success/#GP marker");
            let features: u32 = memory.memory().read_obj(GuestAddress(0x2000)).unwrap();
            assert_ne!(features & (1 << 4), 0);
            assert_ne!(features & (1 << 10), 0);
            assert_eq!(port, if irqchip { 0x80 } else { 0x81 });
            println!(
                "{}",
                serde_json::json!({
                    "irqchip":irqchip,"enable_flags":flags,"guest_features":features,
                    "async_pf_advertised":features&(1<<4)!=0,"async_pf_vmexit_advertised":features&(1<<10)!=0,
                    "observed_port":port,"general_protection_handler":port==0x81,
                    "scope":"Actual managed guest CPUID and WRMSR_KVM_ASYNC_PF_EN, with a distinct real-mode #GP handler. Full previously qualified interrupt-v3 product."
                })
            );
        }
    }
}
