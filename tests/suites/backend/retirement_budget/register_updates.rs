//! Public register/PC updates retain the private state used by the next turn.
use rax::vm::vcpu::{CpuState, RetirementStop, VcpuExit};
use vm_memory::{Bytes, GuestAddress};

#[test]
fn software_aarch64_register_overlay_preserves_running_and_terminal_retirement() {
    for terminal in [false, true] {
        let (mut cpu, memory) = super::machine(1);
        let words = if terminal {
            [0x5280_0100u32, 0x72b0_8000, 0xd400_0002]
        } else {
            [0xd503_201f; 3]
        };
        for (index, word) in words.into_iter().enumerate() {
            memory
                .write_slice(
                    &word.to_le_bytes(),
                    GuestAddress(super::CODE + index as u64 * 4),
                )
                .unwrap();
        }
        memory
            .write_slice(
                &0xd281_75a2u32.to_le_bytes(), // MOV X2, #0xbad.
                GuestAddress(super::CODE + 12),
            )
            .unwrap();
        let first = cpu.run_retirement_budget(3).unwrap();
        assert_eq!(first.retired, 3);
        if terminal {
            assert!(matches!(
                first.stop,
                RetirementStop::Exit(VcpuExit::Shutdown)
            ));
        } else {
            assert!(matches!(first.stop, RetirementStop::BudgetExhausted));
        }
        let CpuState::Aarch64(mut public) = cpu.get_state().unwrap() else {
            panic!()
        };
        public.regs.x[5] = 0x1234;
        cpu.update_state(&CpuState::Aarch64(public)).unwrap();
        assert_eq!(cpu.instruction_count(), 3);
        let next = cpu.run_retirement_budget(1).unwrap();
        let CpuState::Aarch64(public) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            next.retired,
            u64::from(!terminal),
            "terminal={terminal}: stop={:?}, PC={:#x}, X2={:#x}",
            next.stop,
            public.regs.pc,
            public.regs.x[2],
        );
        assert_eq!(public.regs.x[5], 0x1234);
        if terminal {
            assert!(matches!(
                next.stop,
                RetirementStop::Exit(VcpuExit::Shutdown)
            ));
            assert_eq!(public.regs.pc, super::CODE + 12);
            assert_eq!(public.regs.x[2], 0);
        } else {
            assert!(matches!(next.stop, RetirementStop::BudgetExhausted));
            assert_eq!(public.regs.x[2], 0xbad);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "hvf"))]
mod native {
    use rax::backend::{Backend, hvf::HvfArm64Backend};
    use rax::vm::memory::GuestMemoryWrapper;
    use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress};

    const BASE: u64 = 0x4000_0000;
    const CODE: u64 = BASE + 0x1000;
    const NEXT: u64 = CODE + 0x40;
    const UART: u64 = 0x0900_0000;
    const SEED: u64 = 0x1122_3344_5566_7788;

    fn event(cpu: &mut dyn VCpu) -> VcpuExit {
        for _ in 0..100 {
            match cpu.run().unwrap() {
                VcpuExit::Hlt => (),
                exit => return exit,
            }
        }
        panic!("native CPU produced no architectural exit");
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and a hypervisor-entitled executable"]
    fn native_cpu_lifetime_preserves_peers_identity_reuse_and_retained_vm() {
        let memory = GuestMemoryWrapper::new(BASE + 0x4000).unwrap();
        let backend = HvfArm64Backend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        vm.as_any()
            .downcast_ref::<rax::backend::hvf::HvfArm64Vm>()
            .unwrap()
            .register_memory(&memory, BASE, 0x4000)
            .unwrap();
        vm.configure_cpu_topology(2, BASE + 0x4000).unwrap();
        for (address, words) in [
            (
                CODE,
                &[0xd280_0022u32, 0xf940_0020, 0xd280_0042, 0xf940_0020][..],
            ),
            (
                NEXT,
                &[
                    0xd297_dde3u32,
                    0xf940_0020,
                    0xd299_5fc3,
                    0x5280_0100,
                    0x72b0_8000,
                    0xd400_0002,
                ][..],
            ),
        ] {
            for (index, word) in words.iter().enumerate() {
                memory
                    .memory()
                    .write_slice(
                        &word.to_le_bytes(),
                        GuestAddress(address + index as u64 * 4),
                    )
                    .unwrap();
            }
        }
        let mut first = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let peer = vm
            .create_vcpu(1, Arc::new(memory.memory().clone()))
            .unwrap();
        assert!(
            vm.create_vcpu(0, Arc::new(memory.memory().clone()))
                .is_err()
        );
        let CpuState::Aarch64(mut public) = first.get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = CODE;
        public.regs.pstate = 0x3c5;
        public.regs.x[1] = UART;
        first.set_state(&CpuState::Aarch64(public)).unwrap();
        assert!(matches!(
            event(&mut *first),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8
            }
        ));
        drop(peer);
        let CpuState::Aarch64(public) = first.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(public.regs.x[2], 1);
        // A missing member prevents a complete checkpoint, but does not revoke
        // the surviving native CPU's ordinary register and execution APIs.
        {
            let boundary = vm.checkpoint_boundary().unwrap();
            assert!(vm.capture_checkpoint_vm_context(&boundary).is_err());
        }
        first.complete_io_in(&1u64.to_le_bytes());
        first.io_completion_result().unwrap();
        assert!(matches!(
            event(&mut *first),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8
            }
        ));
        let CpuState::Aarch64(public) = first.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(public.regs.x[2], 2);
        let mut peer = vm
            .create_vcpu(1, Arc::new(memory.memory().clone()))
            .unwrap();
        let CpuState::Aarch64(mut public) = peer.get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = NEXT;
        public.regs.pstate = 0x3c5;
        public.regs.x[1] = UART;
        peer.set_state(&CpuState::Aarch64(public)).unwrap();
        assert!(matches!(
            event(&mut *peer),
            VcpuExit::MmioRead {
                addr: UART,
                size: 8
            }
        ));
        {
            let boundary = vm.checkpoint_boundary().unwrap();
            assert!(
                vm.capture_checkpoint_vm_context(&boundary)
                    .unwrap()
                    .is_some()
            );
        }
        drop(first);
        drop(vm);
        drop(memory);
        // The final CPU retains the mapped backing and SDK VM even after the
        // caller drops both corresponding public owner objects.
        peer.complete_io_in(&2u64.to_le_bytes());
        peer.io_completion_result().unwrap();
        assert!(matches!(event(&mut *peer), VcpuExit::Shutdown));
        let CpuState::Aarch64(public) = peer.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(public.regs.x[3], 0xcafe);
        drop(peer);
        drop(backend.create_vm().unwrap());
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and a hypervisor-entitled executable"]
    fn native_pc_update_retains_pending_input_output_and_terminal_stop() {
        for phase in ["read", "write", "shutdown"] {
            let memory = GuestMemoryWrapper::new(BASE + 0x4000).unwrap();
            let backend = HvfArm64Backend::new().unwrap();
            let vm = backend.create_vm().unwrap();
            vm.as_any()
                .downcast_ref::<rax::backend::hvf::HvfArm64Vm>()
                .unwrap()
                .register_memory(&memory, BASE, 0x4000)
                .unwrap();
            vm.configure_cpu_topology(1, BASE + 0x4000).unwrap();
            let initial: &[u32] = match phase {
                "read" => &[0xf940_0020],  // LDR X0, [X1].
                "write" => &[0xf900_0020], // STR X0, [X1].
                _ => &[0x5280_0100, 0x72b0_8000, 0xd400_0002],
            };
            for (index, word) in initial.iter().enumerate() {
                memory
                    .memory()
                    .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
                    .unwrap();
            }
            for (index, word) in [
                0xd297_dde2u32, // MOV X2, #0xbeef.
                0x5280_0100,
                0x72b0_8000,
                0xd400_0002,
            ]
            .into_iter()
            .enumerate()
            {
                memory
                    .memory()
                    .write_slice(&word.to_le_bytes(), GuestAddress(NEXT + index as u64 * 4))
                    .unwrap();
            }
            let mut cpu = vm
                .create_vcpu(0, Arc::new(memory.memory().clone()))
                .unwrap();
            let CpuState::Aarch64(mut public) = cpu.get_state().unwrap() else {
                panic!()
            };
            public.regs.pc = CODE;
            public.regs.pstate = 0x3c5;
            public.regs.x[0] = SEED;
            public.regs.x[1] = UART;
            public.regs.x[2] = 0;
            cpu.set_state(&CpuState::Aarch64(public)).unwrap();
            let first = event(&mut *cpu);
            match (phase, first) {
                (
                    "read",
                    VcpuExit::MmioRead {
                        addr: UART,
                        size: 8,
                    },
                ) => (),
                ("write", VcpuExit::MmioWrite { addr: UART, data }) => {
                    assert_eq!(data, SEED.to_le_bytes());
                }
                ("shutdown", VcpuExit::Shutdown) => (),
                (_, exit) => panic!("{phase}: unexpected initial exit {exit:?}"),
            }
            cpu.set_current_pc(NEXT).unwrap();
            for _ in 0..2 {
                let exit = event(&mut *cpu);
                match (phase, exit) {
                    (
                        "read",
                        VcpuExit::MmioRead {
                            addr: UART,
                            size: 8,
                        },
                    ) => (),
                    ("write", VcpuExit::MmioWrite { addr: UART, data }) => {
                        assert_eq!(data, SEED.to_le_bytes());
                    }
                    ("shutdown", VcpuExit::Shutdown) => (),
                    (_, exit) => panic!("{phase}: PC update lost private state: {exit:?}"),
                }
                let CpuState::Aarch64(public) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(public.regs.pc, NEXT, "{phase}");
                assert_eq!(public.regs.x[2], 0, "{phase}: stopped CPU executed marker");
            }
            match phase {
                "read" => cpu.complete_io_in(&SEED.to_le_bytes()),
                "write" => cpu.complete_io_out().unwrap(),
                _ => cpu.wake(),
            }
            cpu.io_completion_result().unwrap();
            assert!(matches!(event(&mut *cpu), VcpuExit::Shutdown));
            let CpuState::Aarch64(public) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(public.regs.x[2], 0xbeef, "{phase}");
            assert_eq!(public.regs.pc, NEXT + 16, "{phase}");
        }
    }
}
