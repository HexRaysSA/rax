//! The public backend API also permits a VM without configured PSCI topology.
use super::*;
use crate::backend::{Backend, Vm};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::vcpu::VCpu;

fn state(cpu: &dyn VCpu) -> crate::vm::vcpu::Aarch64CpuState {
    let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state
}

fn standalone(count: u32) -> (Box<dyn Vm>, GuestMemoryWrapper, Vec<Box<dyn VCpu>>) {
    let backend = crate::backend::hvf::HvfArm64Backend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(128 << 20).unwrap();
    vm.as_any()
        .downcast_ref::<crate::backend::hvf::HvfArm64Vm>()
        .unwrap()
        .register_memory(&memory, 0x4000_0000, 128 << 20)
        .unwrap();
    let cpus = (0..count)
        .map(|id| {
            vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                .unwrap()
        })
        .collect();
    (vm, memory, cpus)
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn standalone_native_shutdown_is_vm_wide_and_restores_with_the_shared_graph() {
    for count in [1, 2] {
        let (vm, memory, mut cpus) = standalone(count);
        memory
            .memory()
            .write_slice(&0xd4000002u32.to_le_bytes(), GuestAddress(CODE))
            .unwrap();
        memory
            .memory()
            .write_slice(
                &(0xd2800002u32 | (0xbad << 5)).to_le_bytes(),
                GuestAddress(CODE + 4),
            )
            .unwrap();
        memory
            .memory()
            .write_slice(&0xf9400023u32.to_le_bytes(), GuestAddress(CODE + 8))
            .unwrap();
        // BSP invokes SYSTEM_OFF; peers would change X2 and hit UART if entered.
        for (id, cpu) in cpus.iter_mut().enumerate() {
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = CODE + if id == 0 { 0 } else { 4 };
            state.regs.pstate = 0x3c5;
            state.regs.x[0] = 0x84000008;
            state.regs.x[1] = UART;
            state.regs.x[2] = 0;
            cpu.set_state(&CpuState::Aarch64(state)).unwrap();
        }
        let mut stopped = false;
        for _ in 0..16 {
            match cpus[0].run().unwrap() {
                VcpuExit::Shutdown => {
                    stopped = true;
                    break;
                }
                VcpuExit::Hlt => (),
                other => panic!("SYSTEM_OFF returned {other:?}"),
            }
        }
        assert!(stopped);
        let boundary = vm.checkpoint_boundary().unwrap();
        let shared = vm
            .capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap();
        let graph = GlobalContext::decode(&shared.data).unwrap();
        assert!(
            graph.power.shutdown,
            "unconfigured VM lost terminal shared state"
        );
        assert!(
            graph
                .power
                .states
                .iter()
                .all(|state| *state == crate::backend::arm64_hvf_power::State::On)
        );
        let records: Vec<_> = cpus
            .iter()
            .map(|cpu| cpu.capture_checkpoint_record(&boundary, None).unwrap())
            .collect();
        assert!(records.iter().all(|(_, private)| {
            Context::decode(&private.as_ref().unwrap().data)
                .unwrap()
                .shutdown
        }));
        drop(boundary);
        for cpu in &mut cpus {
            let before = state(cpu.as_ref());
            assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
            assert_eq!(state(cpu.as_ref()), before);
        }
        drop(cpus);
        drop(vm);
        drop(memory);

        let (vm, _memory, mut cpus) = standalone(count);
        let boundary = vm.checkpoint_boundary().unwrap();
        for (cpu, (public, private)) in cpus.iter_mut().zip(&records) {
            cpu.restore_checkpoint_record(
                &boundary,
                &public.state,
                &public.emulator,
                private.as_ref(),
            )
            .unwrap();
        }
        vm.restore_checkpoint_vm_context(&boundary, Some(&shared))
            .unwrap();
        for (cpu, (_, private)) in cpus.iter_mut().zip(&records) {
            cpu.finish_checkpoint_restore(&boundary, private.as_ref())
                .unwrap();
        }
        let captured = vm
            .capture_checkpoint_vm_context(&boundary)
            .unwrap()
            .unwrap();
        assert_eq!(
            GlobalContext::decode(&captured.data).unwrap().power,
            graph.power
        );
        drop(boundary);
        for cpu in &mut cpus {
            let before = state(cpu.as_ref());
            assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
            assert_eq!(state(cpu.as_ref()), before);
        }
        cpus.last_mut().unwrap().wake();
        assert!(cpus.iter().all(|cpu| {
            !Context::decode(&cpu.capture_backend_context().unwrap().unwrap().data)
                .unwrap()
                .shutdown
        }));
        drop(cpus);
        drop(vm);
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn standalone_native_shared_capture_preserves_a_restored_pending_power_graph() {
    let (vm, _memory, cpus) = standalone(2);
    let boundary = vm.checkpoint_boundary().unwrap();
    let mut shared = vm
        .capture_checkpoint_vm_context(&boundary)
        .unwrap()
        .unwrap();
    let mut graph = GlobalContext::decode(&shared.data).unwrap();
    graph.power.cpu_off(1).unwrap();
    shared.data = graph.encode().unwrap();
    vm.restore_checkpoint_vm_context(&boundary, Some(&shared))
        .unwrap();
    let captured = vm
        .capture_checkpoint_vm_context(&boundary)
        .unwrap()
        .unwrap();
    assert_eq!(
        GlobalContext::decode(&captured.data).unwrap().power,
        graph.power
    );
    drop(boundary);
    drop(cpus);
    drop(vm);
}
