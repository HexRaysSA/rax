//! File checkpoints across zero-retirement faults in the actual coordinator.
use super::*;
use crate::isa::arm::common::features::ArmFeatures;

fn entry(id: usize) -> u64 {
    CODE + id as u64 * 0x1_0000
}

fn handler(id: usize) -> u64 {
    entry(id) + 0x1200
}

fn source(count: u8) -> Fixture {
    let mut source = Fixture::new(count);
    for id in 1..count {
        assert_eq!(
            source
                .cluster()
                .request_on(u64::from(id), entry(usize::from(id)), 0, 0x3c5)
                .unwrap(),
            0
        );
    }
    source.vm.route_interprocessor_requests().unwrap();
    for id in 0..usize::from(count) {
        for (address, word) in [
            (entry(id), 0xce02_9420u32),
            (handler(id), 0x9100_0529),     // ADD X9,X9,#1
            (handler(id) + 4, 0xd503_207f), // WFI
        ] {
            source
                .vm
                .guest_mem
                .memory()
                .write_slice(&word.to_le_bytes(), GuestAddress(address))
                .unwrap();
        }
        let cpu = &mut source.vm.vcpus[id];
        cpu.set_aarch64_fp_features(
            (ArmFeatures::FP16
                | ArmFeatures::FHM
                | ArmFeatures::JSCVT
                | ArmFeatures::FCMA
                | ArmFeatures::FRINTTS
                | ArmFeatures::BF16
                | ArmFeatures::I8MM
                | ArmFeatures::DOTPROD)
                .bits(),
        )
        .unwrap();
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = entry(id);
        state.regs.x[9] = 100 + id as u64;
        state.regs.pstate = 0x3c5;
        let vbar = entry(id) + 0x1000;
        state.sregs.vbar_el1 = vbar;
        let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
        system.el1.vbar = vbar;
        system.el1.cpacr = 3 << 20;
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    }
    source
}

fn assert_frontiers(vm: &Vmm, count: u8, delivered: usize) {
    assert_eq!(vm.coordinator.retired, 0);
    assert_eq!(vm.coordinator.cursor, delivered % usize::from(count));
    for id in 0..usize::from(count) {
        let cpu = &vm.vcpus[id];
        assert_eq!(cpu.instruction_count(), 0);
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.x[9], 100 + id as u64);
        assert_eq!(
            state.regs.pc,
            if id < delivered {
                handler(id)
            } else {
                entry(id)
            }
        );
        if id < delivered {
            let system = &state.sregs.execution.as_ref().unwrap().sysregs;
            assert_eq!((system.el1.elr, system.el1.esr), (entry(id), 1 << 25));
        }
    }
}

#[test]
fn undefined_two_and_four_cpu_file_continuations_preserve_every_fault_and_scheduler_unit() {
    for count in [2, 4] {
        for delivered in [0, 1, usize::from(count)] {
            let mut source = source(count);
            for _ in 0..delivered {
                assert!(source.vm.execute_turn().unwrap().is_none());
            }
            assert_frontiers(&source.vm, count, delivered);
            let saved = source.vm.take_snapshot_bundle(0).unwrap();
            let path = source.kernel.with_extension("undefined.rxc");
            saved.save(&path).unwrap();
            let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
            let mut target = Fixture::new(count);
            target.vm.restore_snapshot_bundle(&loaded).unwrap();
            assert_frontiers(&target.vm, count, delivered);
            for _ in delivered..usize::from(count) {
                assert!(target.vm.execute_turn().unwrap().is_none());
            }
            assert_frontiers(&target.vm, count, usize::from(count));
            for id in 0..usize::from(count) {
                let turn = target.vm.execute_turn().unwrap().unwrap();
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                let cpu = &target.vm.vcpus[id];
                let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                    panic!()
                };
                assert_eq!(
                    (state.regs.x[9], state.regs.pc),
                    (101 + id as u64, handler(id) + 8)
                );
                assert_eq!(cpu.instruction_count(), 2, "ADD and WFI each retire once");
                assert_eq!(target.vm.coordinator.retired, 2 * (id as u64 + 1));
            }
            std::fs::remove_file(path).unwrap();
        }
    }
}
