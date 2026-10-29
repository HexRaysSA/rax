//! Hot native execution through real 2/4-CPU scheduling and file restoration.
use super::*;
use crate::vm::vcpu::DEFAULT_RETIREMENT_QUANTUM;

fn source(count: u8) -> Fixture {
    let mut source = Fixture::new(count);
    for id in 1..count {
        assert_eq!(
            source
                .cluster()
                .request_on(u64::from(id), CODE, u64::from(id), 0x3c5)
                .unwrap(),
            0
        );
    }
    source.vm.route_interprocessor_requests().unwrap();
    for (index, word) in [0x9100_0529u32, 0x17ff_ffff].iter().enumerate() {
        // ADD X9,X9,#1; B CODE
        source
            .vm
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
            .unwrap();
    }
    source
}

fn assert_progress(vm: &Vmm, count: u8, rounds: u64, hot: bool) {
    assert_eq!(vm.coordinator.cursor, 0);
    assert_eq!(
        vm.coordinator.retired,
        u64::from(count) * rounds * DEFAULT_RETIREMENT_QUANTUM
    );
    for cpu in &vm.vcpus {
        assert_eq!(cpu.instruction_count(), rounds * DEFAULT_RETIREMENT_QUANTUM);
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.pc, CODE);
        assert_eq!(state.regs.x[9], rounds * DEFAULT_RETIREMENT_QUANTUM / 2);
        if hot {
            assert!(cpu.bounded_native_test_count() > 0);
        }
    }
}

#[test]
fn native_two_and_four_cpu_file_continuations_preserve_fairness_counters_and_hot_execution() {
    for count in [2, 4] {
        let mut source = source(count);
        for _ in 0..count {
            assert!(source.vm.execute_turn().unwrap().is_none());
        }
        assert_progress(&source.vm, count, 1, true);
        let saved = source.vm.take_snapshot_bundle(0).unwrap();
        let path = source.kernel.with_extension("bounded-native.rxc");
        saved.save(&path).unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let mut target = Fixture::new(count);
        target.vm.restore_snapshot_bundle(&loaded).unwrap();
        assert_progress(&target.vm, count, 1, false);
        for cpu in &target.vm.vcpus {
            assert_eq!(cpu.bounded_native_test_count(), 0);
        }
        for _ in 0..count {
            assert!(target.vm.execute_turn().unwrap().is_none());
        }
        assert_progress(&target.vm, count, 2, true);
        for _ in 0..count {
            assert!(source.vm.execute_turn().unwrap().is_none());
        }
        assert_eq!(
            format!("{:?}", target.vm.capture_cpu_states().unwrap()),
            format!("{:?}", source.vm.capture_cpu_states().unwrap())
        );
        assert_eq!(target.vm.coordinator, source.vm.coordinator);
        std::fs::remove_file(path).unwrap();
    }
}
