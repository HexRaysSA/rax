//! Event latches and peer delivery through actual multi-CPU file restoration.
use super::*;
use crate::vm::vcpu::{RetirementStop, VcpuExit};

const WFE: u32 = 0xd503_205f;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const NOP: u32 = 0xd503_201f;

fn source(count: u8) -> Fixture {
    let mut source = Fixture::new(count);
    for id in 1..count {
        source
            .cluster()
            .request_on(u64::from(id), CODE + u64::from(id) * 0x100, 0, 0x3c5)
            .unwrap();
    }
    source.vm.route_interprocessor_requests().unwrap();
    for id in 0..usize::from(count) {
        let program = [
            if id % 2 == 0 { SEVL } else { NOP },
            WFE,
            WFE,
            NOP,
            SEV,
            WFE,
            WFE,
        ];
        let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
        source
            .vm
            .guest_mem
            .memory()
            .write_slice(&bytes, GuestAddress(CODE + id as u64 * 0x100))
            .unwrap();
        let result = source.vm.vcpus[id].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1);
        assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    }
    source
}

fn continuation(vm: &mut Vmm, count: u8) {
    for id in 0..usize::from(count) {
        let result = vm.vcpus[id].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1);
        if id % 2 == 0 {
            assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
        } else {
            assert!(matches!(result.stop, RetirementStop::Exit(VcpuExit::Hlt)));
        }
    }
    // Move all CPUs to SEV/WFE without changing their private latch values.
    for id in 0..usize::from(count) {
        let pc = CODE + id as u64 * 0x100 + if id == 0 { 16 } else { 20 };
        vm.vcpus[id].set_current_pc(pc).unwrap();
    }
    // The sender executes SEV after restoration; fresh peer WFE must consume it.
    let sender = 0;
    assert!(matches!(
        vm.vcpus[sender].run_retirement_budget(1).unwrap().stop,
        RetirementStop::BudgetExhausted
    ));
    for id in 0..usize::from(count) {
        let result = vm.vcpus[id].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1);
        // Odd peers were waiting: completing their old WFE consumes the signal,
        // so the new WFE can wait again. Even peers consume it in this WFE.
        if id % 2 == 0 {
            assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
        } else {
            assert!(matches!(result.stop, RetirementStop::Exit(VcpuExit::Hlt)));
        }
    }
}

#[test]
fn two_and_four_cpu_file_restore_preserves_distinct_latches_and_peer_delivery() {
    for count in [2, 4] {
        let mut original = source(count);
        let saved = original.vm.take_snapshot_bundle(0).unwrap();
        let path = original.kernel.with_extension("events.rxc");
        saved.save(&path).unwrap();
        let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let mut restored = Fixture::new(count);
        restored.vm.restore_snapshot_bundle(&loaded).unwrap();
        continuation(&mut original.vm, count);
        continuation(&mut restored.vm, count);
        assert_eq!(
            format!("{:?}", original.vm.capture_cpu_states().unwrap()),
            format!("{:?}", restored.vm.capture_cpu_states().unwrap())
        );
        assert_eq!(original.vm.coordinator, restored.vm.coordinator);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn final_cpu_rejection_preserves_each_live_event_latch() {
    for count in [2, 4] {
        let source = Fixture::new(count);
        let mut saved = source.vm.take_snapshot_bundle(0).unwrap();
        let mut contexts = saved.take_backend_contexts().unwrap().entries().to_vec();
        contexts.last_mut().unwrap().as_mut().unwrap().data.pop();
        let bad = saved.with_backend_contexts(contexts).unwrap();
        let mut target = self::source(count);
        let before = target.vm.capture_cpu_states().unwrap();
        let graph = target.graph();
        assert!(target.vm.restore_snapshot_bundle(&bad).is_err());
        assert_eq!(
            format!("{:?}", target.vm.capture_cpu_states().unwrap()),
            format!("{before:?}")
        );
        assert_eq!(target.graph(), graph);
        continuation(&mut target.vm, count);
    }
}

#[test]
fn coordinator_executes_event_wakeup_cycles_on_every_two_and_four_cpu_peer() {
    for count in [2, 4] {
        let mut fixture = source(count);
        for id in 0..usize::from(count) {
            // Each cycle waits, records progress, signals peers, consumes its
            // own signal, then waits again at the first WFE.
            let program = [WFE, 0x9100_0529, SEV, WFE, 0x17ff_fffc];
            let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
            fixture
                .vm
                .guest_mem
                .memory()
                .write_slice(&bytes, GuestAddress(CODE + id as u64 * 0x100 + 4))
                .unwrap();
        }
        for round in 1..=8 {
            for id in 0..usize::from(count) {
                let turn = fixture
                    .vm
                    .execute_turn()
                    .unwrap()
                    .expect("WFE yields a scheduler exit");
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
            }
            assert_eq!(fixture.vm.coordinator.cursor, 0);
            assert_eq!(
                fixture.vm.coordinator.retired,
                u64::from(count) * (6 + (round - 1) * 5)
            );
            for (id, cpu) in fixture.vm.vcpus.iter().enumerate() {
                let state = cpu.get_state().unwrap();
                let regs = &state.as_aarch64().unwrap().regs;
                assert_eq!(regs.x[9], round, "CPU {id}, round {round}");
                assert_eq!(regs.pc, CODE + id as u64 * 0x100 + 8);
                assert_eq!(cpu.instruction_count(), 1 + 6 + (round - 1) * 5);
            }
        }
    }
}
