//! Event latches and peer delivery through actual multi-CPU file restoration.
use super::*;
use crate::vm::vcpu::{RetirementStop, VcpuExit};

const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const NOP: u32 = 0xd503_201f;

fn step(vm: &mut Vmm, id: usize) -> crate::vm::vcpu::RetirementRun {
    let _timing = vm.timing_context.enter();
    let result = vm.vcpus[id].run_retirement_budget(1).unwrap();
    vm.coordinator.retired = vm.coordinator.retired.wrapping_add(result.retired);
    result
}

fn source(count: u8) -> Fixture {
    let mut source = Fixture::with_clock(count, ClockMode::Retired);
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
        let result = step(&mut source.vm, id);
        assert_eq!(result.retired, 1);
        assert!(matches!(result.stop, RetirementStop::BudgetExhausted));
    }
    source
}

fn continuation(vm: &mut Vmm, count: u8) {
    for id in 0..usize::from(count) {
        let result = step(vm, id);
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
        step(vm, sender).stop,
        RetirementStop::BudgetExhausted
    ));
    for id in 0..usize::from(count) {
        let result = step(vm, id);
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
        let mut restored = Fixture::with_clock(count, ClockMode::Retired);
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
        let source = Fixture::with_clock(count, ClockMode::Retired);
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
                u64::from(count) * (1 + 6 + (round - 1) * 5)
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

#[test]
fn wfx_traps_resume_on_the_correct_pe_after_detached_file_restore() {
    const MEMORY_BYTES: u64 = 8 * 1024 * 1024;
    let mut original = Fixture::with_memory(2, ClockMode::Retired, MEMORY_BYTES);
    let secondary = CODE + 0x100;
    assert_eq!(
        original
            .cluster()
            .request_on(1, secondary, 0, 0x3c5)
            .unwrap(),
        0
    );
    original.vm.route_interprocessor_requests().unwrap();

    for (id, word, hcr_bit) in [(0, WFE, 14), (1, WFI, 13)] {
        let entry = CODE + id as u64 * 0x100;
        let vectors = CODE + 0x800 * (id as u64 + 1);
        let mut state = original.vm.vcpus[id].get_state().unwrap();
        let CpuState::Aarch64(arm) = &mut state else {
            panic!("AArch64 fixture");
        };
        let system = &mut arm.sregs.execution.as_mut().unwrap().sysregs;
        system.scr_el3 = (1 << 10) | 1;
        system.hcr_el2 = (1 << 31) | (1 << hcr_bit);
        system.el2.vbar = vectors;
        original.vm.vcpus[id].set_state(&state).unwrap();

        let memory = original.vm.guest_mem.memory();
        memory
            .write_slice(&word.to_le_bytes(), GuestAddress(entry))
            .unwrap();
        memory
            .write_slice(&WFI.to_le_bytes(), GuestAddress(vectors + 0x400))
            .unwrap();
    }

    let path = original.kernel.with_extension("wfx.rxc");
    original
        .vm
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&path)
        .unwrap();
    let verify = |vm: &mut Vmm| {
        for id in 0..2 {
            assert!(vm.execute_turn().unwrap().is_none());
            let state = vm.vcpus[id].get_state().unwrap();
            let state = state.as_aarch64().unwrap();
            let el2 = &state.sregs.execution.as_ref().unwrap().sysregs.el2;
            assert_eq!(el2.esr, 0x07e0_0000 | u64::from(id == 0));
            assert_eq!(el2.elr, CODE + id as u64 * 0x100);
            assert_eq!(state.regs.pc, CODE + 0x800 * (id as u64 + 1) + 0x400);
            assert_eq!(vm.vcpus[id].instruction_count(), 0);
        }
        assert_eq!(vm.coordinator.retired, 0);
        for id in 0..2 {
            let turn = vm.execute_turn().unwrap().expect("EL2 handler yields");
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let state = vm.vcpus[id].get_state().unwrap();
            assert_eq!(
                state.as_aarch64().unwrap().regs.pc,
                CODE + 0x800 * (id as u64 + 1) + 0x404
            );
            assert_eq!(vm.vcpus[id].instruction_count(), 1);
        }
        assert_eq!(vm.coordinator.retired, 2);
    };
    verify(&mut original.vm);
    let coordinator = original.vm.coordinator.clone();
    let kernel = original.kernel.clone();
    drop(original);
    assert!(!kernel.exists());

    let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let mut restored = Fixture::with_memory(2, ClockMode::Retired, MEMORY_BYTES);
    restored.vm.restore_snapshot_bundle(&loaded).unwrap();
    verify(&mut restored.vm);
    assert_eq!(coordinator, restored.vm.coordinator);
}

#[test]
fn hcr_virtual_interrupts_resume_on_the_correct_pe_after_detached_file_restore() {
    const MEMORY_BYTES: u64 = 8 * 1024 * 1024;
    const CASES: [(u64, u64, u64); 2] = [
        ((1 << 4) | (1 << 7), 0x345, 0x280), // Virtual IRQ, FIQ masked.
        ((1 << 3) | (1 << 6), 0x385, 0x300), // Virtual FIQ, IRQ masked.
    ];
    let mut original = Fixture::with_memory(2, ClockMode::Retired, MEMORY_BYTES);
    assert_eq!(
        original
            .cluster()
            .request_on(1, CODE + 0x100, 0, 0x385)
            .unwrap(),
        0
    );
    original.vm.route_interprocessor_requests().unwrap();

    for (id, (hcr, pstate, offset)) in CASES.into_iter().enumerate() {
        let entry = CODE + id as u64 * 0x100;
        let vectors = CODE + 0x800 * (id as u64 + 1);
        let mut state = original.vm.vcpus[id].get_state().unwrap();
        let CpuState::Aarch64(arm) = &mut state else {
            panic!("AArch64 fixture");
        };
        arm.regs.pstate = pstate;
        arm.sregs.vbar_el1 = vectors;
        let system = &mut arm.sregs.execution.as_mut().unwrap().sysregs;
        system.scr_el3 = (1 << 10) | 1;
        system.hcr_el2 = (1 << 31) | hcr;
        system.el1.vbar = vectors;
        original.vm.vcpus[id].set_state(&state).unwrap();

        let memory = original.vm.guest_mem.memory();
        memory
            .write_slice(&NOP.to_le_bytes(), GuestAddress(entry))
            .unwrap();
        memory
            .write_slice(&WFI.to_le_bytes(), GuestAddress(vectors + offset))
            .unwrap();
    }

    let path = original.kernel.with_extension("virtual-interrupts.rxc");
    original
        .vm
        .take_snapshot_bundle(0)
        .unwrap()
        .save(&path)
        .unwrap();
    let verify = |vm: &mut Vmm| {
        for (id, (hcr, pstate, offset)) in CASES.into_iter().enumerate() {
            assert!(vm.execute_turn().unwrap().is_none());
            let state = vm.vcpus[id].get_state().unwrap();
            let arm = state.as_aarch64().unwrap();
            let system = &arm.sregs.execution.as_ref().unwrap().sysregs;
            assert_eq!(system.hcr_el2, (1 << 31) | hcr);
            assert_eq!(system.el1.elr, CODE + id as u64 * 0x100);
            assert_eq!(system.el1.spsr, pstate);
            assert_eq!(arm.regs.pc, CODE + 0x800 * (id as u64 + 1) + offset);
            assert_eq!(vm.vcpus[id].instruction_count(), 0);
        }
        assert_eq!(vm.coordinator.retired, 0);
        for (id, (_, _, offset)) in CASES.into_iter().enumerate() {
            let turn = vm.execute_turn().unwrap().expect("EL1 handler yields");
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let state = vm.vcpus[id].get_state().unwrap();
            assert_eq!(
                state.as_aarch64().unwrap().regs.pc,
                CODE + 0x800 * (id as u64 + 1) + offset + 4
            );
            assert_eq!(vm.vcpus[id].instruction_count(), 1);
        }
        assert_eq!(vm.coordinator.retired, 2);
    };
    verify(&mut original.vm);
    let coordinator = original.vm.coordinator.clone();
    let kernel = original.kernel.clone();
    drop(original);
    assert!(!kernel.exists());

    let loaded = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let mut restored = Fixture::with_memory(2, ClockMode::Retired, MEMORY_BYTES);
    restored.vm.restore_snapshot_bundle(&loaded).unwrap();
    verify(&mut restored.vm);
    assert_eq!(coordinator, restored.vm.coordinator);
}

#[test]
fn hcr_virtual_serror_survives_detached_file_restore_and_is_delivered_once_per_pe() {
    use crate::isa::arm::aarch64::hcr;

    const MEMORY_BYTES: u64 = 8 * 1024 * 1024;
    const HCR_ROUTING: u64 = hcr::RW | hcr::AMO;
    const PSTATE: u64 = 0x2c5; // EL1h, SError unmasked.
    let pending = |id: usize| id % 2 == 0;
    let initial_hcr = |id| HCR_ROUTING | if pending(id) { hcr::VSE } else { 0 };
    for count in [2u8, 4] {
        let mut original = Fixture::with_memory(count, ClockMode::Retired, MEMORY_BYTES);
        for id in 1..u64::from(count) {
            assert_eq!(
                original
                    .cluster()
                    .request_on(id, CODE + id * 0x100, 0, PSTATE)
                    .unwrap(),
                0
            );
        }
        original.vm.route_interprocessor_requests().unwrap();
        for id in 0..usize::from(count) {
            let entry = CODE + id as u64 * 0x100;
            let vectors = CODE + 0x800 * (id as u64 + 1);
            let mut state = original.vm.vcpus[id].get_state().unwrap();
            let CpuState::Aarch64(arm) = &mut state else {
                panic!("AArch64 fixture");
            };
            arm.regs.pstate = PSTATE;
            arm.sregs.vbar_el1 = vectors;
            let system = &mut arm.sregs.execution.as_mut().unwrap().sysregs;
            system.scr_el3 = (1 << 10) | 1;
            system.hcr_el2 = initial_hcr(id);
            system.el1.vbar = vectors;
            original.vm.vcpus[id].set_state(&state).unwrap();
            let memory = original.vm.guest_mem.memory();
            memory
                .write_slice(&WFI.to_le_bytes(), GuestAddress(entry))
                .unwrap();
            memory
                .write_slice(&0xd69f_03e0u32.to_le_bytes(), GuestAddress(vectors + 0x380))
                .unwrap();
        }

        let path = original.kernel.with_extension("virtual-serror.rxc");
        original
            .vm
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&path)
            .unwrap();
        drop(original);

        let bundle = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut restored = Fixture::with_memory(count, ClockMode::Retired, MEMORY_BYTES);
        restored.vm.restore_snapshot_bundle(&bundle).unwrap();

        for id in 0..usize::from(count) {
            let state = restored.vm.vcpus[id].get_state().unwrap();
            let system = &state
                .as_aarch64()
                .unwrap()
                .sregs
                .execution
                .as_ref()
                .unwrap()
                .sysregs;
            assert_eq!(system.hcr_el2, initial_hcr(id));
        }
        for id in 0..usize::from(count) {
            let turn = restored.vm.execute_turn().unwrap();
            let state = restored.vm.vcpus[id].get_state().unwrap();
            let arm = state.as_aarch64().unwrap();
            let system = &arm.sregs.execution.as_ref().unwrap().sysregs;
            assert_eq!(system.hcr_el2, HCR_ROUTING);
            if !pending(id) {
                let turn = turn.expect("peer without VSE reaches WFI directly");
                assert_eq!(turn.cpu_index, id);
                assert!(matches!(turn.exit, VcpuExit::Hlt));
                assert_eq!(arm.regs.pc, CODE + id as u64 * 0x100 + 4);
                assert_eq!(restored.vm.vcpus[id].instruction_count(), 1);
                continue;
            }
            assert!(turn.is_none());
            assert_eq!(arm.regs.pc, CODE + 0x800 * (id as u64 + 1) + 0x380);
            assert_eq!(system.el1.elr, CODE + id as u64 * 0x100);
            assert_eq!(system.el1.spsr, PSTATE);
            assert_eq!(system.el1.esr, 0xbe00_0000);
            assert_eq!(restored.vm.vcpus[id].instruction_count(), 0);
        }
        assert_eq!(restored.vm.coordinator.retired, u64::from(count) / 2);
        for id in 0..usize::from(count) {
            let turn = restored
                .vm
                .execute_turn()
                .unwrap()
                .expect("guests yield at WFI");
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(turn.exit, VcpuExit::Hlt));
            let state = restored.vm.vcpus[id].get_state().unwrap();
            assert_eq!(
                state.as_aarch64().unwrap().regs.pc,
                CODE + id as u64 * 0x100 + 4
            );
            assert_eq!(
                restored.vm.vcpus[id].instruction_count(),
                1 + u64::from(pending(id))
            );
        }
        assert_eq!(restored.vm.coordinator.retired, 3 * u64::from(count) / 2);
    }
}
