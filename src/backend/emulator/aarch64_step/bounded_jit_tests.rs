//! A hot native tier must preserve the scheduler's instruction frontier.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;

fn machine(program: &[u32], micro: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let bytes: Vec<_> = program.iter().flat_map(|word| word.to_le_bytes()).collect();
    memory.write_slice(&bytes, GuestAddress(ENTRY)).unwrap();
    let mut cpu = if micro {
        Aarch64Vcpu::new_micro(0, memory.clone())
    } else {
        Aarch64Vcpu::new(0, memory.clone())
    };
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 5 | (15 << 6);
    state.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 3 << 20;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, memory)
}

#[test]
fn hot_native_loop_returns_at_every_budget_boundary() {
    for micro in [false, true] {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _binding = clock.enter();
        let (mut cpu, _) = machine(&[0x9100_0400, 0x17ff_ffff], micro); // ADD X0,X0,#1; B ENTRY
        for index in 0..512u64 {
            let result = cpu.run_retirement_budget(1).unwrap();
            assert!(
                matches!(result.stop, RetirementStop::BudgetExhausted),
                "{result:?}"
            );
            assert_eq!(result.retired, 1);
            assert_eq!(cpu.instruction_count(), index + 1);
            assert_eq!(cpu.current_pc(), ENTRY + 4 * ((index + 1) % 2));
            assert_eq!(cpu.cpu.get_gpr(0), (index + 2) / 2);
            assert_eq!(clock.checkpoint_state().retired_units, index + 1);
        }
        assert!(
            cpu.cpu.bounded_native_runs() > 300,
            "hot instructions must actually execute natively"
        );
    }
}

#[test]
fn self_branch_retires_once_and_zero_budget_never_enters_native_code() {
    let (mut cpu, _) = machine(&[0x1400_0000], true); // B .
    for _ in 0..128 {
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(cpu.current_pc(), ENTRY);
    }
    let entered = cpu.cpu.bounded_native_runs();
    assert!(entered > 0);
    let count = cpu.instruction_count();
    assert_eq!(cpu.run_retirement_budget(0).unwrap().retired, 0);
    assert_eq!(cpu.cpu.bounded_native_runs(), entered);
    assert_eq!(cpu.instruction_count(), count);
    assert_eq!(cpu.current_pc(), ENTRY);
}

#[test]
fn native_conditional_branch_consumes_live_nzcv_and_both_edges() {
    let (mut cpu, _) = machine(&[0x5400_0040, 0x17ff_ffff, 0x17ff_fffe], true); // B.EQ +8; B ENTRY; B ENTRY
    for index in 0..256 {
        let zero = index % 2 == 0;
        cpu.cpu.set_nzcv_bits(if zero { 4 } else { 0 });
        assert_eq!(cpu.current_pc(), ENTRY);
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(cpu.current_pc(), ENTRY + if zero { 8 } else { 4 });
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        assert_eq!(cpu.current_pc(), ENTRY);
    }
    assert!(cpu.cpu.bounded_native_runs() > 200);
}

#[test]
fn native_cache_observes_code_replacement_and_checkpoint_rebuilds_it() {
    let (mut cpu, memory) = machine(&[0x9100_0400, 0x17ff_ffff], true);
    assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
    assert!(cpu.cpu.bounded_native_runs() > 0);
    let state = cpu.get_state().unwrap();
    let context = cpu.capture_backend_context().unwrap().unwrap();
    let mut restored = Aarch64Vcpu::new_micro(0, memory.clone());
    restored
        .restore_checkpoint_context(&state, &Default::default(), Some(&context))
        .unwrap();
    assert_eq!(
        restored.cpu.bounded_native_runs(),
        0,
        "native caches are derived"
    );
    assert_eq!(restored.run_retirement_budget(256).unwrap().retired, 256);
    assert_eq!(restored.cpu.get_gpr(0), 256);
    assert!(restored.cpu.bounded_native_runs() > 0);
    memory
        .write_slice(&0x9100_0800u32.to_le_bytes(), GuestAddress(ENTRY))
        .unwrap(); // ADD X0,X0,#2
    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(cpu.cpu.get_gpr(0), 130);
}

#[test]
fn native_load_fault_stops_without_retirement_and_retries_after_mapping_is_valid() {
    let (mut cpu, memory) = machine(&[0xf940_0020, 0x17ff_ffff], true); // LDR X0,[X1]; B ENTRY
    cpu.cpu.set_jit_mem(true);
    cpu.cpu.set_x(1, 0x800);
    memory
        .write_slice(&0x1234_5678_9abc_def0u64.to_le_bytes(), GuestAddress(0x800))
        .unwrap();
    assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
    let entered = cpu.cpu.bounded_native_runs();
    assert!(entered > 0);
    cpu.cpu.set_x(1, 0x5000);
    let result = cpu.run_retirement_budget(1000).unwrap();
    assert!(
        matches!(result.stop, RetirementStop::Fault(_)),
        "{result:?}"
    );
    assert_eq!(result.retired, 0);
    assert_eq!(cpu.current_pc(), ENTRY);
    assert_eq!(cpu.instruction_count(), 256);
    assert_eq!(cpu.cpu.bounded_native_runs(), entered + 1);
    assert_eq!(cpu.cpu.get_gpr(0), 0x1234_5678_9abc_def0);
    cpu.cpu.set_x(1, 0x800);
    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(cpu.current_pc(), ENTRY + 4);
}

#[test]
fn native_tier_switch_does_not_change_retirement_or_attempt_clock() {
    let (mut cpu, _) = machine(&[0x9100_0400, 0x17ff_ffff], true);
    assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
    let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        state.sregs.execution.as_ref().unwrap().sysregs.cntpct_el0,
        256 * 16
    );
    assert!(cpu.cpu.bounded_native_runs() > 0);
    cpu.cpu.set_jit_enabled(false);
    let entered = cpu.cpu.bounded_native_runs();
    assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
    assert_eq!(cpu.cpu.bounded_native_runs(), entered);
    assert_eq!(cpu.cpu.get_gpr(0), 256);
    let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        state.sregs.execution.as_ref().unwrap().sysregs.cntpct_el0,
        512 * 16
    );
}

#[test]
fn enabling_access_recording_on_hot_code_preserves_exact_fetches_and_data_accesses() {
    let (mut cpu, memory) = machine(&[0xf940_0020, 0x17ff_ffff], true);
    cpu.cpu.set_jit_mem(true);
    cpu.cpu.set_x(1, 0x800);
    memory
        .write_slice(&7u64.to_le_bytes(), GuestAddress(0x800))
        .unwrap();
    assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
    let entered = cpu.cpu.bounded_native_runs();
    assert!(entered > 0);
    cpu.set_mem_recording(true);
    assert_eq!(cpu.run_retirement_budget(2).unwrap().retired, 2);
    assert_eq!(cpu.cpu.bounded_native_runs(), entered);
    let mut records = Vec::new();
    cpu.drain_mem_records(&mut records);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.access == MemAccess::Exec)
            .count(),
        2
    );
    let reads: Vec<_> = records
        .iter()
        .filter(|record| record.access == MemAccess::Read)
        .collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(
        (reads[0].addr, reads[0].size, reads[0].value),
        (0x800, 8, 7)
    );
    cpu.set_mem_recording(false);
    assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(cpu.cpu.bounded_native_runs(), entered + 1);
}

#[test]
fn hot_native_register_flags_fp_and_branch_results_match_independent_apple_silicon_execution() {
    let rows: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-bounded-native/native-vectors.json"
    )))
    .unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1536);
    for row in rows {
        let word = row["word"].as_u64().unwrap() as u32;
        let (mut cpu, _) = machine(&[word, 0x17ff_ffff, 0x17ff_fffe], true);
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        for index in 0..4 {
            state.regs.x[index] = row["initial_x"][index].as_u64().unwrap();
        }
        state.regs.pstate |= row["flags"].as_u64().unwrap() << 28;
        state.regs.v[0] = [0x3ff8_0000_0000_0000, 0x1122_3344_5566_7788];
        state.regs.v[1] = [0xbfe0_0000_0000_0000, 0x8877_6655_4433_2211];
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
        assert_eq!(cpu.run_retirement_budget(254).unwrap().retired, 254);
        let entered = cpu.cpu.bounded_native_runs();
        let result = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1, "word={word:08x} {result:?}");
        assert_eq!(
            cpu.cpu.bounded_native_runs(),
            entered + 1,
            "word={word:08x}: final instruction must execute natively"
        );
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        for index in 0..4 {
            assert_eq!(
                state.regs.x[index],
                row["x"][index].as_u64().unwrap(),
                "word={word:08x} x{index}, row={row}"
            );
        }
        assert_eq!(
            state.regs.pstate & 0xf000_0000,
            row["nzcv"].as_u64().unwrap(),
            "word={word:08x}"
        );
        assert_eq!(
            state.regs.pc,
            row["pc"].as_u64().unwrap(),
            "word={word:08x}"
        );
        for index in 0..4 {
            assert_eq!(
                state.regs.v[index / 2][index % 2],
                row["v"][index].as_u64().unwrap(),
                "word={word:08x} v{index}"
            );
        }
        assert_eq!(u64::from(state.regs.fpcr), row["fpcr"].as_u64().unwrap());
        assert_eq!(u64::from(state.regs.fpsr), row["fpsr"].as_u64().unwrap());
    }
}
