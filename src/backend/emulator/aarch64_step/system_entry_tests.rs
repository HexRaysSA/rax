//! Batch exits publish retirement, including restored observation phases.
use super::*;
use crate::vm::vcpu::RetirementStop;
use vm_memory::Bytes;

const ENTRY: u64 = 0x100;

fn machine(words: &[u32], micro: bool) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory
        .write_slice(
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            GuestAddress(ENTRY),
        )
        .unwrap();
    let mut cpu = if micro {
        Aarch64Vcpu::new_micro(0, memory.clone())
    } else {
        Aarch64Vcpu::new(0, memory.clone())
    };
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = ENTRY;
    state.regs.pstate = 0x3c5;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    (cpu, memory)
}

#[test]
fn system_batch_shutdown_publishes_all_completed_instructions() {
    for micro in [false, true] {
        let (mut cpu, _) = machine(&[0x9100_0400, 0xd440_0000], micro); // ADD; HLT
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
        assert_eq!(cpu.cpu.instruction_count(), 2);
        assert_eq!(cpu.instruction_count(), 2);
        assert_eq!(cpu.cpu.get_gpr(0), 1);
    }
}

#[test]
fn system_batch_returns_at_its_attempt_limit_before_a_long_loop_frontier() {
    for micro in [false, true] {
        let (mut cpu, _) = machine(&[0x9100_0400, 0xf100_0421, 0x54ff_ffc1, 0xd420_0000], micro);
        cpu.cpu.set_x(1, 1_000_000);
        let exit = cpu.run().expect("finite batch returns before BRK");
        assert!(if micro {
            matches!(exit, VcpuExit::Debug)
        } else {
            matches!(exit, VcpuExit::Hlt)
        });
        let attempts = u64::from(BATCH);
        assert_eq!(cpu.instruction_count(), attempts);
        assert_eq!(cpu.cpu.instruction_count(), attempts);
        assert_eq!(cpu.cpu.get_gpr(0), (attempts + 2) / 3);
        assert_eq!(cpu.cpu.get_gpr(1), 1_000_000 - (attempts + 1) / 3);
        assert_eq!(cpu.current_pc(), ENTRY + [0, 4, 8][attempts as usize % 3]);
        assert!(cpu.cpu.bounded_native_runs() > 1000);
    }
}

#[test]
fn system_restored_observation_phase_advances_by_retirement_delta_including_wrap() {
    for observed in [17, u64::MAX] {
        let (mut source, memory) = machine(&[0xd503_201f; 3], true);
        assert!(matches!(source.cpu.step().unwrap(), CpuExit::Continue));
        source.insn_count.store(observed, Ordering::Relaxed);
        let state = source.get_state().unwrap();
        let context = source.capture_backend_context().unwrap().unwrap();
        let mut target = Aarch64Vcpu::new_micro(0, memory);
        target
            .restore_checkpoint_context(&state, &Default::default(), Some(&context))
            .unwrap();
        assert_eq!(target.instruction_count(), observed);
        let result = target.run_retirement_budget(1).unwrap();
        assert!(
            matches!(result.stop, RetirementStop::BudgetExhausted),
            "{result:?}"
        );
        assert_eq!(result.retired, 1);
        assert_eq!(target.instruction_count(), observed.wrapping_add(1));
        assert_eq!(target.cpu.instruction_count(), 2);
        assert_eq!(target.current_pc(), ENTRY + 8);
    }
}

#[test]
fn system_batch_access_recording_bypasses_hot_native_entries() {
    for micro in [false, true] {
        let (mut cpu, memory) = machine(&[0xf940_0020, 0x17ff_ffff], micro); // LDR; B ENTRY
        cpu.cpu.set_jit_mem(true);
        cpu.cpu.set_x(1, 0x800);
        memory
            .write_slice(&7u64.to_le_bytes(), GuestAddress(0x800))
            .unwrap();
        assert_eq!(cpu.run_retirement_budget(256).unwrap().retired, 256);
        let entered = cpu.cpu.bounded_native_runs();
        assert!(entered > 0);
        memory
            .write_slice(&0xd440_0000u32.to_le_bytes(), GuestAddress(ENTRY + 4))
            .unwrap();
        cpu.set_mem_recording(true);
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
        assert_eq!(cpu.cpu.bounded_native_runs(), entered);
        assert_eq!(cpu.instruction_count(), 258);
        let mut records = Vec::new();
        cpu.drain_mem_records(&mut records);
        let exec: Vec<_> = records
            .iter()
            .filter(|r| r.access == MemAccess::Exec)
            .collect();
        assert_eq!(exec.len(), 2);
        assert_eq!(
            exec.iter().map(|r| (r.addr, r.size)).collect::<Vec<_>>(),
            [(ENTRY, 4), (ENTRY + 4, 4)]
        );
        let reads: Vec<_> = records
            .iter()
            .filter(|r| r.access == MemAccess::Read)
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(
            (reads[0].addr, reads[0].size, reads[0].value),
            (0x800, 8, 7)
        );
        assert_eq!(records.len(), 3);
    }
}
