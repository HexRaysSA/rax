//! Native retirement retains the budget interface's wrapping u64 counters.
use super::*;

fn control_cpu(word: u32) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x1000)),
    );
    let program = [word, 0xf100_0421, 0x54ff_ffc1, 0xd420_0000]; // hint; SUBS X1,X1,#1; B.NE entry; BRK
    let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    cpu.write_memory(0x100, &bytes).unwrap();
    cpu.set_pc(0x100);
    cpu.set_x(1, 2);
    cpu
}

#[test]
fn native_control_wait_instructions_reject_before_erasing_scheduler_exits() {
    for (word, waiting) in [
        (0xd503_205f, true),
        (0xd503_207f, true),
        (0xd503_1000, false),
        (0xd503_1020, false),
    ] {
        let mut cpu = control_cpu(word);
        assert!(
            cpu.jit_compile_region().is_none(),
            "wait instruction {word:08x} must not become a native NOP"
        );
        cpu.jit.hot.insert(0x100, A64_JIT_HOT_THRESHOLD - 1);
        let exit = cpu.step_system_bounded(true).unwrap();
        assert_eq!(cpu.jit.bounded_runs, 0);
        assert_eq!((cpu.pc, cpu.insn_count), (0x104, 1));
        assert_eq!(matches!(exit, CpuExit::Wfe | CpuExit::Wfi), waiting);
        if word == 0xd503_205f {
            let mut ready = control_cpu(word);
            ready.event_register = true;
            ready.jit.hot.insert(0x100, A64_JIT_HOT_THRESHOLD - 1);
            assert!(matches!(
                ready.step_system_bounded(true).unwrap(),
                CpuExit::Continue
            ));
            assert!(!ready.event_register);
            assert_eq!(ready.jit.bounded_runs, 0);
            assert_eq!((ready.pc, ready.insn_count), (0x104, 1));
        }
    }
}

#[test]
fn native_control_event_instructions_reject_before_erasing_cpu_event_state() {
    for word in [0xd503_209f, 0xd503_20bf] {
        let mut cpu = control_cpu(word);
        assert!(!cpu.event_register);
        assert!(
            cpu.jit_compile_region().is_none(),
            "event instruction {word:08x} must not become a native NOP"
        );
        cpu.jit.hot.insert(0x100, A64_JIT_HOT_THRESHOLD - 1);
        assert!(matches!(
            cpu.step_system_bounded(true).unwrap(),
            CpuExit::Continue
        ));
        assert!(cpu.event_register);
        assert_eq!(cpu.jit.bounded_runs, 0);
        assert_eq!((cpu.pc, cpu.insn_count), (0x104, 1));
    }
}

#[test]
fn bounded_pauth_retirement_wraps_instruction_and_cycle_counters_independently() {
    for instructions in [0, u64::MAX - 1, u64::MAX] {
        for cycles in [0, u64::MAX - 1, u64::MAX] {
            let raw = 0xd503_233fu32; // PACIASP: a checked PAuth HINT.
            let mut cpu = AArch64Cpu::new(
                AArch64Config::default(),
                Box::new(FlatMemory::new(0, 0x1000)),
            );
            cpu.write_memory(0x100, &raw.to_le_bytes()).unwrap();
            cpu.set_pc(0x100);
            let region = cpu
                .jit_compile_pauth_instruction(raw)
                .expect("single-instruction PAuth native region");
            cpu.insn_count = instructions;
            cpu.cycle_count = cycles;
            assert!(cpu.jit_run_pauth_instruction(&region, raw));
            assert!(cpu.execution.native_fault.is_none());
            assert_eq!(cpu.execution.pauth_native_runs, 1);
            assert_eq!(cpu.insn_count, instructions.wrapping_add(1));
            assert_eq!(cpu.cycle_count, cycles.wrapping_add(1));
            assert_eq!(cpu.pc, 0x104);
        }
    }
}
