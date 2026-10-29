//! Public system steps are instruction boundaries even when native code is hot.
use super::*;

const ENTRY: u64 = 0x100;

fn machine() -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x2000)),
    );
    let words = [0x9100_0400u32, 0xf100_0421, 0x54ff_ffc1, 0xd420_0000];
    cpu.write_memory(
        ENTRY,
        &words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    cpu.set_pc(ENTRY);
    cpu.set_x(1, 10_000);
    cpu
}

#[test]
fn public_system_entry_cannot_execute_a_cached_multi_instruction_region() {
    for diagnostic in [false, true] {
        let mut cpu = machine();
        let region = cpu.jit_compile_region().expect("legacy native scalar loop");
        cpu.jit.cache.insert(
            (ENTRY, cpu.jit_mode_tag()),
            Some(std::sync::Arc::new(region)),
        );
        let exit = if diagnostic {
            cpu.step_system_with_fault_exit()
        } else {
            cpu.step_system()
        }
        .unwrap();
        assert!(matches!(exit, CpuExit::Continue));
        assert_eq!((cpu.pc, cpu.get_x(0), cpu.get_x(1)), (ENTRY + 4, 1, 10_000));
        assert_eq!(
            (cpu.insn_count, cpu.cycle_count, cpu.sysregs.cntpct_el0),
            (1, 1, 16)
        );
    }
}

#[test]
fn public_system_entry_preserves_every_hot_loop_frontier_and_attempt_tick() {
    for diagnostic in [false, true] {
        let mut cpu = machine();
        for index in 0..768u64 {
            let result = if diagnostic {
                cpu.step_system_with_fault_exit()
            } else {
                cpu.step_system()
            };
            assert!(matches!(result, Ok(CpuExit::Continue)), "{result:?}");
            assert_eq!(cpu.pc, ENTRY + [4, 8, 0][index as usize % 3]);
            assert_eq!(cpu.get_x(0), (index + 3) / 3);
            assert_eq!(cpu.get_x(1), 10_000 - (index + 2) / 3);
            assert_eq!((cpu.insn_count, cpu.cycle_count), (index + 1, index + 1));
            assert_eq!(cpu.sysregs.cntpct_el0, (index + 1) * 16);
        }
        assert!(
            cpu.jit.bounded_runs > 400,
            "hot public steps must actually run natively"
        );
    }
}
