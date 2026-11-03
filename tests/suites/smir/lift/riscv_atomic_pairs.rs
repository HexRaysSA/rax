//! RV32 atomic expectations derive from Unprivileged ISA 20250508 13.4/15.1.
use super::*;
use rax::smir::lift::riscv::RiscVExtensions;
use rax::smir::{BlockResult, ExitReason, SmirMemory};

#[test]
fn atomic_extension_profiles_and_reserved_forms_match_the_isa() {
    for rv32 in [false, true] {
        for (a, zacas) in [(false, false), (true, false), (false, true), (true, true)] {
            for (word, accepted) in [
                (0x1005_22afu32, a),                  // LR.W, Zalrsc only.
                (0x18c5_25af, a),                     // SC.W.
                (0x00c5_25af, a || zacas),            // AMOADD.W, Zaamo.
                (0x28c5_232f, zacas),                 // AMOCAS.W x6,x12,(x10).
                (0x28c5_332f, zacas),                 // AMOCAS.D: RV32 pair / RV64 scalar.
                (0x28c5_432f, zacas && !rv32),        // AMOCAS.Q: RV64 only.
                (0x00c5_35af, (a || zacas) && !rv32), // AMOADD.D: RV64 only.
                (0x10c5_22af, false),                 // LR with nonzero rs2 is reserved.
            ] {
                let mut extensions = RiscVExtensions::rv64gc();
                extensions.a = a;
                extensions.zacas = zacas;
                let mut lifter = if rv32 {
                    RiscVLifter::new_rv32(extensions)
                } else {
                    RiscVLifter::new_rv64(extensions)
                };
                let arch = if rv32 {
                    SourceArch::RiscV32
                } else {
                    SourceArch::RiscV64
                };
                let result =
                    lifter.lift_insn(CODE_ADDR, &word.to_le_bytes(), &mut LiftContext::new(arch));
                assert_eq!(
                    result.is_ok(),
                    accepted,
                    "rv32={rv32}, a={a}, zacas={zacas}, {word:#010x}: {result:?}"
                );
            }
        }
    }
}

fn interpret(word: u32, registers: [u64; 32], old: u64) -> ([u64; 32], u64) {
    let mut lifter = RiscVLifter::new_rv32(RiscVExtensions::rv64gc());
    let mut lift = LiftContext::new(SourceArch::RiscV32);
    let mut result = lifter
        .lift_insn(CODE_ADDR, &word.to_le_bytes(), &mut lift)
        .unwrap();
    for (index, op) in result.ops.iter_mut().enumerate() {
        op.id = OpId(index as u16);
    }
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: CODE_ADDR,
        phis: vec![],
        ops: result.ops,
        terminator: Terminator::Trap {
            kind: TrapKind::Breakpoint,
        },
        exec_count: 0,
    };
    let mut context = SmirContext::new_riscv();
    let ArchRegState::RiscV(state) = &mut context.arch_regs else {
        panic!()
    };
    state.x = registers;
    let mut memory = SmirMem::with_base(0, MEM_SIZE as usize);
    memory.write(SCRATCH, &old.to_le_bytes()).unwrap();
    let result = SmirInterpreter::new().execute_block(&mut context, &mut memory, &block);
    assert!(
        matches!(result, BlockResult::Exit(ExitReason::Breakpoint { .. })),
        "{word:#010x}: {result:?}"
    );
    let registers = std::array::from_fn(|n| {
        if n == 0 {
            0
        } else {
            context.read_vreg(lift.get_arch_reg(ArchReg::RiscV(RiscVReg::X(n as u8))))
        }
    });
    let mut bytes = [0; 8];
    memory.read(SCRATCH, &mut bytes).unwrap();
    (registers, u64::from_le_bytes(bytes))
}

#[test]
fn rv32_doubleword_cas_pairs_zero_registers_aliases_and_orderings() {
    for (rd, rs1, rs2) in [
        (6u8, 10u8, 8u8),
        (6, 10, 6),
        (6, 6, 8),
        (6, 7, 8),
        (6, 8, 8),
        (6, 9, 8),
        (0, 10, 8),
        (6, 10, 0),
        (0, 10, 0),
        (30, 10, 28),
    ] {
        for success in [false, true] {
            for order in 0..4 {
                let mut initial = std::array::from_fn(|i| 0x8000_0000 + i as u64);
                initial[0] = 0;
                initial[usize::from(rs1)] = SCRATCH;
                let pair = |reg: u8| {
                    if reg == 0 {
                        0
                    } else {
                        initial[usize::from(reg)] | (initial[usize::from(reg + 1)] << 32)
                    }
                };
                let compare = pair(rd);
                let replacement = pair(rs2);
                let old = if success { compare } else { compare ^ 1 };
                let word = (5 << 27)
                    | (order << 25)
                    | (u32::from(rs2) << 20)
                    | (u32::from(rs1) << 15)
                    | (3 << 12)
                    | (u32::from(rd) << 7)
                    | 0x2f;
                let (actual, memory) = interpret(word, initial, old);
                let mut expected = initial;
                if rd != 0 {
                    expected[usize::from(rd)] = old & u64::from(u32::MAX);
                    expected[usize::from(rd + 1)] = old >> 32;
                }
                assert_eq!(actual, expected, "{word:#010x}, old={old:#018x}");
                assert_eq!(memory, if success { replacement } else { old });
            }
        }
    }
}

#[test]
fn rv32_word_atomic_results_and_addresses_are_zero_extended() {
    for operation in [0, 1, 5] {
        let mut initial = [0; 32];
        initial[10] = 0xffff_ffff_0000_0000 | SCRATCH;
        initial[12] = 1;
        initial[6] = 0x8000_0001;
        let word = (operation << 27) | (12 << 20) | (10 << 15) | (2 << 12) | (6 << 7) | 0x2f;
        let (registers, memory) = interpret(word, initial, 0x8000_0001);
        assert_eq!(registers[6], 0x8000_0001);
        assert_eq!(memory, if operation == 0 { 0x8000_0002 } else { 1 });
    }
}
