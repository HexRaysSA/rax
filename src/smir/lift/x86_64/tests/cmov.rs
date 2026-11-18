use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::lift::x86_64::*;
use crate::smir::optimize::{OptLevel, optimize_function};

#[test]
fn legacy_cmov32_reads_before_changing_the_destination_in_optimized_smir() {
    let original = 0x1234_5678_9abc_def0;
    let source = 0x9876_5432u32;
    let address = 8;
    let mut lift = LiftContext::new(SourceArch::X86_64);
    let cmove = X86_64Lifter::strict()
        .lift_insn(0x1000, &[0x0f, 0x44, 0x07], &mut lift)
        .unwrap();
    let mut block = SmirBlock::new(BlockId(0), 0x1000);
    block.ops = cmove.ops;
    block.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let mut function = SmirFunction::new(FunctionId(0), block.id, block.guest_pc);
        function.add_block(block.clone());
        optimize_function(&mut function, level);
        for (flags, mapped, expected) in [
            (2, false, original),
            (2, true, original & 0xffff_ffff),
            (0x42, true, u64::from(source)),
        ] {
            let mut context = SmirContext::new_x86_64();
            context.flags.materialized = MaterializedFlags::from_rflags(flags);
            context.write_vreg(x86_gpr(0), original);
            context.write_vreg(x86_gpr(7), address);
            let mut memory = FlatMemory::new(if mapped { 16 } else { 8 });
            if mapped {
                memory.write(address, &source.to_le_bytes()).unwrap();
            }
            let result = SmirInterpreter::new().execute_block(
                &mut context,
                &mut memory,
                function.entry_block().unwrap(),
            );
            if mapped {
                assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
            } else {
                assert!(matches!(
                    result,
                    BlockResult::Exit(ExitReason::MemoryFault {
                        addr: 8,
                        write: false
                    })
                ));
            }
            assert_eq!(context.read_vreg(x86_gpr(0)), expected, "{level:?}");
            assert_eq!(context.flags.materialized.to_rflags(), flags, "{level:?}");
        }
    }
}
