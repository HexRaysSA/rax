//! Full-state mixed-width ERET equivalence at every optimization level.

use super::*;
use crate::smir::interpret::SmirInterpreter;
use crate::smir::ir::context::{Aarch64RegState, ArchRegState, SmirContext};
use crate::smir::ir::memory::FlatMemory;
use crate::smir::ir::types::{BlockId, FunctionId, SourceArch};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::optimize::{OptLevel, optimize_function};
use crate::vm::vcpu::{Aarch64CpuState, Aarch64Registers};

fn snapshot(cpu: &AArch64Cpu) -> Aarch64CpuState {
    Aarch64CpuState {
        regs: Aarch64Registers {
            x: cpu.x,
            sp: cpu.current_sp(),
            pc: cpu.pc,
            pstate: cpu.pstate_bits(),
            v: std::array::from_fn(|i| [cpu.v[i] as u64, (cpu.v[i] >> 64) as u64]),
            fpcr: cpu.fpcr,
            fpsr: cpu.fpsr,
        },
        sregs: cpu.export_sregs(),
    }
}

fn function(cpu: &AArch64Cpu, raw: u32, level: OptLevel) -> SmirFunction {
    let mut context = LiftContext::new(SourceArch::Aarch64);
    context.aarch64_features = Some(cpu.config.features);
    let lifted = Aarch64Lifter::strict()
        .lift_insn(0, &raw.to_le_bytes(), &mut context)
        .unwrap();
    let ControlFlow::IndirectBranch { target } = lifted.control_flow else {
        panic!("ERET terminator");
    };
    let mut block = SmirBlock::new(BlockId(0), 0);
    block.ops = lifted.ops;
    block.terminator = Terminator::IndirectBranch {
        target,
        possible_targets: vec![],
    };
    let mut function = SmirFunction::new(FunctionId(0), block.id, 0);
    function.add_block(block);
    optimize_function(&mut function, level);
    function
}

fn cases(mut check: impl FnMut(&AArch64Cpu, &Aarch64CpuState, &SmirFunction, &Aarch64CpuState)) {
    let mut count = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for raw in [0xd69f_0bff, 0xd69f_0fff] {
                for (mode, _) in MODES {
                    for thumb in [false, true] {
                        let mut direct = prepare(raw, mode, thumb, algorithm, profile);
                        let initial = snapshot(&direct);
                        direct.step().unwrap();
                        let expected = snapshot(&direct);
                        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                            let function = function(&direct, raw, level);
                            check(&direct, &initial, &function, &expected);
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 768);
}

#[test]
fn pauth_eret_aarch32_smir_full_state_matches_direct_at_o0_o1_o2() {
    cases(|direct, initial, function, expected| {
        let mut context = SmirContext::new_aarch64();
        context.arch_regs =
            ArchRegState::Aarch64(Aarch64RegState::from_cpu_state(initial).unwrap());
        context.flags.materialized = crate::smir::ir::flags::MaterializedFlags::from_nzcv(
            (initial.regs.pstate & 0xf000_0000) as u32,
        );
        let mut memory = FlatMemory::new(0x10000);
        let result =
            SmirInterpreter::new().execute_block(&mut context, &mut memory, &function.blocks[0]);
        assert!(
            matches!(result, crate::smir::interpret::BlockResult::Continue(target) if target == expected.regs.pc),
            "{result:?}"
        );
        let ArchRegState::Aarch64(state) = context.arch_regs else {
            panic!("AArch64 state container");
        };
        assert_eq!(
            crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
            crate::codec::serialize(expected).unwrap()
        );
        assert_eq!(state.event_register, direct.event_register);
        assert_eq!(context.insn_count, 1);
    });
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn pauth_eret_aarch32_native_full_state_matches_direct_at_o0_o1_o2() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    cases(|direct, initial, function, expected| {
        #[cfg(target_arch = "aarch64")]
        let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
        #[cfg(target_arch = "x86_64")]
        let mut lowerer =
            crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
        lowerer.set_pauth_helpers(true);
        let lowered = lowerer.lower_function(function).unwrap();
        assert!(lowered.relocations.is_empty());
        let code = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
        let mut memory = FlatMemory::new(0x10000);
        let mut runtime = Aarch64PauthRuntime::new(
            Aarch64RegState::from_cpu_state(initial).unwrap(),
            &mut memory,
        )
        .unwrap();
        runtime
            .run(&mut Aarch64GuestRegs::default(), |registers| {
                #[cfg(target_arch = "aarch64")]
                code.run_aarch64_identity(lowered.entry_offset, registers);
                #[cfg(target_arch = "x86_64")]
                code.run_aarch64(lowered.entry_offset, registers);
            })
            .unwrap();
        assert_eq!(runtime.retired, 1);
        assert_eq!(
            crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
            crate::codec::serialize(expected).unwrap()
        );
        assert_eq!(runtime.registers.event_register, direct.event_register);
    });
}
