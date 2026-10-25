//! Complete raw-form direct/SMIR comparisons; expectations are not masked.

use super::*;
use crate::isa::arm::aarch64::pauth::{
    PauthAlgorithm, PauthConfig, PauthKey, PauthKeys, PauthProfile,
};
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::cpu::{ArmCpu, ArmError};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::FlatMemory as ArmMemory;
use crate::smir::ir::context::Aarch64RegState;
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::optimize::{OptLevel, optimize_function};
use crate::vm::vcpu::{Aarch64CpuState, Aarch64Registers};

mod flow;
mod keys;
mod mmu;
mod success;

const PC: u64 = 0x1000;

fn forms() -> Vec<u32> {
    let mut words = vec![
        0xd71f_0801,
        0xd71f_0c01,
        0xd73f_0801,
        0xd73f_0c01,
        0xd61f_081f,
        0xd61f_0c1f,
        0xd63f_081f,
        0xd63f_0c1f,
        0xd65f_0bff,
        0xd65f_0fff,
        0xd69f_0bff,
        0xd69f_0fff,
        0xf820_17e6,
        0xf8a0_17e6,
        0x9ac1_3000,
    ];
    words.extend((0..=17).map(|opcode| 0xdac1_03e0 | (opcode << 10)));
    words.extend(
        [7, 8, 10, 12, 14, 24, 25, 26, 27, 28, 29, 30, 31].map(|imm| 0xd503_201f | (imm << 5)),
    );
    assert_eq!(words.len(), 46);
    words
}

fn cpu(word: u32, algorithm: PauthAlgorithm, profile: PauthProfile, enabled: bool) -> AArch64Cpu {
    let mut features = ArmFeatures::armv8_3_base();
    features.set(ArmFeatures::PACA | ArmFeatures::PACG, enabled);
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            features,
            pauth: PauthConfig { algorithm, profile },
            gic_config: None,
            ..Default::default()
        },
        Box::new(ArmMemory::new(0, 0x10000)),
    );
    cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
    cpu.write_memory(0x3008, &0xdead_beef_cafe_f00du64.to_le_bytes())
        .unwrap();
    cpu.set_pc(PC);
    cpu.set_pstate_bits(0xa000_0cc5).unwrap();
    cpu.set_current_sp(0x3000);
    for index in 0..31 {
        cpu.set_x(index, 0x4000 + u64::from(index) * 16);
        cpu.set_simd(index, u128::from(index) * 0x1234_5678_9abc_def0);
    }
    cpu.set_x(1, 1);
    let key = PauthKey {
        lo: u64::MAX,
        hi: 0x0123_4567_89ab_cdef,
    };
    cpu.set_pauth_keys(PauthKeys {
        ia: key,
        ib: key,
        da: key,
        db: key,
        ga: key,
    });
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 = 1 | (1 << 10) | (1 << 16) | (1 << 17);
    controls.hcr_el2 = (1 << 31) | (1 << 40) | (1 << 41);
    controls.sctlr[1] = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13);
    controls.tcr[1] = 16 | (16 << 16);
    cpu.set_pauth_controls(controls).unwrap();
    let mut system = cpu.export_sregs();
    system.elr_el1 = 0x5000;
    system.spsr_el1 = 0x6000_0000; // AArch64 EL0t, distinct saved NZCV.
    system.sp_el0 = 0x6000;
    cpu.import_sregs(&system).unwrap();
    if enabled
        && let Some(crate::isa::arm::aarch64::pauth_instruction::PauthInstruction::Load {
            key_b,
            ..
        }) = crate::isa::arm::aarch64::pauth_instruction::PauthInstruction::decode(word)
    {
        let layout = cpu.pauth_controls().layout(0x3000, true);
        let signed = layout.sign(
            algorithm,
            profile,
            0x3000,
            0,
            if key_b {
                cpu.pauth_keys().db
            } else {
                cpu.pauth_keys().da
            },
        );
        cpu.set_current_sp(signed);
    }
    cpu
}

fn snapshot(cpu: &AArch64Cpu) -> Aarch64CpuState {
    let system = cpu.export_sregs();
    let mode = cpu.pstate_bits() & 15;
    let sp = match mode {
        5 => system.sp_el1,
        9 => system.execution.as_ref().unwrap().sp_el2,
        13 => system.execution.as_ref().unwrap().sp_el3,
        _ => system.sp_el0,
    };
    Aarch64CpuState {
        regs: Aarch64Registers {
            x: std::array::from_fn(|index| cpu.get_x(index as u8)),
            pc: cpu.get_pc(),
            sp,
            pstate: cpu.pstate_bits(),
            v: std::array::from_fn(|index| {
                let value = cpu.get_simd(index as u8);
                [value as u64, (value >> 64) as u64]
            }),
            fpcr: cpu.fpcr_value(),
            fpsr: cpu.fpsr_value(),
        },
        sregs: system,
    }
}

fn function(words: &[u32], features: ArmFeatures) -> SmirFunction {
    let mut context = LiftContext::new(SourceArch::Aarch64);
    context.aarch64_features = Some(features);
    let mut lifter = Aarch64Lifter::strict();
    let mut block = SmirBlock::new(BlockId(0), PC);
    for (index, raw) in words.iter().enumerate() {
        let pc = PC + index as u64 * 4;
        let lifted = lifter
            .lift_insn(pc, &raw.to_le_bytes(), &mut context)
            .unwrap();
        assert!(matches!(
            lifted.ops.first().unwrap().kind,
            OpKind::ArmInstructionBegin { .. }
        ));
        assert!(matches!(
            lifted.ops.last().unwrap().kind,
            OpKind::ArmInstructionCommit { .. }
        ));
        block.ops.extend(lifted.ops);
        block.terminator = match lifted.control_flow {
            ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                target,
                possible_targets: vec![],
            },
            _ => Terminator::Trap {
                kind: TrapKind::Halt,
            },
        };
    }
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
}

fn context(state: &Aarch64CpuState) -> SmirContext {
    let mut context = SmirContext::new_aarch64();
    context.pc = state.regs.pc;
    context.arch_regs = ArchRegState::Aarch64(Aarch64RegState::from_cpu_state(state).unwrap());
    context.flags.materialized =
        MaterializedFlags::from_nzcv((state.regs.pstate & 0xf000_0000) as u32);
    context
}

#[test]
fn pauth_smir_all_forms_match_direct_at_every_profile_feature_and_optimization() {
    let mut cases = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for enabled in [false, true] {
                for raw in forms() {
                    let mut direct = cpu(raw, algorithm, profile, enabled);
                    let initial = snapshot(&direct);
                    let result = direct.step();
                    let expected = snapshot(&direct);
                    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                        let mut function = function(&[raw], direct.config().features);
                        optimize_function(&mut function, level);
                        let mut context = context(&initial);
                        let mut memory = FlatMemory::new(0x10000);
                        memory.load(0x3008, &0xdead_beef_cafe_f00du64.to_le_bytes());
                        let exit = SmirInterpreter::new().execute_block(
                            &mut context,
                            &mut memory,
                            &function.blocks[0],
                        );
                        let label = format!(
                            "{raw:#010x} {algorithm:?} {profile:?} enabled={enabled} {level:?} {exit:?}"
                        );
                        match &result {
                            Ok(_) => {
                                assert!(
                                    matches!(
                                        exit,
                                        BlockResult::Continue(_)
                                            | BlockResult::Exit(ExitReason::Halt)
                                    ),
                                    "{label}"
                                );
                                assert_eq!(context.insn_count, 1, "{label}");
                            }
                            Err(ArmError::UndefinedInstruction(word)) => {
                                assert!(
                                    matches!(exit, BlockResult::Exit(ExitReason::Undefined { addr: PC, opcode }) if opcode == *word),
                                    "{label}"
                                );
                                assert_eq!(context.insn_count, 0, "{label}");
                            }
                            Err(ArmError::ArchitecturalException { ec, iss, target_el }) => {
                                assert!(
                                    matches!(exit, BlockResult::Exit(ExitReason::Aarch64Exception { pc: PC, ec: actual_ec, iss: actual_iss, target_el: actual_el }) if actual_ec == *ec && actual_iss == *iss && Some(actual_el) == *target_el),
                                    "{label}"
                                );
                                assert_eq!(context.insn_count, 0, "{label}");
                            }
                            Err(error) => panic!("unexpected fixture error {error:?}: {label}"),
                        }
                        let ArchRegState::Aarch64(actual) = &context.arch_regs else {
                            panic!("wrong architecture")
                        };
                        assert_eq!(
                            crate::codec::serialize(&actual.to_cpu_state().unwrap()).unwrap(),
                            crate::codec::serialize(&expected).unwrap(),
                            "{label}"
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 2208);
}

#[test]
fn pauth_smir_known_signatures_and_prior_retirement_survive_a_later_auth_fault() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        // MOV X0,#0; PACIA X0,X1; PACGA X2,XZR,X1; AUTIA X3,X1.
        let words = [0xd280_0000, 0xdac1_0020, 0x9ac1_33e2, 0xdac1_1023];
        let direct = cpu(
            words[0],
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
            true,
        );
        let mut context = context(&snapshot(&direct));
        let mut function = function(&words, direct.config().features);
        optimize_function(&mut function, level);
        let result = SmirInterpreter::new().execute_block(
            &mut context,
            &mut FlatMemory::new(0x10000),
            &function.blocks[0],
        );
        assert!(
            matches!(result, BlockResult::Exit(ExitReason::Aarch64Exception { pc, ec: 0x1c, iss: 0, .. }) if pc == PC + 12),
            "{level:?} {result:?}"
        );
        let ArchRegState::Aarch64(state) = context.arch_regs else {
            panic!("wrong architecture")
        };
        assert_eq!(state.x[0], 0xf916_0000_0000_0000, "{level:?}");
        assert_eq!(state.x[2], 0xf996_e761_0000_0000, "{level:?}");
        assert_eq!(state.x[3], 0x4030);
        assert_eq!(state.pc, PC + 12);
        assert_eq!(state.pstate & (3 << 10), 0);
        assert_eq!(context.insn_count, 3);
    }
}

#[test]
fn pauth_smir_feature_mismatch_missing_state_and_malformed_ir_exit_before_effects() {
    let direct = cpu(
        0xdac1_0020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
        true,
    );
    let initial = snapshot(&direct);
    for fault in 0..4 {
        let mut context = context(&initial);
        let mut function = function(&[0xdac1_0020], direct.config().features);
        match fault {
            0 => {
                let ArchRegState::Aarch64(state) = &mut context.arch_regs else {
                    panic!()
                };
                state
                    .system
                    .as_mut()
                    .unwrap()
                    .execution
                    .as_mut()
                    .unwrap()
                    .features &= !ArmFeatures::PACA.bits();
            }
            1 => {
                let ArchRegState::Aarch64(state) = &mut context.arch_regs else {
                    panic!()
                };
                state.system = None;
            }
            2 => {
                let OpKind::ArmPauth(ref mut operation) = function.blocks[0].ops[1].kind else {
                    panic!()
                };
                operation.raw ^= 1;
            }
            3 => {
                function.blocks[0].ops.remove(0);
            }
            _ => panic!(),
        }
        let exit = SmirInterpreter::new().execute_block(
            &mut context,
            &mut FlatMemory::new(0x10000),
            &function.blocks[0],
        );
        assert!(
            matches!(
                exit,
                BlockResult::Exit(ExitReason::Unsupported { addr: PC, .. })
            ),
            "{fault}: {exit:?}"
        );
        let ArchRegState::Aarch64(state) = &context.arch_regs else {
            panic!()
        };
        assert_eq!(state.x, initial.regs.x);
        assert_eq!(state.pstate_bits(), initial.regs.pstate);
        assert_eq!(context.insn_count, 0);
    }
}

#[test]
fn pauth_smir_instruction_budget_resumes_at_an_optimized_guest_boundary() {
    let words = [0xd280_0000, 0xdac1_0020, 0x9ac1_33e2];
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let direct = cpu(
            words[0],
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
            true,
        );
        let mut context = context(&snapshot(&direct));
        let mut function = function(&words, direct.config().features);
        optimize_function(&mut function, level);
        let mut interpreter = SmirInterpreter::new();
        interpreter.set_max_insns(1);
        interpreter.add_function(function);
        let mut memory = FlatMemory::new(0x10000);
        for expected in [PC + 4, PC + 8] {
            assert!(matches!(
                interpreter.run(&mut context, &mut memory),
                ExitReason::InsnLimit
            ));
            assert_eq!(context.pc, expected);
            assert_eq!(context.arch_regs.pc(), expected);
        }
        assert!(matches!(
            interpreter.run(&mut context, &mut memory),
            ExitReason::Halt
        ));
        assert_eq!(context.insn_count, 3);
        let ArchRegState::Aarch64(state) = context.arch_regs else {
            panic!()
        };
        assert_eq!(state.x[0], 0xf916_0000_0000_0000);
        assert_eq!(state.x[2], 0xf996_e761_0000_0000);
    }
}

#[test]
fn pauth_native_lowerers_require_the_scoped_helper_abi_and_validate_framing() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::aarch64::Aarch64Lowerer;
    use crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer;
    let direct = cpu(
        0xdac1_0020,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
        true,
    );
    let mut function = function(&[0xdac1_0020], direct.config().features);
    function.blocks[0].terminator = Terminator::Return { values: vec![] };
    assert!(!function.blocks[0].ops.iter().any(|op| op.is_jit_safe()));
    assert!(Aarch64Lowerer::new().lower_function(&function).is_err());
    assert!(
        Aarch64X86_64Lowerer::new()
            .lower_function(&function)
            .is_err()
    );
    let mut arm = Aarch64Lowerer::new();
    arm.set_pauth_helpers(true);
    assert!(arm.lower_function(&function).is_ok());
    let mut x86 = Aarch64X86_64Lowerer::new();
    x86.set_pauth_helpers(true);
    assert!(x86.lower_function(&function).is_ok());
    function.blocks[0].ops.remove(0);
    assert!(arm.lower_function(&function).is_err());
    assert!(x86.lower_function(&function).is_err());
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn pauth_native_all_forms_match_full_direct_state_at_o0_o1_o2() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    let mut cases = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for enabled in [false, true] {
                for raw in forms() {
                    let mut direct = cpu(raw, algorithm, profile, enabled);
                    let initial = snapshot(&direct);
                    let expected_exit = direct.step();
                    let expected = snapshot(&direct);
                    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                        let mut function = function(&[raw], direct.config().features);
                        if !matches!(
                            function.blocks[0].terminator,
                            Terminator::IndirectBranch { .. }
                        ) {
                            function.blocks[0].terminator = Terminator::Return { values: vec![] };
                        }
                        optimize_function(&mut function, level);
                        #[cfg(target_arch = "aarch64")]
                        let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
                        #[cfg(target_arch = "x86_64")]
                        let mut lowerer = crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
                        lowerer.set_pauth_helpers(true);
                        let lowered = lowerer.lower_function(&function).unwrap();
                        assert!(lowered.relocations.is_empty());
                        let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
                        let mut memory = FlatMemory::new(0x10000);
                        memory.load(0x3008, &0xdead_beef_cafe_f00du64.to_le_bytes());
                        let mut runtime = Aarch64PauthRuntime::new(
                            Aarch64RegState::from_cpu_state(&initial).unwrap(),
                            &mut memory,
                        )
                        .unwrap();
                        let mut registers = Aarch64GuestRegs::default();
                        let result = runtime.run(&mut registers, |registers| {
                            #[cfg(target_arch = "aarch64")]
                            executable.run_aarch64_identity(lowered.entry_offset, registers);
                            #[cfg(target_arch = "x86_64")]
                            executable.run_aarch64(lowered.entry_offset, registers);
                        });
                        let label = format!(
                            "{raw:#010x} {algorithm:?} {profile:?} enabled={enabled} {level:?}: {result:?}"
                        );
                        match &expected_exit {
                            Ok(_) => {
                                assert!(result.is_ok(), "{label}");
                                assert_eq!(runtime.retired, 1, "{label}");
                            }
                            Err(ArmError::UndefinedInstruction(word)) => {
                                assert!(
                                    matches!(result, Err(ExitReason::Undefined { addr: PC, opcode }) if opcode == *word),
                                    "{label}"
                                );
                                assert_eq!(runtime.retired, 0, "{label}");
                            }
                            Err(ArmError::ArchitecturalException { ec, iss, target_el }) => {
                                assert!(
                                    matches!(result, Err(ExitReason::Aarch64Exception { pc: PC, ec: actual_ec, iss: actual_iss, target_el: actual_el }) if actual_ec == *ec && actual_iss == *iss && Some(actual_el) == *target_el),
                                    "{label}"
                                );
                                assert_eq!(runtime.retired, 0, "{label}");
                            }
                            Err(error) => panic!("unexpected fixture error {error:?}: {label}"),
                        }
                        assert_eq!(
                            crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
                            crate::codec::serialize(&expected).unwrap(),
                            "{label}"
                        );
                        assert_eq!(registers.pauth_context, 0);
                        assert_eq!(registers.pauth_fn, 0);
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 2208);
}

#[test]
fn pauth_smir_authenticated_load_offsets_writeback_zero_register_and_byte_order() {
    let mut cases = 0;
    for key_b in [false, true] {
        for writeback in [false, true] {
            for base in [0, 31] {
                for destination in [6, 31] {
                    for offset in [-4096i64, -8, 0, 8, 4088] {
                        for big_endian in [false, true] {
                            let immediate = (offset / 8) as u32 & 0x3ff;
                            let raw = 0xf820_0400
                                | (u32::from(key_b) << 23)
                                | ((immediate >> 9) << 22)
                                | ((immediate & 0x1ff) << 12)
                                | (u32::from(writeback) << 11)
                                | (base << 5)
                                | destination;
                            let mut direct =
                                cpu(raw, PauthAlgorithm::Qarma5, PauthProfile::FpacCombine, true);
                            let mut controls = direct.pauth_controls();
                            controls.sctlr[1] |= u64::from(big_endian) << 25;
                            direct.set_pauth_controls(controls).unwrap();
                            let pointer = controls.layout(0x3000, true).sign(
                                PauthAlgorithm::Qarma5,
                                PauthProfile::FpacCombine,
                                0x3000,
                                0,
                                if key_b {
                                    direct.pauth_keys().db
                                } else {
                                    direct.pauth_keys().da
                                },
                            );
                            if base == 31 {
                                direct.set_current_sp(pointer);
                            } else {
                                direct.set_x(base as u8, pointer);
                            }
                            let address = 0x3000u64.wrapping_add(offset as u64);
                            let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
                            direct.write_memory(address, &bytes).unwrap();
                            let initial = snapshot(&direct);
                            direct.step().unwrap();
                            let expected = snapshot(&direct);
                            if destination != 31 {
                                assert_eq!(
                                    expected.regs.x[destination as usize],
                                    if big_endian {
                                        u64::from_be_bytes(bytes)
                                    } else {
                                        u64::from_le_bytes(bytes)
                                    }
                                );
                            }
                            if writeback {
                                assert_eq!(
                                    if base == 31 {
                                        expected.regs.sp
                                    } else {
                                        expected.regs.x[base as usize]
                                    },
                                    address
                                );
                            }
                            for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                                let mut function = function(&[raw], direct.config().features);
                                optimize_function(&mut function, level);
                                let mut context = context(&initial);
                                let mut memory = FlatMemory::new(0x10000);
                                memory.load(address as usize, &bytes);
                                let result = SmirInterpreter::new().execute_block(
                                    &mut context,
                                    &mut memory,
                                    &function.blocks[0],
                                );
                                assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
                                let ArchRegState::Aarch64(state) = context.arch_regs else {
                                    panic!()
                                };
                                assert_eq!(
                                    crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
                                    crate::codec::serialize(&expected).unwrap(),
                                    "{raw:#x} BE={big_endian} {level:?}"
                                );
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 480);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn pauth_native_helpers_preserve_live_vectors_fpcr_fpsr_across_success_and_fault() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::aarch64::{Aarch64Lowerer, uses_aarch64_fp_trampoline};
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    // FADD D0,D0,D1; PACIA X0,X1; FADD D2,D0,D1; AUTIA X3,X1 (fails).
    let words = [0x1e61_2800u32, 0xdac1_0020, 0x1e61_2802, 0xdac1_1023];
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let mut direct = cpu(
            words[0],
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
            true,
        );
        let mut system = direct.export_sregs();
        system.execution.as_mut().unwrap().sysregs.el1.cpacr = 3 << 20;
        direct.import_sregs(&system).unwrap();
        direct.set_simd(0, 0x3ff0_0000_0000_0000); // 1.0.
        direct.set_simd(1, 0x4000_0000_0000_0000); // 2.0.
        direct.set_fpcr_value((1 << 25) | (1 << 24)); // DN/FZ survive helper calls.
        direct.set_fpsr_value(0x0800_009f); // Existing cumulative status survives.
        for (index, raw) in words.iter().enumerate() {
            direct
                .write_memory(PC + index as u64 * 4, &raw.to_le_bytes())
                .unwrap();
        }
        let initial = snapshot(&direct);
        for _ in 0..3 {
            direct.step().unwrap();
        }
        assert!(matches!(
            direct.step(),
            Err(ArmError::ArchitecturalException { ec: 0x1c, .. })
        ));
        let expected = snapshot(&direct);
        assert_eq!(expected.regs.v[0][0], 0x4008_0000_0000_0000); // 3.0.
        assert_eq!(expected.regs.v[2][0], 0x4014_0000_0000_0000); // 5.0.
        let mut function = function(&words, direct.config().features);
        function.blocks[0].terminator = Terminator::Return { values: vec![] };
        optimize_function(&mut function, level);
        assert!(uses_aarch64_fp_trampoline(&function));
        let mut lowerer = Aarch64Lowerer::new();
        lowerer.set_pauth_helpers(true);
        let lowered = lowerer.lower_function(&function).unwrap();
        let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
        let mut memory = FlatMemory::new(0x10000);
        let mut runtime = Aarch64PauthRuntime::new(
            Aarch64RegState::from_cpu_state(&initial).unwrap(),
            &mut memory,
        )
        .unwrap();
        let result = runtime.run(&mut Aarch64GuestRegs::default(), |registers| {
            executable.run_aarch64_identity_fp(lowered.entry_offset, registers);
        });
        assert!(
            matches!(result, Err(ExitReason::Aarch64Exception { pc, ec: 0x1c, .. }) if pc == PC + 12),
            "{level:?}: {result:?}"
        );
        assert_eq!(runtime.retired, 3);
        assert_eq!(
            crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
            crate::codec::serialize(&expected).unwrap(),
            "{level:?}"
        );
    }
}
