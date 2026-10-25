//! A real backedge with two loop predecessors, live guest values and NZCV
//! across helper calls, and an authentication fault after prior iterations.

use super::*;
use crate::smir::ir::memory::MemoryError;
use crate::smir::lift::MemoryReader;

const ENTRY: u64 = PC - 4;
const END: u64 = PC + 20;
const WORDS: [u32; 6] = [
    0x1400_0001, // B loop
    0xdac1_0020, // loop: PACIA X0,X1
    0xf100_0442, // SUBS X2,X2,#1
    0x9a84_1000, // CSEL X0,X0,X4,NE
    0xdac1_1020, // AUTIA X0,X1
    0x54ff_ff81, // B.NE loop
];

struct Code(Vec<u8>);
impl MemoryReader for Code {
    fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = address
            .checked_sub(ENTRY)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(MemoryError::OutOfBounds { addr: address })?;
        self.0
            .get(offset..offset + size)
            .map(<[u8]>::to_vec)
            .ok_or(MemoryError::OutOfBounds { addr: address })
    }
}

fn fixture(algorithm: PauthAlgorithm, profile: PauthProfile, bad: bool) -> AArch64Cpu {
    let mut direct = cpu(WORDS[1], algorithm, profile, true);
    for (index, raw) in WORDS.into_iter().enumerate() {
        direct
            .write_memory(ENTRY + index as u64 * 4, &raw.to_le_bytes())
            .unwrap();
    }
    direct.set_pc(ENTRY);
    direct.set_x(0, 0);
    direct.set_x(1, 1);
    direct.set_x(2, 5);
    // Independent QEMU address-signing values for pointer=0, modifier=1,
    // key Lo=MAX, key Hi=0x0123456789abcdef (also checked by the C oracle).
    direct.set_x(
        4,
        if bad {
            0
        } else {
            match algorithm {
                PauthAlgorithm::Qarma3 => 0xa02d_0000_0000_0000,
                PauthAlgorithm::Qarma5 => 0xf916_0000_0000_0000,
            }
        },
    );
    direct
}

fn cfg(features: ArmFeatures, level: OptLevel) -> SmirFunction {
    let code = Code(WORDS.into_iter().flat_map(u32::to_le_bytes).collect());
    let mut context = LiftContext::new(SourceArch::Aarch64);
    context.aarch64_features = Some(features);
    let mut lifter = Aarch64Lifter::strict();
    let entry = lifter.lift_block(ENTRY, &code, &mut context).unwrap();
    let loop_body = lifter.lift_block(PC, &code, &mut context).unwrap();
    let mut exit = SmirBlock::new(context.get_or_create_block(END), END);
    exit.terminator = Terminator::Return { values: vec![] };
    let mut function = SmirFunction::new(FunctionId(0), entry.id, ENTRY);
    function.add_block(entry);
    function.add_block(loop_body);
    function.add_block(exit);
    optimize_function(&mut function, level);
    function
}

fn cases(mut check: impl FnMut(&Aarch64CpuState, &SmirFunction, &Aarch64CpuState, bool, u64)) {
    let mut count = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for bad in [false, true] {
                let mut direct = fixture(algorithm, profile, bad);
                let initial = snapshot(&direct);
                let fault =
                    bad && matches!(profile, PauthProfile::Fpac | PauthProfile::FpacCombine);
                let retired = if fault { 24 } else { 26 };
                let mut saw_fault = false;
                for _ in 0..30 {
                    match direct.step() {
                        Ok(_) => {
                            if direct.get_pc() == END {
                                break;
                            }
                        }
                        Err(ArmError::ArchitecturalException {
                            ec: 0x1c,
                            iss: 0,
                            target_el: Some(1),
                        }) => {
                            saw_fault = true;
                            break;
                        }
                        other => panic!("unexpected direct result {other:?}"),
                    }
                }
                assert_eq!(saw_fault, fault);
                assert_eq!(direct.instruction_count(), retired);
                assert_eq!(direct.nzcv_bits(), 6);
                assert_eq!(direct.get_x(2), 0);
                if !bad {
                    assert_eq!(direct.get_x(0), 0);
                }
                let expected = snapshot(&direct);
                for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                    check(
                        &initial,
                        &cfg(direct.config().features, level),
                        &expected,
                        fault,
                        retired,
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 48);
}

#[test]
fn pauth_cfg_loop_and_precise_fault_match_direct_at_o0_o1_o2() {
    cases(|initial, function, expected, fault, retired| {
        let mut interpreter = SmirInterpreter::new();
        interpreter.add_function(function.clone());
        interpreter.set_max_insns(100);
        let mut context = context(initial);
        let result = interpreter.run(&mut context, &mut FlatMemory::new(0x10000));
        if fault {
            assert!(
                matches!(result, ExitReason::Aarch64Exception { pc, ec: 0x1c, iss: 0, target_el: 1 } if pc == PC + 12),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(result, ExitReason::Return { to } if to == expected.regs.x[30]),
                "{result:?}"
            );
        }
        assert_eq!(context.insn_count, retired);
        let ArchRegState::Aarch64(state) = context.arch_regs else {
            panic!("state");
        };
        assert_eq!(
            crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
            crate::codec::serialize(expected).unwrap()
        );
    });
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn pauth_cfg_native_loop_and_precise_fault_match_direct_at_o0_o1_o2() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    cases(|initial, function, expected, fault, retired| {
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
        runtime.instruction_limit = 100;
        let result = runtime.run(&mut Aarch64GuestRegs::default(), |registers| {
            #[cfg(target_arch = "aarch64")]
            code.run_aarch64_identity(lowered.entry_offset, registers);
            #[cfg(target_arch = "x86_64")]
            code.run_aarch64(lowered.entry_offset, registers);
        });
        if fault {
            assert!(
                matches!(result, Err(ExitReason::Aarch64Exception { pc, ec: 0x1c, iss: 0, target_el: 1 }) if pc == PC + 12),
                "{result:?}"
            );
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
        assert_eq!(runtime.retired, retired);
        assert_eq!(
            crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
            crate::codec::serialize(expected).unwrap()
        );
    });
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn pauth_cfg_native_retains_an_architectural_branch_condition_destination() {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    let direct = fixture(PauthAlgorithm::Qarma5, PauthProfile::FpacCombine, false);
    let mut function = cfg(direct.config().features, OptLevel::O0);
    let block = function
        .blocks
        .iter_mut()
        .find(|block| block.guest_pc == PC)
        .unwrap();
    let Terminator::CondBranch { cond, .. } = &mut block.terminator else {
        panic!("condition");
    };
    let previous = *cond;
    let architectural = VReg::Arch(ArchReg::Arm(ArmReg::X(5)));
    let mut replaced = false;
    for op in &mut block.ops {
        if let OpKind::TestCondition { dst, .. } = &mut op.kind {
            if *dst == previous {
                *dst = architectural;
                replaced = true;
            }
        }
    }
    assert!(replaced);
    *cond = architectural;
    let initial = snapshot(&direct);
    let mut interpreter = SmirInterpreter::new();
    interpreter.add_function(function.clone());
    let mut context = context(&initial);
    let result = interpreter.run(&mut context, &mut FlatMemory::new(0x10000));
    assert!(matches!(result, ExitReason::Return { .. }));
    let ArchRegState::Aarch64(expected) = context.arch_regs else {
        panic!("state");
    };
    assert_eq!(expected.x[5], 0);
    assert_ne!(initial.regs.x[5], expected.x[5]);
    #[cfg(target_arch = "aarch64")]
    let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
    #[cfg(target_arch = "x86_64")]
    let mut lowerer =
        crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
    lowerer.set_pauth_helpers(true);
    let lowered = lowerer.lower_function(&function).unwrap();
    let code = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
    let mut memory = FlatMemory::new(0x10000);
    let mut runtime = Aarch64PauthRuntime::new(
        Aarch64RegState::from_cpu_state(&initial).unwrap(),
        &mut memory,
    )
    .unwrap();
    runtime.instruction_limit = 100;
    runtime
        .run(&mut Aarch64GuestRegs::default(), |registers| {
            #[cfg(target_arch = "aarch64")]
            code.run_aarch64_identity(lowered.entry_offset, registers);
            #[cfg(target_arch = "x86_64")]
            code.run_aarch64(lowered.entry_offset, registers);
        })
        .unwrap();
    assert_eq!(runtime.retired, 26);
    assert_eq!(
        crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
        crate::codec::serialize(&expected.to_cpu_state().unwrap()).unwrap()
    );
}
