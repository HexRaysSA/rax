//! Successful authentication complements the unsigned/corrupt-pointer matrix.

use super::*;
use crate::isa::arm::aarch64::pauth::PauthKeyKind;
use crate::isa::arm::aarch64::pauth_instruction::{PauthInstruction, PauthModifier};

fn prepare(cpu: &mut AArch64Cpu, raw: u32) {
    let keys = PauthKeys {
        ia: PauthKey { lo: 1, hi: 2 },
        ib: PauthKey { lo: 3, hi: 4 },
        da: PauthKey { lo: 5, hi: 6 },
        db: PauthKey { lo: 7, hi: 8 },
        ga: PauthKey { lo: 9, hi: 10 },
    };
    cpu.set_pauth_keys(keys);
    let state = snapshot(cpu);
    let controls = cpu.pauth_controls();
    let config = cpu.config().pauth;
    let modifier = |value| match value {
        PauthModifier::Zero => 0,
        PauthModifier::Sp => state.regs.sp,
        PauthModifier::Register(index) => state.regs.x[usize::from(index)],
    };
    // Input preparation uses the separately oracle-verified primitive. The
    // observed targets/restored pointers below are fixed architectural values.
    let signed = |pointer, value, key: PauthKeyKind| {
        controls.layout(pointer, key.data()).sign(
            config.algorithm,
            config.profile,
            pointer,
            value,
            keys.get(key),
        )
    };
    match PauthInstruction::decode(raw).unwrap() {
        PauthInstruction::Authenticate {
            dst,
            modifier: value,
            key,
            ..
        } => {
            cpu.set_x(dst, signed(0x4000, modifier(value), key));
        }
        PauthInstruction::Strip { dst, data, .. } => {
            let key = if data {
                PauthKeyKind::Da
            } else {
                PauthKeyKind::Ia
            };
            cpu.set_x(dst, signed(0x4000, 1, key));
        }
        PauthInstruction::Branch {
            target,
            modifier: value,
            key_b,
            ..
        } => {
            cpu.set_x(
                target,
                signed(
                    0x4000,
                    modifier(value),
                    if key_b {
                        PauthKeyKind::Ib
                    } else {
                        PauthKeyKind::Ia
                    },
                ),
            );
        }
        PauthInstruction::Return { key_b } => {
            cpu.set_x(
                30,
                signed(
                    0x4000,
                    state.regs.sp,
                    if key_b {
                        PauthKeyKind::Ib
                    } else {
                        PauthKeyKind::Ia
                    },
                ),
            );
        }
        PauthInstruction::ExceptionReturn { key_b } => {
            let mut system = cpu.export_sregs();
            system.elr_el1 = signed(
                0x5000,
                state.regs.sp,
                if key_b {
                    PauthKeyKind::Ib
                } else {
                    PauthKeyKind::Ia
                },
            );
            cpu.import_sregs(&system).unwrap();
        }
        PauthInstruction::Load { base, key_b, .. } => {
            let pointer = signed(
                0x3000,
                0,
                if key_b {
                    PauthKeyKind::Db
                } else {
                    PauthKeyKind::Da
                },
            );
            if base == 31 {
                cpu.set_current_sp(pointer);
            } else {
                cpu.set_x(base, pointer);
            }
        }
        PauthInstruction::Sign { .. } | PauthInstruction::Generic { .. } => {}
    }
}

#[test]
fn pauth_successful_authentication_all_forms_and_distinct_keys_match_all_planes() {
    use crate::smir::lower::SmirLowerer;
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    let mut interpreted = 0;
    let mut native = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for raw in forms() {
                let mut direct = cpu(raw, algorithm, profile, true);
                prepare(&mut direct, raw);
                let initial = snapshot(&direct);
                direct.step().unwrap();
                match PauthInstruction::decode(raw).unwrap() {
                    PauthInstruction::Authenticate { dst, .. }
                    | PauthInstruction::Strip { dst, .. } => {
                        assert_eq!(direct.get_x(dst), 0x4000);
                    }
                    PauthInstruction::Branch { link, .. } => {
                        assert_eq!(direct.get_pc(), 0x4000);
                        if link {
                            assert_eq!(direct.get_x(30), PC + 4);
                        }
                    }
                    PauthInstruction::Return { .. } => assert_eq!(direct.get_pc(), 0x4000),
                    PauthInstruction::ExceptionReturn { .. } => {
                        assert_eq!(direct.get_pc(), 0x5000);
                        assert_eq!(direct.pstate_bits(), 0x6000_0000);
                    }
                    PauthInstruction::Load { dst, .. } => {
                        assert_eq!(direct.get_x(dst), 0xdead_beef_cafe_f00d)
                    }
                    _ => {}
                }
                let expected = snapshot(&direct);
                for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                    let mut function = function(&[raw], direct.config().features);
                    optimize_function(&mut function, level);
                    let mut context = context(&initial);
                    let mut memory = FlatMemory::new(0x10000);
                    memory.load(0x3008, &0xdead_beef_cafe_f00du64.to_le_bytes());
                    let result = SmirInterpreter::new().execute_block(
                        &mut context,
                        &mut memory,
                        &function.blocks[0],
                    );
                    assert!(
                        matches!(
                            result,
                            BlockResult::Continue(_) | BlockResult::Exit(ExitReason::Halt)
                        ),
                        "{raw:#x}: {result:?}"
                    );
                    let ArchRegState::Aarch64(state) = context.arch_regs else {
                        panic!()
                    };
                    assert_eq!(
                        crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
                        crate::codec::serialize(&expected).unwrap()
                    );
                    assert_eq!(context.insn_count, 1);
                    if matches!(
                        PauthInstruction::decode(raw),
                        Some(PauthInstruction::ExceptionReturn { .. })
                    ) {
                        assert!(state.event_register);
                    }
                    interpreted += 1;
                    #[cfg(all(
                        feature = "smir-jit",
                        any(target_arch = "aarch64", target_arch = "x86_64")
                    ))]
                    {
                        if !matches!(
                            function.blocks[0].terminator,
                            Terminator::IndirectBranch { .. }
                        ) {
                            function.blocks[0].terminator = Terminator::Return { values: vec![] };
                        }
                        #[cfg(target_arch = "aarch64")]
                        let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
                        #[cfg(target_arch = "x86_64")]
                        let mut lowerer = crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
                        lowerer.set_pauth_helpers(true);
                        let lowered = lowerer.lower_function(&function).unwrap();
                        let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
                        let mut runtime = Aarch64PauthRuntime::new(
                            Aarch64RegState::from_cpu_state(&initial).unwrap(),
                            &mut memory,
                        )
                        .unwrap();
                        runtime
                            .run(&mut Aarch64GuestRegs::default(), |registers| {
                                #[cfg(target_arch = "aarch64")]
                                executable.run_aarch64_identity(lowered.entry_offset, registers);
                                #[cfg(target_arch = "x86_64")]
                                executable.run_aarch64(lowered.entry_offset, registers);
                            })
                            .unwrap();
                        assert_eq!(runtime.retired, 1);
                        assert_eq!(
                            crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap())
                                .unwrap(),
                            crate::codec::serialize(&expected).unwrap(),
                            "{raw:#x} {algorithm:?} {profile:?} {level:?}"
                        );
                        native += 1;
                    }
                }
            }
        }
    }
    assert_eq!(interpreted, 1104);
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    assert_eq!(native, 1104);
    #[cfg(not(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    assert_eq!(native, 0);
}
