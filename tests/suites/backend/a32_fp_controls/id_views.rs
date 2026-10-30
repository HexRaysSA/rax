//! The architectural MVFR aliases must describe the same physical FP profile.
use super::*;
use rax::isa::arm::common::features::ArmFeatures;
use rax::smir::ir::context::Aarch64RegState;
use rax::vm::vcpu::{Aarch64CpuState, Aarch64Registers};

const MRS: [u32; 3] = [0xd5380300, 0xd5380321, 0xd5380342];
const VMRS: [u32; 3] = [0xeef70a10, 0xeef61a10, 0xeef52a10];
fn expected(half: bool) -> [u64; 3] {
    [0x10110222, if half { 0x13211111 } else { 0x12111111 }, 0x43]
}
fn cpu(half: bool) -> AArch64Cpu {
    let mut config = AArch64Config {
        initial_el: 3,
        gic_config: None,
        ..Default::default()
    };
    config.features.set(ArmFeatures::FP16, half);
    let mut cpu = AArch64Cpu::new(config, Box::new(Memory64::new(0, 0x4000)));
    let mut state = cpu.export_sregs();
    let system = &mut state.execution.as_mut().unwrap().sysregs;
    system.scr_el3 = 1 | (1 << 10);
    system.hcr_el2 = 0;
    system.el1.cpacr = 3 << 20;
    system
        .impl_defined
        .insert(Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(), 1 << 30);
    cpu.import_sregs(&state).unwrap();
    cpu
}
fn words(cpu: &mut AArch64Cpu, words: &[u32], thumb: bool) {
    cpu.set_pc(0x100);
    for (i, &word) in words.iter().enumerate() {
        let bytes = if thumb {
            [
                ((word >> 16) as u16).to_le_bytes(),
                (word as u16).to_le_bytes(),
            ]
            .concat()
        } else {
            word.to_le_bytes().to_vec()
        };
        cpu.write_memory(0x100 + i as u64 * 4, &bytes).unwrap();
    }
}
#[test]
fn a64_mrs_and_arm_thumb_vmrs_share_the_selected_fp_profile() {
    for half in [false, true] {
        for thumb in [false, true] {
            let mut cpu = cpu(half);
            words(&mut cpu, &MRS, false);
            for (index, expected) in expected(half).into_iter().enumerate() {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(
                    cpu.get_x(index as u8),
                    expected,
                    "A64 MVFR{index}, half={half}"
                );
            }
            cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
                .unwrap();
            words(&mut cpu, &VMRS, thumb);
            for (index, expected) in expected(half).into_iter().enumerate() {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(
                    cpu.get_x(index as u8) as u32,
                    expected as u32,
                    "A32 MVFR{index}, half={half}, Thumb={thumb}"
                );
            }
        }
    }
}
#[test]
fn mvfr_aliases_agree_in_saved_state_and_smir_and_after_reset() {
    for half in [false, true] {
        let mut cpu = cpu(half);
        for reset in [false, true] {
            if reset {
                cpu.reset();
            }
            let state = Aarch64CpuState {
                regs: Aarch64Registers {
                    pstate: cpu.pstate_bits(),
                    ..Default::default()
                },
                sregs: cpu.export_sregs(),
            };
            let ir = Aarch64RegState::from_cpu_state(&state).unwrap();
            for (index, expected) in expected(half).into_iter().enumerate() {
                let encoding = Aarch64SysRegEncoding::new(3, 0, 0, 3, index as u8);
                assert_eq!(
                    state
                        .sregs
                        .execution
                        .as_ref()
                        .unwrap()
                        .sysregs
                        .read(encoding, 3),
                    Some(expected)
                );
                assert_eq!(ir.read_system_register(encoding.encode()), Some(expected));
            }
        }
    }
}
#[test]
fn guest_writes_to_mvfr_aliases_are_undefined_before_any_state_change() {
    for index in 0..3 {
        let mut cpu = cpu(true);
        let word = MRS[index] & !(1 << 21);
        words(&mut cpu, &[word], false);
        cpu.set_x(index as u8, u64::MAX);
        let before = cpu.export_sregs();
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(actual)) if actual == word)
        );
        assert_eq!(cpu.get_pc(), 0x100);
        assert_eq!(cpu.instruction_count(), 0);
        assert_eq!(cpu.export_sregs(), before);
    }
}
#[test]
fn ns_el1_tid3_traps_mvfr_alias_reads_with_complete_iss_and_no_effects() {
    for index in 0..3 {
        let mut cpu = cpu(true);
        let mut state = cpu.export_sregs();
        state.execution.as_mut().unwrap().sysregs.hcr_el2 = (1 << 31) | (1 << 18);
        cpu.import_sregs(&state).unwrap();
        cpu.set_pstate_bits(0x3c5).unwrap();
        words(&mut cpu, &[MRS[index]], false);
        cpu.set_x(index as u8, 0xface1234);
        let expected_iss =
            (3 << 20) | ((index as u32) << 17) | ((index as u32) << 5) | (3 << 1) | 1;
        assert!(
            matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec: 0x18, iss, target_el: Some(2) }) if iss == expected_iss)
        );
        assert_eq!(cpu.get_pc(), 0x100);
        assert_eq!(cpu.get_x(index as u8), 0xface1234);
        assert_eq!(cpu.instruction_count(), 0);
    }
}

fn profile(cpu: &mut AArch64Cpu, ids: [u64; 3]) {
    let mut state = cpu.export_sregs();
    let sysregs = &mut state.execution.as_mut().unwrap().sysregs;
    for (index, value) in ids.into_iter().enumerate() {
        sysregs.impl_defined.insert(
            Aarch64SysRegEncoding::new(3, 0, 0, 3, index as u8).encode(),
            value,
        );
    }
    cpu.import_sregs(&state).unwrap();
}

#[test]
fn trusted_profile_is_zero_extended_and_preserved_across_fresh_cpu_restore() {
    // Deliberately reduced scalar/SIMD capabilities, with nonzero host upper bits.
    let ids = [0xaabbccdd10110021, 0xaabbccdd11000011, 0xaabbccdd00000000];
    let mut source = cpu(true);
    profile(&mut source, ids);
    let saved = source.export_sregs();
    let mut restored = cpu(false);
    restored.import_sregs(&saved).unwrap();
    for mut cpu in [source, restored] {
        words(&mut cpu, &MRS, false);
        for (index, value) in ids.into_iter().enumerate() {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(index as u8), u64::from(value as u32));
        }
        cpu.set_pstate_bits(0x1d3).unwrap();
        words(&mut cpu, &VMRS, false);
        for (index, value) in ids.into_iter().enumerate() {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(index as u8) as u32, value as u32);
        }
    }
}

#[test]
fn half_capability_upper_bound_preserves_absent_and_reserved_field_values() {
    for half in [false, true] {
        for (shift, full, conversion) in [(24, 3, 2), (20, 2, 1)] {
            for value in 0..16 {
                let mut cpu = cpu(half);
                let mut ids = expected(true);
                ids[1] = (ids[1] & !(15 << shift)) | (value << shift);
                profile(&mut cpu, ids);
                let effective = if !half && value == full {
                    conversion
                } else {
                    value
                };
                let state = cpu.export_sregs();
                let read = state
                    .execution
                    .as_ref()
                    .unwrap()
                    .sysregs
                    .read(Aarch64SysRegEncoding::new(3, 0, 0, 3, 1), 3)
                    .unwrap();
                assert_eq!(
                    (read >> shift) & 15,
                    effective,
                    "half={half}, shift={shift}, value={value}"
                );
            }
        }
    }
}

#[test]
fn read_only_profile_rejects_internal_and_smir_writes_without_mutation() {
    let cpu = cpu(true);
    let mut state = Aarch64CpuState {
        regs: Aarch64Registers {
            pstate: cpu.pstate_bits(),
            ..Default::default()
        },
        sregs: cpu.export_sregs(),
    };
    let mut ir = Aarch64RegState::from_cpu_state(&state).unwrap();
    for index in 0..3 {
        let encoding = Aarch64SysRegEncoding::new(3, 0, 0, 3, index);
        let before = state.sregs.clone();
        assert!(
            !state
                .sregs
                .execution
                .as_mut()
                .unwrap()
                .sysregs
                .write(encoding, u64::MAX, 3)
        );
        assert_eq!(state.sregs, before);
        let before = ir.read_system_register(encoding.encode());
        assert!(!ir.write_system_register(encoding.encode(), u64::MAX));
        assert_eq!(ir.read_system_register(encoding.encode()), before);
    }
}

#[test]
fn mixed_width_instruction_admission_uses_the_reported_profile_before_access_traps() {
    for thumb in [false, true] {
        for denied_access in [false, true] {
            for (index, shift, arm, thumb_word) in [
                (0, 8, 0xee300b00, 0xee300b00),  // FPDP: VADD.F64 D0,D0,D0.
                (1, 16, 0xf2020d44, 0xef020d44), // SIMDSP: VADD.F32 Q0,Q1,Q2.
                (1, 12, 0xf2020844, 0xef020844), // SIMDInt: VADD.I8 Q0,Q1,Q2.
            ] {
                let mut cpu = cpu(true);
                let mut ids = expected(true);
                ids[index] &= !(15 << shift);
                profile(&mut cpu, ids);
                if denied_access {
                    let mut state = cpu.export_sregs();
                    state.execution.as_mut().unwrap().sysregs.el1.cpacr = 0;
                    cpu.import_sregs(&state).unwrap();
                }
                cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
                    .unwrap();
                let word = if thumb { thumb_word } else { arm };
                words(&mut cpu, &[word], thumb);
                for register in 0..32 {
                    cpu.set_simd(register, 0x3ff00000_3f800000_40000000_3f800000);
                }
                let before = cpu.export_sregs();
                let registers: Vec<_> = (0..31).map(|i| cpu.get_x(i)).collect();
                let simd: Vec<_> = (0..32).map(|i| cpu.get_simd(i)).collect();
                let fp = (cpu.fpcr_value(), cpu.fpsr_value());
                assert!(
                    matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))),
                    "index={index}, shift={shift}, thumb={thumb}, access denied={denied_access}"
                );
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
                assert_eq!(cpu.export_sregs(), before);
                assert_eq!((0..32).map(|i| cpu.get_simd(i)).collect::<Vec<_>>(), simd);
                assert_eq!((cpu.fpcr_value(), cpu.fpsr_value()), fp);
                assert_eq!((0..31).map(|i| cpu.get_x(i)).collect::<Vec<_>>(), registers);
            }
        }
    }
}

#[test]
fn a64_mvfr_id_reads_do_not_require_fp_data_access_permission() {
    for el in [1_u8, 2, 3] {
        let mut cpu = cpu(true);
        let mut state = cpu.export_sregs();
        let sysregs = &mut state.execution.as_mut().unwrap().sysregs;
        sysregs.hcr_el2 = 1 << 31;
        sysregs.el1.cpacr = 0;
        for op1 in [4, 6] {
            sysregs.impl_defined.insert(
                Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(),
                1 << 10,
            );
        }
        cpu.import_sregs(&state).unwrap();
        cpu.set_pstate_bits(0x3c1 | (u64::from(el) << 2)).unwrap();
        words(&mut cpu, &MRS, false);
        for (index, value) in expected(true).into_iter().enumerate() {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(index as u8), value);
        }
    }
}

#[test]
fn tid3_respects_el2_presence_security_and_vhe_host_controls() {
    for el2 in [false, true] {
        for secure in [false, true] {
            for vhe in [false, true] {
                for e2h in [false, true] {
                    for tge in [false, true] {
                        let mut cpu = cpu(true);
                        let mut state = cpu.export_sregs();
                        let execution = state.execution.as_mut().unwrap();
                        execution.features = ArmFeatures::from_bits_retain(execution.features)
                            .union(if vhe {
                                ArmFeatures::VHE
                            } else {
                                ArmFeatures::empty()
                            })
                            .bits();
                        let sysregs = &mut execution.sysregs;
                        sysregs.id_aa64pfr0_el1 &= !(15 << 8);
                        if el2 {
                            sysregs.id_aa64pfr0_el1 |= 1 << 8;
                        }
                        sysregs.scr_el3 = (1 << 10) | u64::from(!secure);
                        sysregs.hcr_el2 =
                            (1 << 31) | (1 << 18) | (u64::from(e2h) << 34) | (u64::from(tge) << 27);
                        cpu.import_sregs(&state).unwrap();
                        cpu.set_pstate_bits(0x3c5).unwrap();
                        words(&mut cpu, &[MRS[0]], false);
                        let result = cpu.step();
                        let traps = el2 && !secure && !(vhe && e2h && tge);
                        assert_eq!(
                            matches!(
                                result,
                                Err(ArmError::ArchitecturalException {
                                    ec: 0x18,
                                    target_el: Some(2),
                                    ..
                                })
                            ),
                            traps,
                            "EL2={el2}, secure={secure}, VHE={vhe}, E2H={e2h}, TGE={tge}: {result:?}"
                        );
                        if !traps {
                            assert_eq!(result.unwrap(), CpuExit::Continue);
                        }
                    }
                }
            }
        }
    }
}
