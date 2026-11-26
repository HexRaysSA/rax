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
fn mixed_width_pure_simd_half_keeps_fpscr_across_instruction_boundaries() {
    const FZ16: u64 = 1 << 19;
    const AHP: u64 = 1 << 26;
    const VMSR: u32 = 0xeee1_1a10; // VMSR FPSCR,R1.
    const VMRS: u32 = 0xeef1_2a10; // VMRS R2,FPSCR.

    for thumb in [false, true] {
        let mut cpu = cpu(true);
        let mut state = cpu.export_sregs();
        let sysregs = &mut state.execution.as_mut().unwrap().sysregs;
        // Retain the D32 bank and pure SIMD FP16. Omit scalar FP and SIMD FP32.
        for (index, value) in [(0, 0x1011_0002), (1, 0x1020_1111)] {
            sysregs.impl_defined.insert(
                Aarch64SysRegEncoding::new(3, 0, 0, 3, index).encode(),
                value,
            );
        }
        cpu.import_sregs(&state).unwrap();
        cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
            .unwrap();
        let add = if thumb { 0xef12_0d44 } else { 0xf212_0d44 };
        words(&mut cpu, &[VMSR, add, VMRS], thumb);
        cpu.set_x(1, AHP | FZ16);
        cpu.set_simd(1, 0x7c00_0001);
        cpu.set_simd(2, 0xfc00_0000);

        for _ in 0..3 {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        }
        assert_eq!(cpu.get_simd(0), 0x7e00_0000);
        assert_eq!(cpu.get_x(2), FZ16 | 1);
        assert_eq!(cpu.instruction_count(), 3);
    }
}

#[test]
fn mixed_width_pure_scalar_half_keeps_fpscr_across_instruction_boundaries() {
    const FZ16: u64 = 1 << 19;
    const FZ: u64 = 1 << 24;
    const AHP: u64 = 1 << 26;
    const VMSR: u32 = 0xeee1_1a10; // VMSR FPSCR,R1.
    const VADD: u32 = 0xee32_0904; // VADD.F16 S0,S4,S8.
    const VMRS: u32 = 0xeef1_2a10; // VMRS R2,FPSCR.

    for thumb in [false, true] {
        let mut cpu = cpu(true);
        let mut state = cpu.export_sregs();
        let sysregs = &mut state.execution.as_mut().unwrap().sysregs;
        for (index, value) in [(0, 0x1000_0002), (1, 0x0300_0011)] {
            sysregs.impl_defined.insert(
                Aarch64SysRegEncoding::new(3, 0, 0, 3, index).encode(),
                value,
            );
        }
        cpu.import_sregs(&state).unwrap();
        cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
            .unwrap();
        words(&mut cpu, &[VMSR, VADD, VMRS, VADD, VMRS], thumb);
        cpu.set_x(1, AHP | FZ | FZ16);
        cpu.set_simd(1, 1);
        cpu.set_simd(2, 0);
        for step in ["VMSR", "VADD", "VMRS"] {
            assert_eq!(
                cpu.step().unwrap(),
                CpuExit::Continue,
                "{step}, Thumb={thumb}"
            );
        }
        assert_eq!(cpu.get_simd(0), 0);
        assert_eq!(cpu.get_x(2), FZ16);

        cpu.set_simd(1, 0x7c00);
        cpu.set_simd(2, 0xfc00);
        for _ in 0..2 {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        }
        assert_eq!(cpu.get_simd(0), 0x7e00);
        assert_eq!(cpu.get_x(2), FZ16 | 1);
        assert_eq!(cpu.instruction_count(), 5);
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

#[test]
fn aarch32_tid3_traps_the_cp15_feature_id_group() {
    use rax::isa::arm::decoder::ThumbDecoder;

    const TID3: u32 = 1 << 18;
    const CANARY: u32 = 0xface_1234;
    let group = (0..8)
        .map(|op2| (1, op2))
        .chain((0..8).map(|op2| (2, op2)))
        .chain((3..=7).flat_map(|crm| [(crm, 0), (crm, 1)]))
        .chain([(3, 2), (5, 4), (5, 5)]);
    let controls = [(0, 0), (0, 1), (0, 5)]; // MIDR, CTR, MPIDR.

    for thumb in [false, true] {
        for tid3 in [0, TID3] {
            for (crm, op2, mixed_traps) in group
                .clone()
                .map(|(crm, op2)| (crm, op2, tid3 != 0))
                .chain(controls.map(|(crm, op2)| (crm, op2, false)))
            {
                let raw = 0xee10_2f10 | (op2 << 5) | crm; // MRC P15,0,R2,C0,CRm,Op2.
                let insn = if thumb {
                    ThumbDecoder::decode_32bit(raw)
                } else {
                    Aarch32Decoder::decode(raw)
                }
                .unwrap();
                let iss = (0x1e << 20) | (op2 << 17) | (2 << 5) | (crm << 1) | 1;
                let mut standalone = Armv7Cpu::new();
                standalone.cp15.id_pfr1 = 1 << 12; // EL2, no EL3.
                standalone.cp15.hcr = tid3;
                standalone.cpsr.mode = ProcessorMode::Supervisor as u8;
                standalone.cpsr.t = thumb;
                standalone.regs[2] = CANARY;
                let mut memory = Memory32::new(4096, 0);
                let result = Executor::new(&mut standalone, &mut memory).execute(&insn);
                let standalone_traps = mixed_traps && (crm == 1 || crm == 2 && op2 != 6);
                if standalone_traps {
                    assert!(
                        matches!(result, ExecResult::FpAccessTrap { target_el: 2, syndrome, undefined: false }
                            if syndrome == (3 << 26) | (1 << 25) | iss),
                        "standalone Thumb={thumb} c{crm},{op2}: {result:?}"
                    );
                    assert_eq!(standalone.regs[2], CANARY);
                } else {
                    assert!(matches!(result, ExecResult::Continue), "{result:?}");
                }

                let mut mixed = mixed(raw, thumb, 0, false, false);
                let mut state = mixed.export_sregs();
                state.execution.as_mut().unwrap().sysregs.hcr_el2 = u64::from(tid3);
                mixed.import_sregs(&state).unwrap();
                mixed.set_x(2, u64::from(CANARY));
                let result = mixed.step();
                if mixed_traps {
                    assert!(
                        matches!(result, Err(ArmError::ArchitecturalException { ec: 3, iss: saved, target_el: Some(2) }) if saved == iss),
                        "mixed Thumb={thumb} c{crm},{op2}: {result:?}"
                    );
                    assert_eq!(mixed.get_x(2), u64::from(CANARY));
                    assert_eq!(mixed.get_pc(), 0x100);
                    assert_eq!(mixed.instruction_count(), 0);
                } else if crm == 2 && matches!(op2, 5 | 7) {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(mixed.get_pc(), 0x104);
                    assert_eq!(mixed.instruction_count(), 1);
                } else {
                    assert!(matches!(
                        result,
                        Err(ArmError::UnsupportedExecutionState(_))
                    ));
                    assert_eq!(mixed.get_x(2), u64::from(CANARY));
                    assert_eq!(mixed.get_pc(), 0x100);
                    assert_eq!(mixed.instruction_count(), 0);
                }
            }
        }
    }
}

#[test]
fn el1_id_isar6_readback_and_tid3_traps_agree_across_execution_states() {
    const MRS_ISAR6: u32 = 0xd538_02e3; // MRS X3,ID_ISAR6_EL1.
    const MRC_ISAR6: u32 = 0xee10_3ff2; // MRC P15,0,R3,C0,C2,7.
    for (fhm, jscvt) in [(false, false), (true, false), (false, true), (true, true)] {
        for tid3 in [false, true] {
            for (a32, thumb) in [(false, false), (true, false), (true, true)] {
                let mut config = AArch64Config {
                    initial_el: 3,
                    gic_config: None,
                    ..Default::default()
                };
                config
                    .features
                    .set(ArmFeatures::FP16 | ArmFeatures::FHM, fhm);
                config.features.set(ArmFeatures::JSCVT, jscvt);
                let mut cpu = AArch64Cpu::new(config, Box::new(Memory64::new(0, 0x4000)));
                let mut state = cpu.export_sregs();
                let system = &mut state.execution.as_mut().unwrap().sysregs;
                system.scr_el3 = 1 | (1 << 10);
                system.hcr_el2 = (u64::from(!a32) << 31) | (u64::from(tid3) << 18);
                cpu.import_sregs(&state).unwrap();
                cpu.set_pstate_bits(if a32 {
                    0x1d3 | (u64::from(thumb) << 5)
                } else {
                    0x3c5
                })
                .unwrap();
                words(&mut cpu, &[if a32 { MRC_ISAR6 } else { MRS_ISAR6 }], thumb);
                cpu.set_x(3, 0xa1b2c3d4);
                let result = cpu.step();
                if tid3 {
                    let (expected_ec, expected_iss) = if a32 {
                        (3, (0x1e << 20) | (7 << 17) | (3 << 5) | (2 << 1) | 1)
                    } else {
                        (0x18, (3 << 20) | (7 << 17) | (3 << 5) | (2 << 1) | 1)
                    };
                    assert!(
                        matches!(result, Err(ArmError::ArchitecturalException {
                        ec, iss, target_el: Some(2),
                    }) if ec == expected_ec && iss == expected_iss),
                        "A32={a32} T32={thumb} FHM={fhm}: {result:?}"
                    );
                    assert_eq!(cpu.get_x(3), 0xa1b2c3d4);
                    assert_eq!(cpu.get_pc(), 0x100);
                    assert_eq!(cpu.instruction_count(), 0);
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.get_x(3), (u64::from(fhm) << 8) | u64::from(jscvt));
                    assert_eq!(cpu.get_pc(), 0x104);
                    assert_eq!(cpu.instruction_count(), 1);
                }
            }
        }
    }
}

#[test]
fn mixed_vjcvt_uses_selected_jscvt_capability_and_fpscr() {
    const VJCVT: u32 = 0xeeb9_0bc1; // VJCVT.S32.F64 S0,D1.
    const VMRS_FPSCR: u32 = 0xeef1_3a10; // VMRS R3,FPSCR.
    let input = u128::from(1.0_f64.to_bits()) << 64;
    let before = input | 0x1122_3344_5566_7788;
    for enabled in [false, true] {
        for thumb in [false, true] {
            let mut cpu = cpu(false);
            if enabled {
                let mut state = cpu.export_sregs();
                state.execution.as_mut().unwrap().features |= ArmFeatures::JSCVT.bits();
                cpu.import_sregs(&state).unwrap();
            }
            cpu.set_pstate_bits(0x8000_01d3 | (u64::from(thumb) << 5))
                .unwrap();
            words(&mut cpu, &[VJCVT, VMRS_FPSCR], thumb);
            cpu.set_simd(0, before);
            if enabled {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), input | 0x1122_3344_0000_0001);
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_x(3), 1 << 30);
                assert_eq!(cpu.pstate_bits() >> 28, 8);
            } else {
                assert!(matches!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(VJCVT))
                ));
                assert_eq!(cpu.get_simd(0), before);
                assert_eq!(cpu.instruction_count(), 0);
            }
        }
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
fn a32_fpscr_preserves_shared_a64_fields_hidden_by_the_a32_profile() {
    const AHP_AND_FZ16: u32 = (1 << 26) | (1 << 19);
    const QC: u32 = 1 << 27;
    const DN: u32 = 1 << 25;
    const FZ: u32 = 1 << 24;
    const NEGATIVE: u32 = 1 << 31;
    const INVALID: u32 = 1;
    for thumb in [false, true] {
        let mut cpu = cpu(true);
        profile(&mut cpu, [0x1011_0221, 0x0000_0011, 0]);
        cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
            .unwrap();
        cpu.set_fpcr_value(AHP_AND_FZ16 | DN);
        cpu.set_fpsr_value(QC | INVALID);
        cpu.set_x(0, u64::from(NEGATIVE | FZ));
        words(&mut cpu, &[0xeef1_1a10, 0xeee1_0a10, 0xeef1_2a10], thumb);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_x(1) as u32, DN | INVALID, "Thumb={thumb}");
        assert_eq!(cpu.fpcr_value(), AHP_AND_FZ16 | DN);
        assert_eq!(cpu.fpsr_value(), QC | INVALID);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.fpcr_value(), AHP_AND_FZ16 | FZ);
        assert_eq!(cpu.fpsr_value(), QC | NEGATIVE);
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_x(2) as u32, NEGATIVE | FZ);
        assert_eq!(cpu.instruction_count(), 3);
    }
}

#[test]
fn mixed_jscvt_views_and_guest_execution_use_the_imported_register_and_precision_profile() {
    const MRS_ISAR6: u32 = 0xd538_02e3;
    const MRC_ISAR6: u32 = 0xee10_3ff2;
    const VJCVT: u32 = 0xeeb9_0bc1;
    let profiles = (0..16)
        .map(|precision| (2, precision))
        .chain([(0, 2), (1, 2), (3, 2), (15, 2)]);
    for thumb in [false, true] {
        for (bank, precision) in profiles.clone() {
            let mut cpu = cpu(false);
            let mut state = cpu.export_sregs();
            state.execution.as_mut().unwrap().features |= ArmFeatures::JSCVT.bits();
            cpu.import_sregs(&state).unwrap();
            let mut ids = expected(false);
            ids[0] = (ids[0] & !0xf0f) | (precision << 8) | bank;
            profile(&mut cpu, ids);
            let enabled = matches!(precision, 1 | 2) && matches!(bank, 1 | 2);

            words(&mut cpu, &[MRS_ISAR6], false);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(
                cpu.get_x(3) & 15,
                u64::from(enabled),
                "SIMDReg={bank}, FPDP={precision}"
            );
            cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
                .unwrap();
            words(&mut cpu, &[MRC_ISAR6, VJCVT], thumb);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(
                cpu.get_x(3) & 15,
                u64::from(enabled),
                "Thumb={thumb}, SIMDReg={bank}, FPDP={precision}"
            );
            let before = (u128::from(1.0_f64.to_bits()) << 64) | 0x1122_3344_5566_7788;
            cpu.set_simd(0, before);
            let result = cpu.step();
            if enabled {
                assert_eq!(result.unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), (before & !u128::from(u32::MAX)) | 1);
                assert_eq!(cpu.instruction_count(), 3);
            } else {
                assert!(matches!(result, Err(ArmError::UndefinedInstruction(VJCVT))));
                assert_eq!(cpu.get_simd(0), before);
                assert_eq!(cpu.instruction_count(), 2);
            }
        }
    }
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
fn mixed_width_user_fpsid_remains_privileged_with_imported_legacy_precision_ids() {
    for thumb in [false, true] {
        for v2_precision in [false, true] {
            let mut cpu = cpu(true);
            if v2_precision {
                let mut ids = expected(true);
                ids[0] = (ids[0] & !0xff0) | 0x110;
                profile(&mut cpu, ids);
            }
            cpu.set_pstate_bits(0x1d0 | (u64::from(thumb) << 5))
                .unwrap();
            words(&mut cpu, &[0xeef0_2a10], thumb);
            cpu.set_x(2, 0xdead_beef);
            let before = cpu.export_sregs();
            assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))));
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(cpu.get_x(2), 0xdead_beef);
            assert_eq!(cpu.export_sregs(), before);
        }
    }
}

#[test]
fn mixed_width_fp_system_transfers_allow_thumb_sp_with_legacy_precision_ids() {
    for word in [0xeef1_da10, 0xeef8_da10, 0xeee1_da10, 0xeee8_da10] {
        let mut cpu = cpu(true);
        let mut ids = expected(true);
        ids[0] = (ids[0] & !0xff0) | 0x110;
        profile(&mut cpu, ids);
        cpu.set_pstate_bits(0x1f3).unwrap(); // Thumb SVC.
        words(&mut cpu, &[word], true);
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{word:#x}");
        assert_eq!(cpu.get_pc(), 0x104);
        assert_eq!(cpu.instruction_count(), 1);
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
