//! Profile-aware FP16 admission, with conversion-only positive controls.
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
use rax::isa::arm::common::features::ArmFeatures;
use rax::isa::arm::common::memory::FlatMemory;
use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// LLVM-assembled ARM/Thumb pairs. The last field marks conversion-only forms.
const CASES: &[([u8; 4], [u8; 4], bool)] = &[
    ([0x2, 0x9, 0x31, 0xee], [0x31, 0xee, 0x2, 0x9], false),
    ([0x44, 0xd, 0x12, 0xf2], [0x12, 0xef, 0x44, 0xd], false),
    ([0x41, 0xa, 0xb0, 0xfe], [0xb0, 0xfe, 0x41, 0xa], false),
    ([0xc1, 0xa, 0xb0, 0xfe], [0xb0, 0xfe, 0xc1, 0xa], false),
    ([0x10, 0x9, 0x0, 0xee], [0x0, 0xee, 0x10, 0x9], false),
    ([0x0, 0x9, 0x90, 0xed], [0x90, 0xed, 0x0, 0x9], false),
    ([0x41, 0xa, 0xb2, 0xee], [0xb2, 0xee, 0x41, 0xa], true),
    ([0xc2, 0xb, 0xb3, 0xee], [0xb3, 0xee, 0xc2, 0xb], true),
    ([0x2, 0x6, 0xb6, 0xf3], [0xb6, 0xff, 0x2, 0x6], true),
    ([0x42, 0x5, 0xb7, 0xf3], [0xb7, 0xff, 0x42, 0x5], false),
    ([0x54, 0xf, 0x12, 0xf3], [0x12, 0xff, 0x54, 0xf], false),
    ([0x42, 0x4, 0xb6, 0xf3], [0xb6, 0xff, 0x42, 0x4], false),
    ([0x42, 0x7, 0xb7, 0xf3], [0xb7, 0xff, 0x42, 0x7], false),
    ([0x52, 0xd, 0xbc, 0xf2], [0xbc, 0xef, 0x52, 0xd], false),
    ([0x42, 0x9, 0x92, 0xf3], [0x92, 0xff, 0x42, 0x9], false),
    ([0x42, 0x7, 0xb5, 0xf3], [0xb5, 0xff, 0x42, 0x7], false),
    ([0x42, 0x5, 0xb5, 0xf3], [0xb5, 0xff, 0x42, 0x5], false),
];

fn mixed(bytes: [u8; 4], thumb: bool, fp16: bool, trap: bool) -> AArch64Cpu {
    let mut config = AArch64Config::v8_2();
    config.initial_el = 3;
    config.gic_config = None;
    config.features.set(ArmFeatures::FP16, fp16);
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x4000)));
    let mut state = cpu.export_sregs();
    let sys = &mut state.execution.as_mut().unwrap().sysregs;
    sys.scr_el3 = 0;
    sys.hcr_el2 = 0;
    sys.el1.cpacr = 3 << 20;
    sys.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(),
        if trap { 1 << 10 } else { 0 },
    );
    sys.impl_defined
        .insert(Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(), 1 << 30);
    cpu.import_sregs(&state).unwrap();
    cpu.set_pstate_bits(0x1d3 | if thumb { 32 } else { 0 })
        .unwrap();
    cpu.set_pc(0x100);
    for index in 0..32 {
        cpu.set_simd(index, 0x3f800000_3f800000_3c003c00_3c003c00);
    }
    cpu.set_x(0, 0x800);
    cpu.write_memory(0x800, &[0, 0x3c, 0, 0x3c, 0, 0x3c, 0, 0x3c])
        .unwrap();
    cpu.write_memory(0x100, &bytes).unwrap();
    cpu
}

fn rejected(cpu: &mut AArch64Cpu) {
    let x: Vec<_> = (0..31).map(|index| cpu.get_x(index)).collect();
    let v: Vec<_> = (0..32).map(|index| cpu.get_simd(index)).collect();
    let fp = (cpu.fpcr_value(), cpu.fpsr_value());
    assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))));
    assert_eq!(cpu.get_pc(), 0x100);
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!((0..31).map(|index| cpu.get_x(index)).collect::<Vec<_>>(), x);
    assert_eq!(
        (0..32).map(|index| cpu.get_simd(index)).collect::<Vec<_>>(),
        v
    );
    assert_eq!((cpu.fpcr_value(), cpu.fpsr_value()), fp);
}

#[test]
fn mixed_arm_rejects_half_data_processing_without_fp16() {
    for &(arm, _, conversion) in CASES {
        if !conversion {
            rejected(&mut mixed(arm, false, false, false));
        }
    }
}

#[test]
fn mixed_thumb_rejects_half_data_processing_without_fp16() {
    for &(_, thumb, conversion) in CASES {
        if !conversion {
            rejected(&mut mixed(thumb, true, false, false));
        }
    }
}

#[test]
fn enabled_feature_admits_every_control_in_both_execution_states() {
    for &(arm, thumb, _) in CASES {
        for (bytes, state) in [(arm, false), (thumb, true)] {
            let mut cpu = mixed(bytes, state, true, false);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_pc(), 0x104);
            assert_eq!(cpu.instruction_count(), 1);
        }
    }
}

#[test]
fn conversion_only_forms_remain_available_without_fp16_arithmetic() {
    let mut count = 0;
    for &(arm, thumb, conversion) in CASES {
        if !conversion {
            continue;
        }
        for (bytes, state) in [(arm, false), (thumb, true)] {
            let mut cpu = mixed(bytes, state, false, false);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_pc(), 0x104);
            count += 1;
        }
    }
    assert_eq!(count, 6);
}

#[test]
fn absence_is_decoded_before_an_fp_access_trap() {
    for &(arm, thumb, conversion) in CASES {
        if conversion {
            continue;
        }
        for (bytes, state) in [(arm, false), (thumb, true)] {
            rejected(&mut mixed(bytes, state, false, true));
            let mut enabled = mixed(bytes, state, true, true);
            assert!(matches!(
                enabled.step(),
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    target_el: Some(3),
                    ..
                })
            ));
            assert_eq!(enabled.get_pc(), 0x100);
            assert_eq!(enabled.instruction_count(), 0);
        }
    }
}

#[test]
fn mixed_vmrs_capabilities_match_configured_fp16() {
    for fp16 in [false, true] {
        for thumb in [false, true] {
            let bytes = if thumb {
                [0xf6, 0xee, 0x10, 0x0a]
            } else {
                [0x10, 0x0a, 0xf6, 0xee]
            };
            let mut cpu = mixed(bytes, thumb, fp16, false);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(0), if fp16 { 0x1321_1111 } else { 0x1211_1111 });
        }
    }
}

#[test]
fn standalone_conversion_profile_rejects_half_data_processing() {
    for &(arm, thumb, conversion) in CASES {
        for (bytes, state) in [(arm, false), (thumb, true)] {
            let raw = if state {
                u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) << 16
                    | u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
            } else {
                u32::from_le_bytes(bytes)
            };
            let insn = if state {
                ThumbDecoder::decode_32bit(raw)
            } else {
                Aarch32Decoder::decode(raw)
            }
            .unwrap();
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = state;
            cpu.vfp.mvfr1 = 0x1211_1111;
            cpu.regs[0] = 0x800;
            cpu.vfp.dregs.fill(0x3f800000_3c003c00);
            let before = cpu.vfp.dregs;
            let mut memory = rax::isa::arm::execution::FlatMemory::new(0x4000, 0);
            let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
            if conversion {
                assert!(matches!(result, ExecResult::Continue));
            } else {
                assert!(matches!(result, ExecResult::Undefined));
                assert_eq!(cpu.vfp.dregs, before);
            }
        }
    }
}

#[test]
fn conversion_only_fpscr_does_not_expose_fz16() {
    for thumb in [false, true] {
        let bytes = if thumb {
            [0xf1, 0xee, 0x10, 0x0a]
        } else {
            [0x10, 0x0a, 0xf1, 0xee]
        };
        for fp16 in [false, true] {
            let mut cpu = mixed(bytes, thumb, fp16, false);
            cpu.set_fpcr_value(1 << 19);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(0) & (1 << 19), if fp16 { 1 << 19 } else { 0 });
        }
    }
}

#[test]
fn capability_field_boundaries_keep_scalar_and_simd_requirements_independent() {
    // Arm MVFR1 FPHP=1 permits half/single conversions; 2 adds double;
    // 3 adds scalar data processing. SIMDHP=1 permits conversions and 2
    // adds data processing. Values beyond those encodings are reserved.
    for scalar in 0..=4 {
        for simd in 0..=3 {
            for (index, &(arm, thumb, _)) in CASES.iter().enumerate() {
                let expected = match index {
                    6 => matches!(scalar, 1..=3),
                    7 => matches!(scalar, 2 | 3),
                    8 => matches!(simd, 1 | 2),
                    0 | 2..=5 => scalar == 3,
                    _ => simd == 2,
                };
                for (bytes, state) in [(arm, false), (thumb, true)] {
                    let raw = if state {
                        u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) << 16
                            | u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
                    } else {
                        u32::from_le_bytes(bytes)
                    };
                    let insn = if state {
                        ThumbDecoder::decode_32bit(raw)
                    } else {
                        Aarch32Decoder::decode(raw)
                    }
                    .unwrap();
                    let mut cpu = Armv7Cpu::new();
                    cpu.cpsr.t = state;
                    cpu.regs[0] = 0x800;
                    cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !0x0ff0_0000) | (scalar << 24) | (simd << 20);
                    let mut memory = rax::isa::arm::execution::FlatMemory::new(0x4000, 0);
                    let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
                    assert_eq!(
                        matches!(result, ExecResult::Continue),
                        expected,
                        "case={index} thumb={state} FPHP={scalar} SIMDHP={simd} result={result:?}"
                    );
                }
            }
        }
    }
}
