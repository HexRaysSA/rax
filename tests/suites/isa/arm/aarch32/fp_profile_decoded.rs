//! LLVM encodings, fixed literal results and complete conversion register effects.
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};
const CENSUS: &[(u32, &str)] = &[
    (0xeeb30b41, "VCVTB_F16_F64"),
    (0xeeb30bc1, "VCVTT_F16_F64"),
    (0xeeb20b41, "VCVTB_F64_F16"),
    (0xeeb20bc1, "VCVTT_F64_F16"),
    (0xf3b70642, "VCVT_F16_S16"),
    (0xf3b706c2, "VCVT_F16_U16"),
    (0xf3b70742, "VCVT_S16_F16"),
    (0xf3b707c2, "VCVT_U16_F16"),
    (0xf3fb0662, "VCVT_F32_S32"),
    (0xf3fb0762, "VCVT_S32_F32"),
    (0xeeba0944, "VCVT_F16_S16_FIXED"),
    (0xeebe0944, "VCVT_S16_F16_FIXED"),
    (0xeebb0944, "VCVT_F16_U16_FIXED"),
    (0xeebf0944, "VCVT_U16_F16_FIXED"),
    (0xeeba09cc, "VCVT_F16_S32_FIXED"),
    (0xeebe09cc, "VCVT_S32_F16_FIXED"),
    (0xeebb09cc, "VCVT_F16_U32_FIXED"),
    (0xeebf09cc, "VCVT_U32_F16_FIXED"),
    (0xeeba0a44, "VCVT_F32_S16_FIXED"),
    (0xeebe0a44, "VCVT_S16_F32_FIXED"),
    (0xeebb0a44, "VCVT_F32_U16_FIXED"),
    (0xeebf0a44, "VCVT_U16_F32_FIXED"),
    (0xeeba0acc, "VCVT_F32_S32_FIXED"),
    (0xeebe0acc, "VCVT_S32_F32_FIXED"),
    (0xeebb0acc, "VCVT_F32_U32_FIXED"),
    (0xeebf0acc, "VCVT_U32_F32_FIXED"),
    (0xeeba0b44, "VCVT_F64_S16_FIXED"),
    (0xeebe0b44, "VCVT_S16_F64_FIXED"),
    (0xeebb0b44, "VCVT_F64_U16_FIXED"),
    (0xeebf0b44, "VCVT_U16_F64_FIXED"),
    (0xeeba0bcc, "VCVT_F64_S32_FIXED"),
    (0xeebe0bcc, "VCVT_S32_F64_FIXED"),
    (0xeebb0bcc, "VCVT_F64_U32_FIXED"),
    (0xeebf0bcc, "VCVT_U32_F64_FIXED"),
    (0xf2120c54, "VFMA"),
    (0xf2320c54, "VFMS"),
    (0xf3120f54, "VMAXNM_F16"),
    (0xf3320f54, "VMINNM_F16"),
    (0xf2020c54, "VFMA"),
    (0xf2220c54, "VFMS"),
    (0xf3020f54, "VMAXNM_F32"),
    (0xf3220f54, "VMINNM_F32"),
    (0xf2b80c52, "VCVT_F16_S16_FIXED"),
    (0xf3b80c52, "VCVT_F16_U16_FIXED"),
    (0xf2b80d52, "VCVT_S16_F16_FIXED"),
    (0xf3b80d52, "VCVT_U16_F16_FIXED"),
];
fn word(raw: u32, thumb: bool) -> u32 {
    if !thumb {
        return raw;
    }
    if raw >> 24 == 0xf2 {
        raw ^ 0x1d000000
    } else if raw >> 24 == 0xf3 {
        raw ^ 0x0c000000
    } else {
        raw
    }
}
fn decode(raw: u32, thumb: bool) -> rax::isa::arm::decoder::DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(word(raw, true))
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}
#[test]
fn llvm_instruction_admission_census() {
    for thumb in [false, true] {
        for &(raw, expected) in CENSUS {
            let insn = decode(raw, thumb);
            assert_eq!(
                format!("{:?}", insn.mnemonic),
                expected,
                "{raw:08x} Thumb={thumb}"
            );
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            let mut memory = FlatMemory::new(4096, 0);
            assert!(
                matches!(
                    Executor::new(&mut cpu, &mut memory).execute(&insn),
                    ExecResult::Continue
                ),
                "{raw:08x} Thumb={thumb}"
            );
        }
    }
}

#[test]
fn absent_bfloat16_is_undefined_without_register_effects() {
    // LLVM MC A32 encodings. Thumb remaps only the vector conversion prefix.
    let encodings = [
        0xf3b6_0642, // VCVT.BF16.F32 d0, q1
        0xf3f6_f66e, // VCVT.BF16.F32 d31, q15
        0xeeb3_0960, // VCVTB.BF16.F32 s0, s1
        0xeef3_09c0, // VCVTT.BF16.F32 s1, s0
        0xfc01_0d02, // VDOT.BF16 d0, d1, d2
        0xfc4c_edea, // VDOT.BF16 q15, q14, q13
        0xfe4e_fdaf, // VDOT.BF16 d31, d30, d15[1]
        0xfe02_0d44, // VDOT.BF16 q0, q1, d4[0]
        0xfe02_0d62, // VDOT.BF16 q0, q1, d2[1]
        0xfc4c_ecea, // VMMLA.BF16 q15, q14, q13
        0xfc32_0814, // VFMAB.BF16 q0, q1, q2
        0xfc7c_e8fa, // VFMAT.BF16 q15, q14, q13
        0xfe32_081a, // VFMAB.BF16 q0, q1, d2[1]
        0xfe7c_e8ff, // VFMAT.BF16 q15, q14, d7[3]
    ];
    for thumb in [false, true] {
        for raw in encodings {
            assert_bfloat16_admission(raw, thumb, None);
        }
        for raw in [0xeef3_f94f, 0xeeb3_f9ef] {
            for zero in [false, true] {
                assert_bfloat16_admission(raw, thumb, Some(zero));
            }
        }
    }
}

fn assert_bfloat16_admission(raw: u32, thumb: bool, eq: Option<bool>) {
    let raw = if eq.is_some() && !thumb {
        raw & 0x0fff_ffff
    } else {
        raw
    };
    let insn = decode(raw, thumb);
    assert_eq!(
        insn.mnemonic,
        Mnemonic::UNDEFINED,
        "{raw:08x} Thumb={thumb}"
    );
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    if let Some(zero) = eq {
        cpu.cpsr.z = zero;
        if thumb {
            cpu.cpsr.set_it_state(0, 0b1000); // IT EQ
        }
    }
    cpu.regs.fill(0x1234_5678);
    cpu.vfp.dregs.fill(0x3f80_0000_4000_0000);
    cpu.vfp.fpscr = Fpscr::from_bits(0xa800_0010);
    let regs = cpu.regs;
    let dregs = cpu.vfp.dregs;
    let fpscr = cpu.vfp.fpscr.bits();
    let cpsr = cpu.cpsr.to_u32();

    let mut memory = FlatMemory::new(4096, 0);
    let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
    if eq == Some(false) {
        assert!(
            matches!(result, ExecResult::Continue),
            "{raw:08x} Thumb={thumb}"
        );
    } else {
        assert!(
            matches!(result, ExecResult::Undefined),
            "{raw:08x} Thumb={thumb}"
        );
    }
    assert_eq!(cpu.regs, regs);
    assert_eq!(cpu.vfp.dregs, dregs);
    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
    assert_eq!(cpu.cpsr.to_u32(), cpsr);
}

#[test]
fn bfloat16_allocations_preserve_adjacent_fp16_decodes() {
    for thumb in [false, true] {
        for (raw, mnemonic) in [
            (0xf3b6_0602, Mnemonic::VCVT_F16_F32),
            (0xeeb3_0a60, Mnemonic::VCVTB_F16_F32),
            (0xeef3_0ac0, Mnemonic::VCVTT_F16_F32),
            (0xfc21_0852, Mnemonic::VFMAL),
            (0xfe01_085a, Mnemonic::VFMAL),
        ] {
            assert_eq!(
                decode(raw, thumb).mnemonic,
                mnemonic,
                "{raw:08x} Thumb={thumb}"
            );
        }
    }
}
fn check(raw: u32, inputs: &[(usize, u64)], control: u32, changes: &[(usize, u64)], status: u32) {
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        cpu.vfp.dregs.fill(0xcafebabe_deadbeef);
        for &(reg, value) in inputs {
            cpu.vfp.dregs[reg] = value;
        }
        cpu.vfp.fpscr = Fpscr::from_bits(control | 0xa8000000);
        let mut expected = cpu.vfp.dregs;
        for &(reg, value) in changes {
            expected[reg] = value;
        }
        let cpsr = cpu.cpsr.to_u32();
        let regs = cpu.regs;
        let mut memory = FlatMemory::new(4096, 0);
        assert!(matches!(
            Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.dregs, expected, "{raw:08x} Thumb={thumb}");
        assert_eq!(
            cpu.vfp.fpscr.bits(),
            control | 0xa8000000 | status,
            "{raw:08x} Thumb={thumb}"
        );
        assert_eq!(cpu.cpsr.to_u32(), cpsr);
        assert_eq!(cpu.regs, regs);
    }
}
#[test]
fn precision_double_narrowing_avoids_single_double_rounding() {
    check(
        0xeeb30b41,
        &[(1, 0x3ff0020000000001)],
        0,
        &[(0, 0xcafebabe_dead3c01)],
        0x10,
    );
    check(
        0xeeb30bc1,
        &[(1, 0x3ff0020000000001)],
        0,
        &[(0, 0xcafebabe_3c01beef)],
        0x10,
    );
}
#[test]
fn precision_double_widening_preserves_other_registers() {
    check(
        0xeeb20b41,
        &[(1, 0xfacebeef_12343c00)],
        0,
        &[(0, 0x3ff0000000000000)],
        0,
    );
    check(
        0xeeb20bc1,
        &[(1, 0xfacebeef_3c001234)],
        0,
        &[(0, 0x3ff0000000000000)],
        0,
    );
}
#[test]
fn scalar_signed_halfword_fixed_extends_the_integer_destination() {
    check(
        0xeebe0a44,
        &[(0, 0x11223344_bf800000)],
        0,
        &[(0, 0x11223344_ffffff00)],
        0,
    );
    check(
        0xeebe0b44,
        &[(0, 0xbff0000000000000)],
        0,
        &[(0, 0xffffffff_ffffff00)],
        0,
    );
}
#[test]
fn scalar_half_fixed_ignores_high_integer_bits_and_zeroes_high_half() {
    check(
        0xeeba0944,
        &[(0, 0x11223344_abcd0100)],
        0,
        &[(0, 0x11223344_00003c00)],
        0,
    );
}
#[test]
fn scalar_fixed_to_float_is_nearest_even_under_all_live_modes() {
    for mode in 0..4 {
        check(
            0xeeba09cc,
            &[(0, 0x11223344_00040080)],
            mode << 22,
            &[(0, 0x11223344_00006400)],
            0x10,
        );
    }
}
#[test]
fn vector_half_fixed_decodes_as_conversion_and_preserves_neighbors() {
    check(
        0xf2b80c52,
        &[(2, 0x0100010001000100), (3, 0x0100010001000100)],
        0,
        &[(0, 0x3c003c003c003c00), (1, 0x3c003c003c003c00)],
        0,
    );
    check(
        0xf2b80d52,
        &[(2, 0x3c003c003c003c00), (3, 0x3c003c003c003c00)],
        0,
        &[(0, 0x0100010001000100), (1, 0x0100010001000100)],
        0,
    );
}
#[test]
fn vector_half_integer_uses_signed_i16_lane_width() {
    check(
        0xf3b70642,
        &[(2, 0xffff0001ffff0001), (3, 0xffff0001ffff0001)],
        0,
        &[(0, 0xbc003c00bc003c00), (1, 0xbc003c00bc003c00)],
        0,
    );
    check(
        0xf3b70742,
        &[(2, 0xbc003c00bc003c00), (3, 0xbc003c00bc003c00)],
        0,
        &[(0, 0xffff0001ffff0001), (1, 0xffff0001ffff0001)],
        0,
    );
}
#[test]
fn vector_half_fma_and_number_selection_use_half_lanes() {
    check(
        0xf2120c54,
        &[
            (0, 0x3c003c003c003c00),
            (1, 0x3c003c003c003c00),
            (2, 0x4000400040004000),
            (3, 0x4000400040004000),
            (4, 0x4200420042004200),
            (5, 0x4200420042004200),
        ],
        0,
        &[(0, 0x4700470047004700), (1, 0x4700470047004700)],
        0,
    );
    check(
        0xf3120f54,
        &[
            (2, 0x7e013c007e013c00),
            (3, 0x7e013c007e013c00),
            (4, 0x40007e0140007e01),
            (5, 0x40007e0140007e01),
        ],
        0,
        &[(0, 0x40003c0040003c00), (1, 0x40003c0040003c00)],
        0,
    );
}

#[test]
fn new_floating_encodings_keep_smir_fpscr_rejection() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::thumb::ThumbLifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    for &(raw, _) in CENSUS {
        for thumb in [false, true] {
            let raw = word(raw, thumb);
            let bytes = if thumb {
                let high = ((raw >> 16) as u16).to_le_bytes();
                let low = (raw as u16).to_le_bytes();
                [high[0], high[1], low[0], low[1]]
            } else {
                raw.to_le_bytes()
            };
            let mut lifter: Box<dyn SmirLifter> = if thumb {
                Box::new(ThumbLifter::new())
            } else {
                Box::new(Aarch32Lifter::new())
            };
            let mut context = LiftContext::new(if thumb {
                SourceArch::Thumb
            } else {
                SourceArch::Aarch32
            });
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, &bytes, &mut context),
                    Err(LiftError::Unsupported { addr: 0x1000, .. })
                ),
                "raw={raw:08x} Thumb={thumb}"
            );
        }
    }
}
#[test]
fn reserved_conversion_scales_and_odd_q_fields_are_undefined() {
    use rax::isa::arm::decoder::Mnemonic;
    for thumb in [false, true] {
        for imm in 8..48 {
            let raw = 0xf2800c52 | (imm << 16);
            assert_eq!(
                decode(raw, thumb).mnemonic,
                Mnemonic::UNDEFINED,
                "raw={raw:08x} Thumb={thumb}"
            );
        }
        for base in [0xf3b70642, 0xf2b80c52, 0xf2120c54, 0xf3120f54] {
            for field in [1 << 12, 1] {
                let raw = base | field;
                assert_eq!(
                    decode(raw, thumb).mnemonic,
                    Mnemonic::UNDEFINED,
                    "raw={raw:08x} Thumb={thumb}"
                );
            }
        }
    }
}
#[test]
fn forged_conversion_fma_and_number_tags_preserve_all_state() {
    use rax::isa::arm::decoder::Mnemonic;
    for thumb in [false, true] {
        for (raw, tag) in [
            (0xf3b70642, Mnemonic::VCVT_F16_U16),
            (0xeeba0944, Mnemonic::VCVT_F16_U16_FIXED),
            (0xeeb30b41, Mnemonic::VCVTT_F16_F64),
            (0xf3120f54, Mnemonic::VMINNM_F16),
            (0xf2120c54, Mnemonic::VFMS),
        ] {
            let mut insn = decode(raw, thumb);
            insn.mnemonic = tag;
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.vfp.dregs.fill(0x7c013c007e018001);
            cpu.vfp.fpscr = Fpscr::from_bits(0xaec80080);
            let regs = cpu.regs;
            let cpsr = cpu.cpsr.to_u32();
            let dregs = cpu.vfp.dregs;
            let fpscr = cpu.vfp.fpscr.bits();
            let mut memory = FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&insn),
                ExecResult::Undefined
            ));
            assert_eq!(cpu.vfp.dregs, dregs);
            assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);
            assert_eq!(cpu.regs, regs);
        }
    }
}
