//! Arm DDI0597 FEAT_AA32BF16 execution and profile boundaries.
use super::*;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Mnemonic, ThumbDecoder};

const BF16: u32 = 1 << 20;
const ISAR6: u32 = 0xee10_0ff2;
const CONVERT_BOTTOM: u32 = 0xeeb3_0960; // VCVTB.BF16.F32 S0,S1.
const CONVERT_TOP: u32 = 0xeeb3_09e0; // VCVTT.BF16.F32 S0,S1.
const CONVERT_VECTOR: u32 = 0xf3b6_0642; // VCVT.BF16.F32 D0,Q1.
const DOT: u32 = 0xfc02_0d44; // VDOT.BF16 Q0,Q1,Q2.
const DOT_INDEXED: u32 = 0xfe02_0d44; // VDOT.BF16 Q0,Q1,D4[0].
const MATRIX: u32 = 0xfc02_0c44; // VMMLA.BF16 Q0,Q1,Q2.
const FMA_BOTTOM: u32 = 0xfc32_0814; // VFMAB.BF16 Q0,Q1,Q2.
const FMA_TOP: u32 = 0xfc32_0854; // VFMAT.BF16 Q0,Q1,Q2.
const FMA_INDEXED: u32 = 0xfe32_081a; // VFMAB.BF16 Q0,Q1,D2[1].

fn decoded(raw: u32, thumb: bool) -> rax::isa::arm::decoder::DecodedInsn {
    if thumb {
        let raw = if raw >> 24 == 0xf3 {
            raw ^ 0x0c00_0000
        } else {
            raw
        };
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}

fn operation(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = decoded(raw, cpu.cpsr.t);
    Executor::new(cpu, &mut Memory32::new(4096, 0)).execute(&insn)
}

#[test]
fn scalar_bfloat_conversion_observes_fpscr_and_preserves_other_halves() {
    let cases: [(u32, u32, u64, u32); 11] = [
        (0, 0x3f80_8000, 0x3f80, 0x10),       // Even tie.
        (1 << 22, 0x3f80_0001, 0x3f81, 0x10), // Toward positive infinity.
        (2 << 22, 0xbf80_0001, 0xbf81, 0x10), // Toward negative infinity.
        (3 << 22, 0x7f7f_ffff, 0x7f7f, 0x10), // Toward zero.
        (0, 0x7f7f_ffff, 0x7f80, 0x14),       // Overflow.
        (0, 0x007f_ffff, 0x0080, 0x18),       // Tiny before rounding.
        (0, 0x0001_0000, 0x0001, 0),          // Exact subnormal.
        (1 << 24, 0x8001_0000, 0x8000, 0x80), // Signed flushed input.
        (0, 0xff81_2345, 0xffc1, 1),          // Quieted sNaN payload.
        (1 << 25, 0xff81_2345, 0x7fc0, 1),    // Default sNaN result.
        (0, 0xff80_0000, 0xff80, 0),          // Infinity.
    ];
    for thumb in [false, true] {
        for (raw, high) in [(CONVERT_BOTTOM, false), (CONVERT_TOP, true)] {
            for (controls, source, result, status) in cases {
                let mut cpu = Armv7Cpu::new();
                cpu.cpsr.t = thumb;
                cpu.cp15.id_isar6 |= BF16;
                cpu.vfp.mvfr1 &= !(0xff << 20); // BF16 also runs without IEEE half precision.
                cpu.vfp.dregs[0] = (u64::from(source) << 32) | 0xdead_beef;
                let controls = controls | (1 << 26) | (1 << 19) | 2; // AHP, FZ16, sticky DZC.
                cpu.vfp.fpscr = Fpscr::from_bits(controls);
                let mut expected = cpu.vfp.dregs;
                let shift = 16 * u32::from(high);
                expected[0] = (expected[0] & !(0xffff << shift)) | (result << shift);
                let exit = operation(&mut cpu, raw);
                assert!(matches!(exit, ExecResult::Continue), "{raw:08x}: {exit:?}");
                assert_eq!(cpu.vfp.dregs, expected);
                assert_eq!(cpu.vfp.fpscr.bits(), controls | status);
            }
        }
    }
}

#[test]
fn scalar_bfloat_conversion_takes_enabled_exceptions_before_destination_write() {
    use rax::isa::arm::ExceptionType;

    for thumb in [false, true] {
        for (source, raised) in [(0x0001_0000, 8), (0x7f80_0001, 1)] {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cp15.id_isar6 |= BF16;
            cpu.vfp.mvfr1 &= !(0xff << 20);
            cpu.vfp.mvfr0 |= 1 << 12; // Synchronous VFP exceptions.
            cpu.vfp.write_s_bits(0, 0xdead_beef);
            cpu.vfp.write_s_bits(1, source);
            let before = cpu.vfp.dregs;
            let controls = (1 << 19) | (u32::from(raised) << 8) | 2;
            cpu.vfp.fpscr = Fpscr::from_bits(controls);
            let exit = operation(&mut cpu, CONVERT_BOTTOM);
            assert!(
                matches!(exit, ExecResult::Exception(ExceptionType::FloatingPoint(flags)) if flags == raised),
                "{source:08x}, Thumb={thumb}: {exit:?}"
            );
            assert_eq!(cpu.vfp.dregs, before);
            assert_eq!(cpu.vfp.fpscr.bits(), controls);
            assert_eq!(cpu.vfp.fpexc & 0x9f, u32::from(raised));
        }
    }
}

#[test]
fn vector_bfloat_results_preserve_other_registers_and_fixed_controls() {
    let lhs = [0x4080_4040_4000_3f80, 0x4100_40e0_40c0_40a0]; // 1..8.
    let rhs = [0x4000_3f80_4000_3f80, 0x3f80_4000_3f80_4000]; // 1,2,1,2 and 2,1,2,1.
    let cases = [
        (DOT, lhs, rhs, [5.0, 11.0, 16.0, 22.0]),
        (DOT_INDEXED, lhs, rhs, [5.0, 11.0, 17.0, 23.0]),
        (MATRIX, lhs, rhs, [16.0, 14.0, 40.0, 38.0]),
        (FMA_BOTTOM, lhs, rhs, [1.0, 3.0, 10.0, 14.0]),
        (FMA_TOP, lhs, rhs, [4.0, 8.0, 6.0, 8.0]),
        (FMA_INDEXED, lhs, rhs, [2.0, 6.0, 10.0, 14.0]),
    ];
    for thumb in [false, true] {
        for (raw, lhs, rhs, lanes) in cases {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cp15.id_isar6 |= BF16;
            cpu.vfp.mvfr1 &= !(0xff << 20);
            cpu.vfp.dregs[2..4].copy_from_slice(&lhs);
            cpu.vfp.dregs[4..6].copy_from_slice(&rhs);
            let controls = (3 << 22) | (1 << 26) | 2;
            cpu.vfp.fpscr = Fpscr::from_bits(controls);
            let mut expected = cpu.vfp.dregs;
            let bits = lanes.map(f32::to_bits);
            expected[0] = u64::from(bits[0]) | (u64::from(bits[1]) << 32);
            expected[1] = u64::from(bits[2]) | (u64::from(bits[3]) << 32);
            let exit = operation(&mut cpu, raw);
            assert!(matches!(exit, ExecResult::Continue), "{raw:08x}: {exit:?}");
            assert_eq!(cpu.vfp.dregs, expected, "{raw:08x} Thumb={thumb}");
            assert_eq!(cpu.vfp.fpscr.bits(), controls);
        }

        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        cpu.cp15.id_isar6 |= BF16;
        cpu.vfp.dregs[2] = 0x3f80_8001_8000_0001;
        cpu.vfp.dregs[3] = 0xff81_2345_7f7f_ffff;
        cpu.vfp.fpscr = Fpscr::from_bits(3 << 22);
        let mut expected = cpu.vfp.dregs;
        expected[2] = 0x7fc0_7f80_3f81_8000;
        let raw = CONVERT_VECTOR | (2 << 12); // D2 overlaps Q1.
        assert!(matches!(operation(&mut cpu, raw), ExecResult::Continue));
        assert_eq!(cpu.vfp.dregs, expected);
        assert_eq!(cpu.vfp.fpscr.bits(), (3 << 22) | 0x95);
    }
}

#[test]
fn bfloat_profile_restrictions_precede_fp_access_faults() {
    for thumb in [false, true] {
        for level in [0, 1, 2, 15] {
            for restriction in 0..5 {
                let mut cpu = hyp();
                cpu.cpsr.t = thumb;
                cpu.cp15.id_isar6 = level << 20;
                match restriction {
                    1 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1, // D16.
                    2 => cpu.vfp.mvfr0 &= !(15 << 4),               // No FPSP.
                    3 => cpu.vfp.mvfr1 &= !(15 << 12),              // No SIMDInt.
                    4 => cpu.vfp.mvfr1 &= !(15 << 16),              // No SIMDSP.
                    _ => (),
                }
                let available = level == 1 && restriction == 0;
                assert!(matches!(operation(&mut cpu, ISAR6), ExecResult::Continue));
                assert_eq!(cpu.regs[0] & (15 << 20), if available { BF16 } else { 0 });
                cpu.cp15.hcptr |= 1 << 10;
                let registers = cpu.vfp.dregs;
                let fpscr = cpu.vfp.fpscr.bits();
                for raw in [CONVERT_BOTTOM, CONVERT_VECTOR, DOT, MATRIX, FMA_TOP] {
                    let exit = operation(&mut cpu, raw);
                    assert!(
                        if available {
                            matches!(exit, ExecResult::FpAccessTrap { target_el: 2, .. })
                        } else {
                            matches!(exit, ExecResult::Undefined)
                        },
                        "BF16={level}, restriction={restriction}, {raw:08x}, Thumb={thumb}: {exit:?}"
                    );
                    assert_eq!(cpu.vfp.dregs, registers);
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                }
            }
        }
    }
}

#[test]
fn bfloat_q_alignment_and_it_constraints_follow_each_encoding() {
    for thumb in [false, true] {
        for raw in [
            CONVERT_VECTOR | 1,
            DOT | 1,
            MATRIX | (1 << 12),
            FMA_BOTTOM | 1,
        ] {
            assert_eq!(decoded(raw, thumb).mnemonic, Mnemonic::UNDEFINED);
        }
        assert_eq!(
            decoded(DOT_INDEXED | 1, thumb).mnemonic,
            Mnemonic::VDOT_BF16
        );
    }
    for raw in [
        CONVERT_BOTTOM,
        CONVERT_TOP,
        CONVERT_VECTOR,
        DOT,
        MATRIX,
        FMA_TOP,
    ] {
        for executes in [false, true] {
            let mut cpu = hyp();
            cpu.cpsr.t = true;
            cpu.cpsr.set_it_state(0, 8); // IT EQ.
            cpu.cpsr.z = executes;
            cpu.cp15.id_isar6 |= BF16;
            cpu.vfp.dregs[0] = 0x3f80_0000_dead_beef;
            let before = cpu.vfp.dregs;
            let exit = operation(&mut cpu, raw);
            assert!(
                if executes && matches!(raw, DOT | MATRIX | FMA_TOP) {
                    matches!(exit, ExecResult::Undefined)
                } else {
                    matches!(exit, ExecResult::Continue)
                },
                "{raw:08x}, Z={executes}: {exit:?}"
            );
            assert_eq!(
                cpu.vfp.dregs == before,
                !executes || matches!(raw, DOT | MATRIX | FMA_TOP)
            );
        }
    }
}

#[test]
fn mixed_width_bfloat_opt_in_survives_state_import_and_matches_guest_id() {
    let encoding = Aarch64SysRegEncoding::new(3, 0, 0, 2, 7);
    let raw = CONVERT_BOTTOM;
    for thumb in [false, true] {
        for (aa32, a64_level, aa32_level) in [
            (true, 1, None),
            (true, 1, Some(1)),
            (true, 2, Some(1)),
            (true, 0, Some(1)),
            (true, 3, Some(1)),
            (true, 1, Some(2)),
            (false, 1, Some(1)),
        ] {
            let mut cpu = mixed(ISAR6, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            let execution = state.execution.as_mut().unwrap();
            let features = &mut execution.features;
            let bf16 = rax::isa::arm::common::features::ArmFeatures::BF16.bits();
            *features = (*features & !bf16) | if a64_level == 1 { bf16 } else { 0 };
            let sys = &mut execution.sysregs;
            sys.id_aa64isar1_el1 = (sys.id_aa64isar1_el1 & !(15 << 44)) | (a64_level << 44);
            if !aa32 {
                sys.id_aa64pfr0_el1 = (sys.id_aa64pfr0_el1 & !15) | 1;
            }
            if let Some(level) = aa32_level {
                sys.impl_defined.insert(encoding.encode(), level << 20);
            }
            sys.impl_defined
                .remove(&Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode());
            let enabled = aa32 && a64_level == 1 && aa32_level == Some(1);
            let reported = if enabled { u64::from(BF16) } else { 0 };
            assert_eq!(sys.read(encoding, 1).unwrap() & (15 << 20), reported);
            if !aa32 {
                continue; // The profile lacks the required AArch32 EL0 support.
            }
            if a64_level > 1 {
                assert!(cpu.import_sregs(&state).is_err());
                continue;
            }
            cpu.import_sregs(&state).unwrap();
            let restored = cpu.export_sregs();
            let restored = &restored.execution.as_ref().unwrap().sysregs;
            assert_eq!(restored.read(encoding, 1).unwrap() & (15 << 20), reported);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(
                cpu.get_gpr(0) & (15 << 20),
                reported,
                "A64 BF16={a64_level}, A32 BF16={aa32_level:?}, Thumb={thumb}, PC={:x}, R0={:x}",
                cpu.get_pc(),
                cpu.get_gpr(0)
            );

            let encoded = if thumb { raw.rotate_left(16) } else { raw };
            cpu.write_memory(0x104, &encoded.to_le_bytes()).unwrap();
            let before = 0x1122_3344_5566_7788_3f80_0000_dead_beefu128;
            cpu.set_simd(0, before);
            let retired = cpu.instruction_count();
            if enabled {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), (before & !0xffff) | 0x3f80);
                assert_eq!(cpu.instruction_count(), retired + 1);
            } else {
                assert!(matches!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(word)) if word == raw
                ));
                assert_eq!(cpu.get_simd(0), before);
                assert_eq!(cpu.instruction_count(), retired);
            }
        }
    }
}
