//! MVFR1/MVFR2 instruction admission, including ARM/Thumb capability boundaries.
use rax::isa::arm::cp15::Cpacr;
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Feature {
    Select,
    Convert,
    Round,
    Number,
    Fused,
}

// LLVM MC ARM/Thumb pairs; exact tool provenance and primary field definitions:
// docs/development/a32-fp-controls/feature-admission/misc-and-fma.md.
const CASES: &[(&str, u32, u32, Feature, bool)] = &[
    (
        "vseleq.f32 s0,s1,s2",
        0xfe000a81,
        0xfe000a81,
        Feature::Select,
        false,
    ),
    (
        "vselge.f32 s0,s1,s2",
        0xfe200a81,
        0xfe200a81,
        Feature::Select,
        false,
    ),
    (
        "vselgt.f32 s0,s1,s2",
        0xfe300a81,
        0xfe300a81,
        Feature::Select,
        false,
    ),
    (
        "vselvs.f32 s0,s1,s2",
        0xfe100a81,
        0xfe100a81,
        Feature::Select,
        false,
    ),
    (
        "vcvta.s32.f32 s0,s1",
        0xfebc0ae0,
        0xfebc0ae0,
        Feature::Convert,
        false,
    ),
    (
        "vcvta.u32.f32 s0,s1",
        0xfebc0a60,
        0xfebc0a60,
        Feature::Convert,
        false,
    ),
    (
        "vcvtn.s32.f32 s0,s1",
        0xfebd0ae0,
        0xfebd0ae0,
        Feature::Convert,
        false,
    ),
    (
        "vcvtn.u32.f32 s0,s1",
        0xfebd0a60,
        0xfebd0a60,
        Feature::Convert,
        false,
    ),
    (
        "vcvtp.s32.f32 s0,s1",
        0xfebe0ae0,
        0xfebe0ae0,
        Feature::Convert,
        false,
    ),
    (
        "vcvtp.u32.f32 s0,s1",
        0xfebe0a60,
        0xfebe0a60,
        Feature::Convert,
        false,
    ),
    (
        "vcvtm.s32.f32 s0,s1",
        0xfebf0ae0,
        0xfebf0ae0,
        Feature::Convert,
        false,
    ),
    (
        "vcvtm.u32.f32 s0,s1",
        0xfebf0a60,
        0xfebf0a60,
        Feature::Convert,
        false,
    ),
    (
        "vrinta.f32 s0,s1",
        0xfeb80a60,
        0xfeb80a60,
        Feature::Round,
        false,
    ),
    (
        "vrintn.f32 s0,s1",
        0xfeb90a60,
        0xfeb90a60,
        Feature::Round,
        false,
    ),
    (
        "vrintp.f32 s0,s1",
        0xfeba0a60,
        0xfeba0a60,
        Feature::Round,
        false,
    ),
    (
        "vrintm.f32 s0,s1",
        0xfebb0a60,
        0xfebb0a60,
        Feature::Round,
        false,
    ),
    (
        "vrintr.f32 s0,s1",
        0xeeb60a60,
        0xeeb60a60,
        Feature::Round,
        false,
    ),
    (
        "vrintx.f32 s0,s1",
        0xeeb70a60,
        0xeeb70a60,
        Feature::Round,
        false,
    ),
    (
        "vrintz.f32 s0,s1",
        0xeeb60ae0,
        0xeeb60ae0,
        Feature::Round,
        false,
    ),
    (
        "vmaxnm.f32 s0,s1,s2",
        0xfe800a81,
        0xfe800a81,
        Feature::Number,
        false,
    ),
    (
        "vminnm.f32 s0,s1,s2",
        0xfe800ac1,
        0xfe800ac1,
        Feature::Number,
        false,
    ),
    (
        "vfma.f32 s0,s1,s2",
        0xeea00a81,
        0xeea00a81,
        Feature::Fused,
        false,
    ),
    (
        "vfms.f32 s0,s1,s2",
        0xeea00ac1,
        0xeea00ac1,
        Feature::Fused,
        false,
    ),
    (
        "vfnma.f32 s0,s1,s2",
        0xee900ac1,
        0xee900ac1,
        Feature::Fused,
        false,
    ),
    (
        "vfnms.f32 s0,s1,s2",
        0xee900a81,
        0xee900a81,
        Feature::Fused,
        false,
    ),
    (
        "vseleq.f64 d0,d1,d2",
        0xfe010b02,
        0xfe010b02,
        Feature::Select,
        false,
    ),
    (
        "vselge.f64 d0,d1,d2",
        0xfe210b02,
        0xfe210b02,
        Feature::Select,
        false,
    ),
    (
        "vselgt.f64 d0,d1,d2",
        0xfe310b02,
        0xfe310b02,
        Feature::Select,
        false,
    ),
    (
        "vselvs.f64 d0,d1,d2",
        0xfe110b02,
        0xfe110b02,
        Feature::Select,
        false,
    ),
    (
        "vcvta.s32.f64 s0,d1",
        0xfebc0bc1,
        0xfebc0bc1,
        Feature::Convert,
        false,
    ),
    (
        "vcvta.u32.f64 s0,d1",
        0xfebc0b41,
        0xfebc0b41,
        Feature::Convert,
        false,
    ),
    (
        "vcvtn.s32.f64 s0,d1",
        0xfebd0bc1,
        0xfebd0bc1,
        Feature::Convert,
        false,
    ),
    (
        "vcvtn.u32.f64 s0,d1",
        0xfebd0b41,
        0xfebd0b41,
        Feature::Convert,
        false,
    ),
    (
        "vcvtp.s32.f64 s0,d1",
        0xfebe0bc1,
        0xfebe0bc1,
        Feature::Convert,
        false,
    ),
    (
        "vcvtp.u32.f64 s0,d1",
        0xfebe0b41,
        0xfebe0b41,
        Feature::Convert,
        false,
    ),
    (
        "vcvtm.s32.f64 s0,d1",
        0xfebf0bc1,
        0xfebf0bc1,
        Feature::Convert,
        false,
    ),
    (
        "vcvtm.u32.f64 s0,d1",
        0xfebf0b41,
        0xfebf0b41,
        Feature::Convert,
        false,
    ),
    (
        "vrinta.f64 d0,d1",
        0xfeb80b41,
        0xfeb80b41,
        Feature::Round,
        false,
    ),
    (
        "vrintn.f64 d0,d1",
        0xfeb90b41,
        0xfeb90b41,
        Feature::Round,
        false,
    ),
    (
        "vrintp.f64 d0,d1",
        0xfeba0b41,
        0xfeba0b41,
        Feature::Round,
        false,
    ),
    (
        "vrintm.f64 d0,d1",
        0xfebb0b41,
        0xfebb0b41,
        Feature::Round,
        false,
    ),
    (
        "vrintr.f64 d0,d1",
        0xeeb60b41,
        0xeeb60b41,
        Feature::Round,
        false,
    ),
    (
        "vrintx.f64 d0,d1",
        0xeeb70b41,
        0xeeb70b41,
        Feature::Round,
        false,
    ),
    (
        "vrintz.f64 d0,d1",
        0xeeb60bc1,
        0xeeb60bc1,
        Feature::Round,
        false,
    ),
    (
        "vmaxnm.f64 d0,d1,d2",
        0xfe810b02,
        0xfe810b02,
        Feature::Number,
        false,
    ),
    (
        "vminnm.f64 d0,d1,d2",
        0xfe810b42,
        0xfe810b42,
        Feature::Number,
        false,
    ),
    (
        "vfma.f64 d0,d1,d2",
        0xeea10b02,
        0xeea10b02,
        Feature::Fused,
        false,
    ),
    (
        "vfms.f64 d0,d1,d2",
        0xeea10b42,
        0xeea10b42,
        Feature::Fused,
        false,
    ),
    (
        "vfnma.f64 d0,d1,d2",
        0xee910b42,
        0xee910b42,
        Feature::Fused,
        false,
    ),
    (
        "vfnms.f64 d0,d1,d2",
        0xee910b02,
        0xee910b02,
        Feature::Fused,
        false,
    ),
    (
        "vcvta.s32.f32 d0,d1",
        0xf3bb0001,
        0xffbb0001,
        Feature::Convert,
        true,
    ),
    (
        "vcvta.u32.f32 d0,d1",
        0xf3bb0081,
        0xffbb0081,
        Feature::Convert,
        true,
    ),
    (
        "vcvtn.s32.f32 d0,d1",
        0xf3bb0101,
        0xffbb0101,
        Feature::Convert,
        true,
    ),
    (
        "vcvtn.u32.f32 d0,d1",
        0xf3bb0181,
        0xffbb0181,
        Feature::Convert,
        true,
    ),
    (
        "vcvtp.s32.f32 d0,d1",
        0xf3bb0201,
        0xffbb0201,
        Feature::Convert,
        true,
    ),
    (
        "vcvtp.u32.f32 d0,d1",
        0xf3bb0281,
        0xffbb0281,
        Feature::Convert,
        true,
    ),
    (
        "vcvtm.s32.f32 d0,d1",
        0xf3bb0301,
        0xffbb0301,
        Feature::Convert,
        true,
    ),
    (
        "vcvtm.u32.f32 d0,d1",
        0xf3bb0381,
        0xffbb0381,
        Feature::Convert,
        true,
    ),
    (
        "vrinta.f32 d0,d1",
        0xf3ba0501,
        0xffba0501,
        Feature::Round,
        true,
    ),
    (
        "vrintn.f32 d0,d1",
        0xf3ba0401,
        0xffba0401,
        Feature::Round,
        true,
    ),
    (
        "vrintp.f32 d0,d1",
        0xf3ba0781,
        0xffba0781,
        Feature::Round,
        true,
    ),
    (
        "vrintm.f32 d0,d1",
        0xf3ba0681,
        0xffba0681,
        Feature::Round,
        true,
    ),
    (
        "vrintx.f32 d0,d1",
        0xf3ba0481,
        0xffba0481,
        Feature::Round,
        true,
    ),
    (
        "vrintz.f32 d0,d1",
        0xf3ba0581,
        0xffba0581,
        Feature::Round,
        true,
    ),
    (
        "vmaxnm.f32 d0,d1,d2",
        0xf3010f12,
        0xff010f12,
        Feature::Number,
        true,
    ),
    (
        "vminnm.f32 d0,d1,d2",
        0xf3210f12,
        0xff210f12,
        Feature::Number,
        true,
    ),
    (
        "vfma.f32 d0,d1,d2",
        0xf2010c12,
        0xef010c12,
        Feature::Fused,
        true,
    ),
    (
        "vfms.f32 d0,d1,d2",
        0xf2210c12,
        0xef210c12,
        Feature::Fused,
        true,
    ),
    (
        "vcvta.s32.f32 q0,q1",
        0xf3bb0042,
        0xffbb0042,
        Feature::Convert,
        true,
    ),
    (
        "vcvta.u32.f32 q0,q1",
        0xf3bb00c2,
        0xffbb00c2,
        Feature::Convert,
        true,
    ),
    (
        "vcvtn.s32.f32 q0,q1",
        0xf3bb0142,
        0xffbb0142,
        Feature::Convert,
        true,
    ),
    (
        "vcvtn.u32.f32 q0,q1",
        0xf3bb01c2,
        0xffbb01c2,
        Feature::Convert,
        true,
    ),
    (
        "vcvtp.s32.f32 q0,q1",
        0xf3bb0242,
        0xffbb0242,
        Feature::Convert,
        true,
    ),
    (
        "vcvtp.u32.f32 q0,q1",
        0xf3bb02c2,
        0xffbb02c2,
        Feature::Convert,
        true,
    ),
    (
        "vcvtm.s32.f32 q0,q1",
        0xf3bb0342,
        0xffbb0342,
        Feature::Convert,
        true,
    ),
    (
        "vcvtm.u32.f32 q0,q1",
        0xf3bb03c2,
        0xffbb03c2,
        Feature::Convert,
        true,
    ),
    (
        "vrinta.f32 q0,q1",
        0xf3ba0542,
        0xffba0542,
        Feature::Round,
        true,
    ),
    (
        "vrintn.f32 q0,q1",
        0xf3ba0442,
        0xffba0442,
        Feature::Round,
        true,
    ),
    (
        "vrintp.f32 q0,q1",
        0xf3ba07c2,
        0xffba07c2,
        Feature::Round,
        true,
    ),
    (
        "vrintm.f32 q0,q1",
        0xf3ba06c2,
        0xffba06c2,
        Feature::Round,
        true,
    ),
    (
        "vrintx.f32 q0,q1",
        0xf3ba04c2,
        0xffba04c2,
        Feature::Round,
        true,
    ),
    (
        "vrintz.f32 q0,q1",
        0xf3ba05c2,
        0xffba05c2,
        Feature::Round,
        true,
    ),
    (
        "vmaxnm.f32 q0,q1,q2",
        0xf3020f54,
        0xff020f54,
        Feature::Number,
        true,
    ),
    (
        "vminnm.f32 q0,q1,q2",
        0xf3220f54,
        0xff220f54,
        Feature::Number,
        true,
    ),
    (
        "vfma.f32 q0,q1,q2",
        0xf2020c54,
        0xef020c54,
        Feature::Fused,
        true,
    ),
    (
        "vfms.f32 q0,q1,q2",
        0xf2220c54,
        0xef220c54,
        Feature::Fused,
        true,
    ),
];

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    let insn = if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap();
    assert_ne!(insn.mnemonic, Mnemonic::UNDEFINED);
    assert_eq!(insn.size, 4);
    insn
}

fn cpu(thumb: bool, fused: u32, scalar_misc: u32, simd_misc: u32) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    // Conversion-only half support keeps absent classic capabilities separate
    // from the later FP16 data-processing extension; FHM is absent as well.
    cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & 0x000f_ffff) | (fused << 28) | 0x0210_0000;
    cpu.vfp.mvfr2 = (scalar_misc << 4) | simd_misc;
    cpu.cp15.id_isar6 = 0;
    cpu.regs[15] = 0x100;
    cpu.vfp.dregs.fill(0x3fa0_0000_3fa0_0000);
    cpu
}

fn execute(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = decode(raw, cpu.cpsr.t);
    let mut memory = FlatMemory::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(&insn)
}

fn reject_without_effects(cpu: &mut Armv7Cpu, raw: u32) {
    let regs = cpu.regs;
    let cpsr = cpu.cpsr.to_u32();
    let dregs = cpu.vfp.dregs;
    let status = cpu.vfp.fpscr.bits();
    let controls = (cpu.vfp.fpexc, cpu.cp15.cpacr.bits());
    let features = (cpu.vfp.mvfr0, cpu.vfp.mvfr1, cpu.vfp.mvfr2);
    let result = execute(cpu, raw);
    assert!(
        matches!(result, ExecResult::Undefined),
        "raw={raw:#010x}: {result:?}"
    );
    assert_eq!(cpu.regs, regs);
    assert_eq!(cpu.cpsr.to_u32(), cpsr);
    assert_eq!(cpu.vfp.dregs, dregs);
    assert_eq!(cpu.vfp.fpscr.bits(), status);
    assert_eq!((cpu.vfp.fpexc, cpu.cp15.cpacr.bits()), controls);
    assert_eq!((cpu.vfp.mvfr0, cpu.vfp.mvfr1, cpu.vfp.mvfr2), features);
}

fn required(feature: Feature, simd: bool) -> u32 {
    match (feature, simd) {
        (Feature::Select, false) => 1,
        (Feature::Convert, false) => 2,
        (Feature::Round, false) => 3,
        (Feature::Number, false) => 4,
        (Feature::Convert, true) => 1,
        (Feature::Round, true) => 2,
        (Feature::Number, true) => 3,
        _ => panic!("not a miscellaneous field"),
    }
}

#[test]
fn enabled_profile_admits_all_miscellaneous_and_fused_forms() {
    let mut count = 0;
    for &(name, arm, thumb, _, _) in CASES {
        for (raw, t) in [(arm, false), (thumb, true)] {
            let result = execute(&mut cpu(t, 1, 4, 3), raw);
            assert!(
                matches!(result, ExecResult::Continue),
                "{name} Thumb={t}: {result:?}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 172);
}

#[test]
fn absent_miscellaneous_and_fused_features_reject_every_form_without_effects() {
    let mut count = 0;
    for &(_, arm, thumb, _, _) in CASES {
        for (raw, t) in [(arm, false), (thumb, true)] {
            reject_without_effects(&mut cpu(t, 0, 0, 0), raw);
            count += 1;
        }
    }
    assert_eq!(count, 172);
}

#[test]
fn defined_miscellaneous_levels_and_reserved_values_are_distinguished() {
    let mut count = 0;
    for &(name, arm, thumb, feature, simd) in CASES {
        if feature == Feature::Fused {
            continue;
        }
        for value in 0..16 {
            let expected = value >= required(feature, simd) && value <= if simd { 3 } else { 4 };
            for (raw, t) in [(arm, false), (thumb, true)] {
                // The unused field is zero: scalar and SIMD capabilities are independent.
                let mut cpu = cpu(
                    t,
                    0,
                    if simd { 0 } else { value },
                    if simd { value } else { 0 },
                );
                let result = execute(&mut cpu, raw);
                assert_eq!(
                    matches!(result, ExecResult::Continue),
                    expected,
                    "{name} Thumb={t} field={value}: {result:?}"
                );
                if !expected {
                    reject_without_effects(&mut cpu, raw);
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 2368);
}

#[test]
fn fused_support_requires_exactly_the_defined_simdfmac_value() {
    let mut count = 0;
    for &(name, arm, thumb, feature, _) in CASES {
        if feature != Feature::Fused {
            continue;
        }
        for value in 0..16 {
            for (raw, t) in [(arm, false), (thumb, true)] {
                let result = execute(&mut cpu(t, value, 0, 0), raw);
                assert_eq!(
                    matches!(result, ExecResult::Continue),
                    value == 1,
                    "{name} Thumb={t} SIMDFMAC={value}: {result:?}"
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 384);
}

#[test]
fn capability_absence_precedes_cpacr_and_fpexc_access_faults() {
    for &(_, arm, thumb, _, _) in CASES {
        for (raw, t) in [(arm, false), (thumb, true)] {
            for disable_cpacr in [false, true] {
                let mut absent = cpu(t, 0, 0, 0);
                let mut enabled = cpu(t, 1, 4, 3);
                for cpu in [&mut absent, &mut enabled] {
                    if disable_cpacr {
                        cpu.cp15.cpacr = Cpacr::from_bits(0);
                    } else {
                        cpu.vfp.fpexc = 0;
                    }
                }
                reject_without_effects(&mut absent, raw);
                assert!(matches!(
                    execute(&mut enabled, raw),
                    ExecResult::Exception(ExceptionType::UndefinedInstruction)
                ));
            }
        }
    }
}

#[test]
fn failed_scalar_arm_and_legal_thumb_it_predicates_skip_capability_checks() {
    for &(_, arm, thumb, feature, simd) in CASES {
        if feature != Feature::Fused || simd {
            continue;
        }
        for (raw, t) in [((arm & 0x0fff_ffff), false), (thumb, true)] {
            let mut cpu = cpu(t, 0, 0, 0);
            cpu.cpsr.z = false;
            if t {
                cpu.cpsr.set_it_state(0, 8);
            }
            cpu.cp15.cpacr = Cpacr::from_bits(0);
            cpu.vfp.fpexc = 0;
            let before = (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.cpsr.to_u32(),
                cpu.vfp.fpscr.bits(),
            );
            assert!(matches!(execute(&mut cpu, raw), ExecResult::Continue));
            assert_eq!(
                (
                    cpu.regs,
                    cpu.vfp.dregs,
                    cpu.cpsr.to_u32(),
                    cpu.vfp.fpscr.bits()
                ),
                before
            );
        }
    }
}

const BASELINE_CONTROLS: &[(u32, u32)] = &[
    (0xee000a81, 0xee000a81), // vmla.f32 s0,s1,s2
    (0xee000ac1, 0xee000ac1), // vmls.f32 s0,s1,s2
    (0xee100ac1, 0xee100ac1), // vnmla.f32 s0,s1,s2
    (0xee100a81, 0xee100a81), // vnmls.f32 s0,s1,s2
    (0xee200ac1, 0xee200ac1), // vnmul.f32 s0,s1,s2
    (0xee300a81, 0xee300a81), // vadd.f32 s0,s1,s2
    (0xee200a81, 0xee200a81), // vmul.f32 s0,s1,s2
    (0xeebd0ae0, 0xeebd0ae0), // vcvt.s32.f32 s0,s1
    (0xeebd0a60, 0xeebd0a60), // vcvtr.s32.f32 s0,s1
    (0xee010b02, 0xee010b02), // vmla.f64 d0,d1,d2
    (0xee010b42, 0xee010b42), // vmls.f64 d0,d1,d2
    (0xee110b42, 0xee110b42), // vnmla.f64 d0,d1,d2
    (0xee110b02, 0xee110b02), // vnmls.f64 d0,d1,d2
    (0xee210b42, 0xee210b42), // vnmul.f64 d0,d1,d2
    (0xee310b02, 0xee310b02), // vadd.f64 d0,d1,d2
    (0xee210b02, 0xee210b02), // vmul.f64 d0,d1,d2
    (0xeebd0bc1, 0xeebd0bc1), // vcvt.s32.f64 s0,d1
    (0xeebd0b41, 0xeebd0b41), // vcvtr.s32.f64 s0,d1
    (0xf2020d54, 0xef020d54), // vmla.f32 q0,q1,q2
    (0xf2220d54, 0xef220d54), // vmls.f32 q0,q1,q2
    (0xf2020d44, 0xef020d44), // vadd.f32 q0,q1,q2
    (0xf3020d54, 0xff020d54), // vmul.f32 q0,q1,q2
    (0xf2020f44, 0xef020f44), // vmax.f32 q0,q1,q2
    (0xf2220f44, 0xef220f44), // vmin.f32 q0,q1,q2
    (0xf3bb0742, 0xffbb0742), // vcvt.s32.f32 q0,q1
    (0xf3bb0642, 0xffbb0642), // vcvt.f32.s32 q0,q1
    (0xeeb20a60, 0xeeb20a60), // vcvtb.f32.f16 s0,s1
    (0xeeb30ae0, 0xeeb30ae0), // vcvtt.f16.f32 s0,s1
];

const HALF_CONTROLS: &[(u32, u32)] = &[
    (0xeea00981, 0xeea00981), // vfma.f16 s0,s1,s2
    (0xeea009c1, 0xeea009c1), // vfms.f16 s0,s1,s2
    (0xee9009c1, 0xee9009c1), // vfnma.f16 s0,s1,s2
    (0xee900981, 0xee900981), // vfnms.f16 s0,s1,s2
    (0xfe000981, 0xfe000981), // vseleq.f16 s0,s1,s2
    (0xfebc09e0, 0xfebc09e0), // vcvta.s32.f16 s0,s1
    (0xeeb609e0, 0xeeb609e0), // vrintz.f16 s0,s1
    (0xfe800981, 0xfe800981), // vmaxnm.f16 s0,s1,s2
    (0xf2120c54, 0xef120c54), // vfma.f16 q0,q1,q2
    (0xf3b70042, 0xffb70042), // vcvta.s16.f16 q0,q1
    (0xf3b605c2, 0xffb605c2), // vrintz.f16 q0,q1
    (0xf3120f54, 0xff120f54), // vmaxnm.f16 q0,q1,q2
];

#[test]
fn baseline_nonfused_arithmetic_and_conversions_remain_available() {
    assert_eq!(BASELINE_CONTROLS.len(), 28);
    for &(arm, thumb) in BASELINE_CONTROLS {
        for (raw, t) in [(arm, false), (thumb, true)] {
            assert!(
                matches!(execute(&mut cpu(t, 0, 0, 0), raw), ExecResult::Continue),
                "baseline raw={raw:#010x} Thumb={t}"
            );
        }
    }
}

#[test]
fn half_data_forms_require_both_half_and_their_corresponding_classic_capabilities() {
    assert_eq!(HALF_CONTROLS.len(), 12);
    for &(arm, thumb) in HALF_CONTROLS {
        for (raw, t) in [(arm, false), (thumb, true)] {
            let mut enabled = Armv7Cpu::new();
            enabled.cpsr.t = t;
            assert!(matches!(execute(&mut enabled, raw), ExecResult::Continue));
            let mut missing_half = cpu(t, 1, 4, 3);
            reject_without_effects(&mut missing_half, raw);
            let mut missing_classic = Armv7Cpu::new();
            missing_classic.cpsr.t = t;
            missing_classic.vfp.mvfr1 &= !(15 << 28);
            missing_classic.vfp.mvfr2 = 0;
            reject_without_effects(&mut missing_classic, raw);
        }
    }
}

#[test]
fn profile_dependent_fp_forms_do_not_acquire_a_profile_free_smir_lift() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::thumb::ThumbLifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    for &(_, arm, thumb, _, _) in CASES {
        for (raw, t) in [(arm, false), (thumb, true)] {
            let bytes = if t {
                raw.rotate_left(16).to_le_bytes()
            } else {
                raw.to_le_bytes()
            };
            let mut context = LiftContext::new(if t {
                SourceArch::Thumb
            } else {
                SourceArch::Aarch32
            });
            let mut lifter: Box<dyn SmirLifter> = if t {
                Box::new(ThumbLifter::new())
            } else {
                Box::new(Aarch32Lifter::new())
            };
            assert!(matches!(
                lifter.lift_insn(0x100, &bytes, &mut context),
                Err(LiftError::Unsupported { addr: 0x100, .. })
            ));
        }
    }
}

#[test]
fn mixed_width_default_profiles_admit_miscellaneous_fp_and_retain_access_traps() {
    use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
    use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
    use rax::isa::arm::common::memory::FlatMemory as MixedMemory;
    use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
    for &(_, arm, thumb, _, _) in CASES {
        for (raw, t) in [(arm, false), (thumb, true)] {
            for trap in [false, true] {
                let mut config = AArch64Config::v8_2();
                config.initial_el = 3;
                config.gic_config = None;
                let mut cpu = AArch64Cpu::new(config, Box::new(MixedMemory::new(0, 0x4000)));
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
                cpu.set_pstate_bits(0x1d3 | if t { 32 } else { 0 }).unwrap();
                cpu.set_pc(0x100);
                let bytes = if t {
                    raw.rotate_left(16).to_le_bytes()
                } else {
                    raw.to_le_bytes()
                };
                cpu.write_memory(0x100, &bytes).unwrap();
                if trap {
                    assert!(matches!(
                        cpu.step(),
                        Err(ArmError::ArchitecturalException {
                            ec: 7,
                            target_el: Some(3),
                            ..
                        })
                    ));
                    assert_eq!(cpu.get_pc(), 0x100);
                    assert_eq!(cpu.instruction_count(), 0);
                } else {
                    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.get_pc(), 0x104);
                    assert_eq!(cpu.instruction_count(), 1);
                }
            }
        }
    }
}
