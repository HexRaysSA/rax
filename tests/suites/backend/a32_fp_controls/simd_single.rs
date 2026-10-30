//! MVFR1.SIMDSP distinguishes FP32 data processing from integer/storage and FP16.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};
// Assembly, ARM, Thumb, family, requires SIMDSP.
const CASES: &[(&str, u32, u32, &str, bool)] = &[
    (
        "vadd.f32 q0,q1,q2",
        0xf2020d44,
        0xef020d44,
        "arithmetic",
        true,
    ),
    (
        "vsub.f32 q0,q1,q2",
        0xf2220d44,
        0xef220d44,
        "arithmetic",
        true,
    ),
    (
        "vabd.f32 q0,q1,q2",
        0xf3220d44,
        0xff220d44,
        "arithmetic",
        true,
    ),
    (
        "vmin.f32 q0,q1,q2",
        0xf2220f44,
        0xef220f44,
        "arithmetic",
        true,
    ),
    (
        "vmax.f32 q0,q1,q2",
        0xf2020f44,
        0xef020f44,
        "arithmetic",
        true,
    ),
    (
        "vminnm.f32 q0,q1,q2",
        0xf3220f54,
        0xff220f54,
        "arithmetic",
        true,
    ),
    (
        "vmaxnm.f32 q0,q1,q2",
        0xf3020f54,
        0xff020f54,
        "arithmetic",
        true,
    ),
    (
        "vmul.f32 q0,q1,q2",
        0xf3020d54,
        0xff020d54,
        "multiply",
        true,
    ),
    (
        "vmla.f32 q0,q1,q2",
        0xf2020d54,
        0xef020d54,
        "multiply",
        true,
    ),
    (
        "vmls.f32 q0,q1,q2",
        0xf2220d54,
        0xef220d54,
        "multiply",
        true,
    ),
    (
        "vfma.f32 q0,q1,q2",
        0xf2020c54,
        0xef020c54,
        "multiply",
        true,
    ),
    (
        "vfms.f32 q0,q1,q2",
        0xf2220c54,
        0xef220c54,
        "multiply",
        true,
    ),
    (
        "vmul.f32 q0,q1,d2[0]",
        0xf3a20942,
        0xffa20942,
        "multiply",
        true,
    ),
    (
        "vmla.f32 q0,q1,d2[0]",
        0xf3a20142,
        0xffa20142,
        "multiply",
        true,
    ),
    (
        "vmls.f32 q0,q1,d2[0]",
        0xf3a20542,
        0xffa20542,
        "multiply",
        true,
    ),
    (
        "vpadd.f32 d0,d1,d2",
        0xf3010d02,
        0xff010d02,
        "pairwise",
        true,
    ),
    (
        "vpmin.f32 d0,d1,d2",
        0xf3210f02,
        0xff210f02,
        "pairwise",
        true,
    ),
    (
        "vpmax.f32 d0,d1,d2",
        0xf3010f02,
        0xff010f02,
        "pairwise",
        true,
    ),
    ("vceq.f32 q0,q1,q2", 0xf2020e44, 0xef020e44, "compare", true),
    ("vcge.f32 q0,q1,q2", 0xf3020e44, 0xff020e44, "compare", true),
    ("vcgt.f32 q0,q1,q2", 0xf3220e44, 0xff220e44, "compare", true),
    (
        "vacge.f32 q0,q1,q2",
        0xf3020e54,
        0xff020e54,
        "compare",
        true,
    ),
    (
        "vacgt.f32 q0,q1,q2",
        0xf3220e54,
        0xff220e54,
        "compare",
        true,
    ),
    ("vceq.f32 q0,q1,#0", 0xf3b90542, 0xffb90542, "compare", true),
    ("vcge.f32 q0,q1,#0", 0xf3b904c2, 0xffb904c2, "compare", true),
    ("vcgt.f32 q0,q1,#0", 0xf3b90442, 0xffb90442, "compare", true),
    ("vcle.f32 q0,q1,#0", 0xf3b905c2, 0xffb905c2, "compare", true),
    ("vclt.f32 q0,q1,#0", 0xf3b90642, 0xffb90642, "compare", true),
    ("vabs.f32 q0,q1", 0xf3b90742, 0xffb90742, "misc", true),
    ("vneg.f32 q0,q1", 0xf3b907c2, 0xffb907c2, "misc", true),
    ("vrecpe.f32 q0,q1", 0xf3bb0542, 0xffbb0542, "misc", true),
    ("vrsqrte.f32 q0,q1", 0xf3bb05c2, 0xffbb05c2, "misc", true),
    ("vrinta.f32 q0,q1", 0xf3ba0542, 0xffba0542, "misc", true),
    ("vrintn.f32 q0,q1", 0xf3ba0442, 0xffba0442, "misc", true),
    ("vrintp.f32 q0,q1", 0xf3ba07c2, 0xffba07c2, "misc", true),
    ("vrintm.f32 q0,q1", 0xf3ba06c2, 0xffba06c2, "misc", true),
    ("vrintx.f32 q0,q1", 0xf3ba04c2, 0xffba04c2, "misc", true),
    ("vrintz.f32 q0,q1", 0xf3ba05c2, 0xffba05c2, "misc", true),
    ("vrecps.f32 q0,q1,q2", 0xf2020f54, 0xef020f54, "misc", true),
    ("vrsqrts.f32 q0,q1,q2", 0xf2220f54, 0xef220f54, "misc", true),
    (
        "vcvt.s32.f32 q0,q1",
        0xf3bb0742,
        0xffbb0742,
        "conversion",
        true,
    ),
    (
        "vcvt.u32.f32 q0,q1",
        0xf3bb07c2,
        0xffbb07c2,
        "conversion",
        true,
    ),
    (
        "vcvt.f32.s32 q0,q1",
        0xf3bb0642,
        0xffbb0642,
        "conversion",
        true,
    ),
    (
        "vcvt.f32.u32 q0,q1",
        0xf3bb06c2,
        0xffbb06c2,
        "conversion",
        true,
    ),
    (
        "vcvta.s32.f32 q0,q1",
        0xf3bb0042,
        0xffbb0042,
        "conversion",
        true,
    ),
    (
        "vcvta.u32.f32 q0,q1",
        0xf3bb00c2,
        0xffbb00c2,
        "conversion",
        true,
    ),
    (
        "vcvtn.s32.f32 q0,q1",
        0xf3bb0142,
        0xffbb0142,
        "conversion",
        true,
    ),
    (
        "vcvtn.u32.f32 q0,q1",
        0xf3bb01c2,
        0xffbb01c2,
        "conversion",
        true,
    ),
    (
        "vcvtp.s32.f32 q0,q1",
        0xf3bb0242,
        0xffbb0242,
        "conversion",
        true,
    ),
    (
        "vcvtp.u32.f32 q0,q1",
        0xf3bb02c2,
        0xffbb02c2,
        "conversion",
        true,
    ),
    (
        "vcvtm.s32.f32 q0,q1",
        0xf3bb0342,
        0xffbb0342,
        "conversion",
        true,
    ),
    (
        "vcvtm.u32.f32 q0,q1",
        0xf3bb03c2,
        0xffbb03c2,
        "conversion",
        true,
    ),
    (
        "vcvt.s32.f32 q0,q1,#16",
        0xf2b00f52,
        0xefb00f52,
        "conversion",
        true,
    ),
    (
        "vcvt.u32.f32 q0,q1,#16",
        0xf3b00f52,
        0xffb00f52,
        "conversion",
        true,
    ),
    (
        "vcvt.f32.s32 q0,q1,#16",
        0xf2b00e52,
        0xefb00e52,
        "conversion",
        true,
    ),
    (
        "vcvt.f32.u32 q0,q1,#16",
        0xf3b00e52,
        0xffb00e52,
        "conversion",
        true,
    ),
    (
        "vcvt.f32.f16 q0,d1",
        0xf3b60701,
        0xffb60701,
        "conversion",
        true,
    ),
    (
        "vcvt.f16.f32 d0,q1",
        0xf3b60602,
        0xffb60602,
        "conversion",
        true,
    ),
    ("vfmal.f16 q0,d2,d3", 0xfc220853, 0xfc220853, "fhm", true),
    ("vfmsl.f16 q0,d2,d3", 0xfca20853, 0xfca20853, "fhm", true),
    ("vfmal.f16 q0,d2,d3[1]", 0xfe02085b, 0xfe02085b, "fhm", true),
    ("vfmsl.f16 q0,d2,d3[1]", 0xfe12085b, 0xfe12085b, "fhm", true),
    (
        "vadd.i32 q0,q1,q2",
        0xf2220844,
        0xef220844,
        "control",
        false,
    ),
    (
        "vsub.i32 q0,q1,q2",
        0xf3220844,
        0xff220844,
        "control",
        false,
    ),
    (
        "vmul.i32 q0,q1,q2",
        0xf2220954,
        0xef220954,
        "control",
        false,
    ),
    (
        "vmla.i32 q0,q1,q2",
        0xf2220944,
        0xef220944,
        "control",
        false,
    ),
    (
        "vmax.s32 q0,q1,q2",
        0xf2220644,
        0xef220644,
        "control",
        false,
    ),
    (
        "vceq.i32 q0,q1,q2",
        0xf3220854,
        0xff220854,
        "control",
        false,
    ),
    (
        "vceq.i32 q0,q1,#0",
        0xf3b90142,
        0xffb90142,
        "control",
        false,
    ),
    ("vabs.s32 q0,q1", 0xf3b90342, 0xffb90342, "control", false),
    ("vneg.s32 q0,q1", 0xf3b903c2, 0xffb903c2, "control", false),
    ("vrecpe.u32 q0,q1", 0xf3bb0442, 0xffbb0442, "control", false),
    (
        "vrsqrte.u32 q0,q1",
        0xf3bb04c2,
        0xffbb04c2,
        "control",
        false,
    ),
    ("vmov q0,q1", 0xf2220152, 0xef220152, "control", false),
    ("vmov.f32 q0,#1.5", 0xf2870f58, 0xef870f58, "control", false),
    ("vmov.i32 q0,#1", 0xf2800051, 0xef800051, "control", false),
    ("vmov.32 d0[0],r1", 0xee001b10, 0xee001b10, "control", false),
    (
        "vld1.32 {d0},[r0]",
        0xf420078f,
        0xf920078f,
        "control",
        false,
    ),
    (
        "vst1.32 {d0},[r0]",
        0xf400078f,
        0xf900078f,
        "control",
        false,
    ),
    ("vdup.32 q0,r1", 0xeea01b10, 0xeea01b10, "control", false),
    (
        "vadd.f16 q0,q1,q2",
        0xf2120d44,
        0xef120d44,
        "control",
        false,
    ),
    (
        "vfma.f16 q0,q1,q2",
        0xf2120c54,
        0xef120c54,
        "control",
        false,
    ),
    (
        "vmaxnm.f16 q0,q1,q2",
        0xf3120f54,
        0xff120f54,
        "control",
        false,
    ),
    ("vrecpe.f16 q0,q1", 0xf3b70542, 0xffb70542, "control", false),
    ("vabs.f16 q0,q1", 0xf3b50742, 0xffb50742, "control", false),
    (
        "vceq.f16 q0,q1,q2",
        0xf2120e44,
        0xef120e44,
        "control",
        false,
    ),
    ("vrintn.f16 q0,q1", 0xf3b60442, 0xffb60442, "control", false),
    (
        "vcvta.s16.f16 q0,q1",
        0xf3b70042,
        0xffb70042,
        "control",
        false,
    ),
    (
        "vadd.f32 s0,s1,s2",
        0xee300a81,
        0xee300a81,
        "control",
        false,
    ),
    (
        "vadd.f64 d0,d1,d2",
        0xee310b02,
        0xee310b02,
        "control",
        false,
    ),
    (
        "vadd.f16 s0,s1,s2",
        0xee300981,
        0xee300981,
        "control",
        false,
    ),
];
fn campaign(family: Option<&str>, field: u32, deny_access: bool, deny_integer: bool) {
    for &(name, arm, thumb, class, single) in CASES {
        if family.is_some_and(|selected| selected != class) {
            continue;
        }
        for is_thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
            cpu.cp15.id_isar6 |= 1 << 8; // FHM, distinct from FP16 arithmetic.
            cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !(15 << 16)) | (field << 16);
            if deny_integer {
                cpu.vfp.mvfr1 &= !(15 << 12);
            }
            cpu.cpsr.t = is_thumb;
            cpu.regs[0] = 0x100;
            cpu.regs[1] = 0x12345678;
            cpu.regs[15] = 0x800;
            cpu.vfp.dregs.fill(0x3c003c003f803f80);
            if deny_access {
                cpu.cp15.cpacr = Cpacr::from_bits(0);
                cpu.cp15.hcptr = 1 << 10;
                cpu.vfp.fpexc = 0;
            }
            let mut memory = FlatMemory::new(4096, 0);
            let before = (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.vfp.fpscr.bits(),
                cpu.vfp.fpexc,
                cpu.cpsr.to_u32(),
            );
            let before_memory: Vec<_> = (0..4096)
                .step_by(4)
                .map(|a| memory.read_word(a).unwrap())
                .collect();
            let insn = if is_thumb {
                ThumbDecoder::decode_32bit(thumb).unwrap()
            } else {
                Aarch32Decoder::decode(arm).unwrap()
            };
            let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
            let rejected = single && (field != 1 || deny_integer);
            if rejected {
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "{name}, thumb={is_thumb}, field={field}: {result:?}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.dregs,
                        cpu.vfp.fpscr.bits(),
                        cpu.vfp.fpexc,
                        cpu.cpsr.to_u32()
                    ),
                    before,
                    "{name}"
                );
                let after: Vec<_> = (0..4096)
                    .step_by(4)
                    .map(|a| memory.read_word(a).unwrap())
                    .collect();
                assert_eq!(after, before_memory, "{name}");
            } else {
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{name}, thumb={is_thumb}, field={field}: {result:?}"
                );
            }
        }
    }
}
#[test]
fn absent_simdsp_rejects_arithmetic() {
    campaign(Some("arithmetic"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_vector_and_lane_multiplication() {
    campaign(Some("multiply"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_pairwise_operations() {
    campaign(Some("pairwise"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_register_and_zero_comparisons() {
    campaign(Some("compare"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_estimates_steps_sign_and_rounding() {
    campaign(Some("misc"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_integer_fixed_and_cross_precision_conversions() {
    campaign(Some("conversion"), 0, false, false);
}
#[test]
fn absent_simdsp_rejects_half_multiply_accumulation_into_single_precision() {
    campaign(Some("fhm"), 0, false, false);
}
#[test]
fn reserved_simdsp_values_do_not_enable_fp32() {
    for field in 2..=15 {
        for family in [
            "arithmetic",
            "multiply",
            "pairwise",
            "compare",
            "misc",
            "conversion",
            "fhm",
        ] {
            campaign(Some(family), field, false, false);
        }
    }
}
#[test]
fn absent_simdsp_precedes_access_denial() {
    for family in [
        "arithmetic",
        "multiply",
        "pairwise",
        "compare",
        "misc",
        "conversion",
        "fhm",
    ] {
        campaign(Some(family), 0, true, false);
    }
}
#[test]
fn full_simdsp_profile_executes_all_controls() {
    campaign(None, 1, false, false);
}
#[test]
fn integer_storage_scalar_and_pure_half_operations_do_not_require_simdsp() {
    for field in [0, 2, 15] {
        campaign(Some("control"), field, false, false);
    }
}
#[test]
fn advertised_fp32_does_not_override_missing_integer_prerequisite() {
    for family in [
        "arithmetic",
        "multiply",
        "pairwise",
        "compare",
        "misc",
        "conversion",
        "fhm",
    ] {
        campaign(Some(family), 1, false, true);
    }
}
