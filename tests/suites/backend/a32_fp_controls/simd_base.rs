//! MVFR1 SIMDInt/SIMDLS instruction admission; LLVM encodings retained with evidence.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};
// name, ARM, Thumb, required MVFR1 field shift.
const CASES: &[(&str, u32, u32, u32)] = &[
    ("integer_add", 0xf2020844, 0xef020844, 12),
    ("core_duplicate", 0xeee01b10, 0xeee01b10, 12),
    ("core_lane", 0xee401b10, 0xee401b10, 12),
    ("load1", 0xf420070d, 0xf920070d, 8),
    ("store1", 0xf400070d, 0xf900070d, 8),
    ("load2", 0xf420080d, 0xf920080d, 8),
    ("store2", 0xf400080d, 0xf900080d, 8),
    ("load3", 0xf420040d, 0xf920040d, 8),
    ("store3", 0xf400040d, 0xf900040d, 8),
    ("load4", 0xf420000d, 0xf920000d, 8),
    ("store4", 0xf400000d, 0xf900000d, 8),
];
fn campaign(field: u32, deny_access: bool) {
    campaign_class(field, deny_access, None);
}
fn campaign_class(field: u32, deny_access: bool, only_shift: Option<u32>) {
    for &(name, arm, thumb, shift) in CASES {
        if only_shift.is_some_and(|selected| selected != shift) {
            continue;
        }
        for is_thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
            cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !(15 << shift)) | (field << shift);
            cpu.cpsr.t = is_thumb;
            cpu.regs[0] = 0x100;
            cpu.regs[1] = 0x12345678;
            cpu.regs[15] = 0x800;
            cpu.vfp.dregs.fill(0x3f8000003f800000);
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
            if field != 1 {
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
                assert_eq!(
                    after, before_memory,
                    "{name}: memory changed before admission"
                );
            } else {
                assert!(matches!(result, ExecResult::Continue), "{name}: {result:?}");
            }
        }
    }
}
#[test]
fn missing_simd_integer_and_structure_capabilities_reject_before_effects() {
    campaign(0, false);
}
#[test]
fn reserved_simd_integer_and_structure_fields_do_not_enable_instructions() {
    for field in 2..=15 {
        campaign(field, false);
    }
}
#[test]
fn simd_base_absence_precedes_access_denial() {
    campaign(0, true);
}
#[test]
fn implemented_simd_integer_and_structure_profiles_execute_all_forms() {
    campaign(1, false);
}
#[test]
fn unrelated_simd_classes_and_scalar_vfp_remain_available() {
    for &(name, arm, _, shift) in CASES {
        let mut cpu = Armv7Cpu::new();
        cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
        let other = if shift == 8 { 12 } else { 8 };
        cpu.vfp.mvfr1 &= !(15 << other);
        cpu.regs[0] = 0x100;
        cpu.regs[1] = 1;
        let mut memory = FlatMemory::new(4096, 0);
        let result =
            Executor::new(&mut cpu, &mut memory).execute(&Aarch32Decoder::decode(arm).unwrap());
        assert!(matches!(result, ExecResult::Continue), "{name}: {result:?}");
    }
    let mut cpu = Armv7Cpu::new();
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
    cpu.vfp.mvfr1 &= !0xff00;
    let mut memory = FlatMemory::new(4096, 0);
    assert!(matches!(
        Executor::new(&mut cpu, &mut memory).execute(&Aarch32Decoder::decode(0xee310a02).unwrap()),
        ExecResult::Continue
    ));
}

#[test]
fn missing_structure_memory_capability_rejects_before_effects() {
    campaign_class(0, false, Some(8));
}
#[test]
fn reserved_structure_memory_fields_do_not_enable_instructions() {
    for field in 2..=15 {
        campaign_class(field, false, Some(8));
    }
}
#[test]
fn structure_memory_absence_precedes_access_denial() {
    campaign_class(0, true, Some(8));
}
