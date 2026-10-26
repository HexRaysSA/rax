//! ASEDIS instruction classes, reserved D32DIS policy and FPEXC access.
use rax::isa::arm::aarch32::cp15::{Cp15State, Cpacr};
use rax::isa::arm::aarch32::cpu::{ArmMemory, MemoryError, ProcessorMode};
use rax::isa::arm::common::sysreg::Cp15Encoding;
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
// Actual LLVM23 encodings; A32 and T32, same assembly operation.
const ADVSIMD: [[u32; 2]; 13] = [
    [0xf2020844, 0xef020844], // vadd.i8 q0,q1,q2
    [0xf2020d44, 0xef020d44], // vadd.f32 q0,q1,q2
    [0xf2110d02, 0xef110d02], // vadd.f16 d0,d1,d2
    [0xf2870e5f, 0xef870e5f], // vmov.i8 q0,#0x7f
    [0xf4200a0f, 0xf9200a0f], // vld1.8 {d0,d1},[r0]
    [0xf4000a0f, 0xf9000a0f], // vst1.8 {d0,d1},[r0]
    [0xeee01b10, 0xeee01b10], // vdup.8 q0,r1
    [0xee801b90, 0xee801b90], // vdup.32 d16,r1
    [0xee401bf0, 0xee401bf0], // vmov.8 d16[3],r1
    [0xee0f1bf0, 0xee0f1bf0], // vmov.16 d31[1],r1
    [0xee501bf0, 0xee501bf0], // vmov.s8 r1,d16[3]
    [0xee9f1bf0, 0xee9f1bf0], // vmov.u16 r1,d31[1]
    [0xfc210852, 0xfc210852], // vfmal.f16 q0,d1,d2
];
const VFP: [[u32; 2]; 14] = [
    [0xee310a02, 0xee310a02], // vadd.f32 s0,s2,s4
    [0xee710ba2, 0xee710ba2], // vadd.f64 d16,d17,d18
    [0xee001b90, 0xee001b90], // vmov.32 d16[0],r1
    [0xee3f1b90, 0xee3f1b90], // vmov.32 r1,d31[1]
    [0xee001a10, 0xee001a10], // vmov s0,r1
    [0xee1f1a90, 0xee1f1a90], // vmov r1,s31
    [0xec410b3f, 0xec410b3f], // vmov d31,r0,r1
    [0xec510b3f, 0xec510b3f], // vmov r0,r1,d31
    [0xeef12a10, 0xeef12a10], // vmrs r2,fpscr
    [0xeee12a10, 0xeee12a10], // vmsr fpscr,r2
    [0xee001910, 0xee001910], // vmov.f16 s0,r1
    [0xee1f1990, 0xee1f1990], // vmov.f16 r1,s31
    [0xfe810a02, 0xfe810a02], // vmaxnm.f32 s0,s2,s4
    [0xfeb80941, 0xfeb80941], // vrinta.f16 s0,s2
];

struct NoMemory;
impl ArmMemory for NoMemory {
    fn read_word(&self, _: u32) -> Result<u32, MemoryError> {
        panic!("denied word read")
    }
    fn write_word(&mut self, _: u32, _: u32) -> Result<(), MemoryError> {
        panic!("denied word write")
    }
    fn read_halfword(&self, _: u32) -> Result<u16, MemoryError> {
        panic!("denied half read")
    }
    fn write_halfword(&mut self, _: u32, _: u16) -> Result<(), MemoryError> {
        panic!("denied half write")
    }
    fn read_byte(&self, _: u32) -> Result<u8, MemoryError> {
        panic!("denied byte read")
    }
    fn write_byte(&mut self, _: u32, _: u8) -> Result<(), MemoryError> {
        panic!("denied byte write")
    }
}
fn cpu(thumb: bool, mode: ProcessorMode, cpacr: u32) -> Armv7Cpu {
    let mut c = Armv7Cpu::new();
    c.cpsr.t = thumb;
    c.cpsr.mode = mode as u8;
    c.cp15.cpacr = Cpacr::from_bits(cpacr);
    c.vfp.fpexc = 1 << 30;
    c.regs[0] = 0x100;
    c.regs[1] = 0x1234_5678;
    c.regs[2] = 0;
    c.regs[13] = 0x800;
    c.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
    c
}
fn decode(word: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(word)
    } else {
        Aarch32Decoder::decode(word)
    }
    .unwrap()
}
fn denied(c: &mut Armv7Cpu, i: &DecodedInsn) {
    let gpr = c.regs;
    let cpsr = c.cpsr.to_u32();
    let d = c.vfp.dregs;
    let fpscr = c.vfp.fpscr.bits();
    let fpexc = c.vfp.fpexc;
    let cpacr = c.cp15.cpacr.bits();
    let result = Executor::new(c, &mut NoMemory).execute(i);
    assert!(
        matches!(
            result,
            ExecResult::Undefined | ExecResult::Exception(ExceptionType::UndefinedInstruction)
        ),
        "{:#x} {result:?}",
        i.raw
    );
    assert_eq!(c.regs, gpr);
    assert_eq!(c.cpsr.to_u32(), cpsr);
    assert_eq!(c.vfp.dregs, d);
    assert_eq!(c.vfp.fpscr.bits(), fpscr);
    assert_eq!(c.vfp.fpexc, fpexc);
    assert_eq!(c.cp15.cpacr.bits(), cpacr);
}
#[test]
fn asedis_denies_all_selected_advsimd_shapes_before_effects_in_a32_and_t32() {
    let mut count = 0;
    for mode in [ProcessorMode::User, ProcessorMode::Supervisor] {
        for thumb in [false, true] {
            for words in ADVSIMD {
                let mut c = cpu(thumb, mode, 0x80f0_0000);
                denied(&mut c, &decode(words[thumb as usize], thumb));
                count += 1;
            }
        }
    }
    assert_eq!(count, 52);
}
#[test]
fn clearing_asedis_permits_the_same_advsimd_shapes() {
    for thumb in [false, true] {
        for words in ADVSIMD {
            let mut c = cpu(thumb, ProcessorMode::Supervisor, 0x00f0_0000);
            let mut memory = FlatMemory::new(4096, 0);
            let i = decode(words[thumb as usize], thumb);
            let result = Executor::new(&mut c, &mut memory).execute(&i);
            assert!(
                matches!(result, ExecResult::Continue),
                "{:#x}: {result:?}",
                i.raw
            );
        }
    }
}
#[test]
fn ordinary_vfp_and_word_lane_transfers_ignore_asedis_and_reserved_d32dis() {
    for bits in [0x00f0_0000, 0x80f0_0000, 0xc0f0_0000] {
        for thumb in [false, true] {
            for words in VFP {
                let mut c = cpu(thumb, ProcessorMode::Supervisor, bits);
                let mut memory = FlatMemory::new(4096, 0);
                let i = decode(words[thumb as usize], thumb);
                let result = Executor::new(&mut c, &mut memory).execute(&i);
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{:#x},cpacr{bits:x}: {result:?}",
                    i.raw
                );
            }
        }
    }
}
#[test]
fn failed_predicates_skip_asedis_without_memory_or_register_effects() {
    for words in ADVSIMD {
        let mut c = cpu(true, ProcessorMode::User, 0x80f0_0000);
        c.cpsr.z = false;
        c.cpsr.set_it_state(0, 8);
        let i = decode(words[1], true);
        let g = c.regs;
        let d = c.vfp.dregs;
        let flags = c.cpsr.to_u32();
        assert!(matches!(
            Executor::new(&mut c, &mut NoMemory).execute(&i),
            ExecResult::Continue
        ));
        assert_eq!(c.regs, g);
        assert_eq!(c.vfp.dregs, d);
        assert_eq!(c.cpsr.to_u32(), flags);
    }
    // Predicated core VDUP is a legal conditional A32 encoding.
    let mut c = cpu(false, ProcessorMode::User, 0x80f0_0000);
    c.cpsr.z = false;
    let i = decode(ADVSIMD[6][0] & 0x0fff_ffff, false);
    let d = c.vfp.dregs;
    assert!(matches!(
        Executor::new(&mut c, &mut NoMemory).execute(&i),
        ExecResult::Continue
    ));
    assert_eq!(c.vfp.dregs, d);
}
#[test]
fn fpexc_disabled_remains_undefined_with_either_asedis_value() {
    for thumb in [false, true] {
        for cpacr in [0x00f0_0000, 0x80f0_0000] {
            for words in ADVSIMD {
                let mut c = cpu(thumb, ProcessorMode::Supervisor, cpacr);
                c.vfp.fpexc = 0;
                denied(&mut c, &decode(words[thumb as usize], thumb));
            }
            let mut c = cpu(thumb, ProcessorMode::Supervisor, cpacr);
            c.vfp.fpexc = 0;
            denied(&mut c, &decode(VFP[0][thumb as usize], thumb));
        }
    }
}
#[test]
fn guest_cpacr_read_write_masks_unimplemented_controls_without_changing_raw_utility() {
    let encoding = Cp15Encoding::new(1, 0, 0, 2);
    let mut cp15 = Cp15State::new();
    assert_eq!(cp15.read(encoding), Some(0));
    for value in [
        0,
        u32::MAX,
        1 << 30,
        1 << 31,
        1 << 28,
        0x00f0_0000,
        0x5555_5555,
        0xaaaa_aaaa,
    ] {
        assert!(cp15.write(encoding, value));
        assert_eq!(cp15.read(encoding), Some(value & 0x80f0_0000));
        assert_eq!(cp15.cpacr.bits(), value & 0x80f0_0000);
    }
    cp15.cpacr = Cpacr::from_bits(u32::MAX);
    assert_eq!(cp15.cpacr.bits(), u32::MAX);
    assert_eq!(cp15.read(encoding), Some(0x80f0_0000));
}
